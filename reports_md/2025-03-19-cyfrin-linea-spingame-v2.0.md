**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[Farouk](https://twitter.com/Ubermensh3dot0)

**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## Medium Risk


### Native token prizes cannot be funded due to missing `receive()` function

**Description:** SpinGame supports multiple prize types, including ERC721, ERC20, and native tokens, where native tokens are represented as `prize.tokenAddress = address(0)`.

To ensure that prizes can be successfully claimed, the protocol team is responsible for maintaining a sufficient token balance in the contract by transferring the necessary assets to the Spin contract.

However, there is an issue specifically with native token prizes: the Spin contract does not have a `receive()` or `fallback()` function, and none of its functions are `payable`. This means there is no way for the team to fund the contract with native tokens using a standard transfer, preventing users from successfully claiming native token prizes.

**Impact:** Native token prizes cannot be claimed because there is no mechanism to deposit native tokens into the contract. The only way to provide a native token balance would involve esoteric workarounds, such as self-destructing a contract that sends funds to the Spin contract.


**Proof of Concept:** Add the following test to `Spin.t.sol`:
```solidity
function testTransferNativeToken() public {
    vm.deal(admin,1e18);

    vm.prank(admin);
    (bool success, ) = address(spinGame).call{value: 1e18}("");

    // transfer failed as there is no `receive` or `fallback` function
    assertFalse(success);
}
```

**Recommended Mitigation:** Consider adding a `receive()` function to the contract to allow native token deposits:

```solidity
receive() external payable {}
```

**Linea:** Fixed in commit [`d1ab4bd`](https://github.com/Consensys/linea-hub/commit/d1ab4bdbaac3639a36d66440b9e6da95771e4b34)

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Rounding errors in boosted probability calculation can cause guaranteed wins to fail

**Description:** The Linea SpinGame includes a boosting feature that allows the protocol to increase a specific user's chance of winning. However, this mechanism introduces the possibility of a user's total winning probability exceeding 100%, as the boosted probabilities can sum to a value greater than 100%. To address this, the contract normalizes the total boosted probability in [`Spin::_fulfillRandomness`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L538-L557):

```solidity
// Apply boost on the sum of totalProbabilities.
uint256 boostedTotalProbabilities = totalProbabilities * userBoost / BASE_POINT;

// If boostedTotalProbabilities exceeds 100% we have to increase the winning threshold so it stays in bound.
//
// Example:
//   PrizeA probability: 50%
//   PrizeB probability: 30%
//   User boost: 1.5x
//   boostedPrizeAProbability: 75%
//   boostedPrizeBProbability: 45%
//
//   We now have a total of 120% totalBoostedProbability so we need to increase winning threshold by boostedTotalProbabilities to BASE_POINT ratio.
//
//   winningThreshold = winningThreshold * 12_000 / 10_000
if (boostedTotalProbabilities > BASE_POINT) {
    winningThreshold =
        (winningThreshold * boostedTotalProbabilities) /
        BASE_POINT;
}
```

Later in [`Spin::_fulfillRandomness`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L569-L589), each prize probability is independently scaled when checking if the user has won:

```solidity
// Apply boost on a single prize probability.
uint256 boostedPrizeProbability = prizeProbability * userBoost / BASE_POINT;

unchecked {
    cumulativeProbability += boostedPrizeProbability;
}

if (winningThreshold < cumulativeProbability) {
    selectedPrizeId = localPrizeIds[i];

    // ... win
    break;
}
```

The issue arises from the probability calculation:

```solidity
uint256 boostedPrizeProbability = prize.probability +
    ((prize.probability * userBoost) / BASE_POINT);
```

Due to this calculation, the final `cumulativeProbability` can be lower than `boostedTotalProbabilities`, leading to a scenario where a user who should be guaranteed a win might still lose due to rounding errors.

**Impact:** A user who theoretically has a 100% chance of winning can still lose. While this is an unlikely edge case, it would be highly problematic for the unlucky user who, despite the math suggesting they are guaranteed a win, does not receive a prize due to numerical precision issues.

**Proof of Concept:** Consider the following example:

- There are three prizes, each with a 30% probability of being won.
- A user receives a 133% probability boost.

Calculating the boosted probabilities:

```solidity
boostedTotalProbabilities = 0.9e8*133_333_333/1e8 = 119_999_999
boostedPrizeProbability = 0.3e8*133_333_333/1e8 = 39_999_999
```
and
```
3*39_999_999 = 119_999_997
```

In the worst case, the user could get:

```
winningThreshold = 99_999_999
```

Applying the threshold adjustment:

```solidity
if (boostedTotalProbabilities > BASE_POINT) {
    winningThreshold =
        (winningThreshold * boostedTotalProbabilities) /
        BASE_POINT;
}
```

This results in:

```
winningThreshold = 99_999_999 * 119_999_999 / 1e8 = 119_999_997
```

Since `winningThreshold < cumulativeProbability` is the condition for winning, and:

```
119_999_997 < 119_999_997  // (false)
```

The condition fails, meaning the user loses, even though they were supposed to be guaranteed a win. This issue is caused by the rounding errors in scaling probabilities.


**Recommended Mitigation:** Consider ensuring that in the last iteration of the loop, if `boostedTotalProbabilities >= BASE_POINT`, the user is guaranteed a win:

```diff
- if (winningThreshold < cumulativeProbability) {
+ if (winningThreshold < cumulativeProbability ||
+     boostedTotalProbabilities >= BASE_POINT && i == prizeLen - 1 // last iteration and win is guaranteed
+ ) {
      selectedPrizeID = prizeIds[i];
```

This change slightly favors the last prize in the list in extremely rare cases, but given that this situation is already highly improbable, this trade-off is reasonable.

**Linea:** Fixed in commit [`b32e038`](https://github.com/Consensys/linea-hub/commit/b32e038bba336d1ad6dddbdb972de8cafbbb2c1a)

**Cyfrin:** Verified.


### Users can select higher-value NFTs by delaying prize claims

**Description:** When a user wins, the contract only tracks that they have won a specific `prizeID` in [`Spin::_fulfillRandomness`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L576-L592):

```solidity
    if (winningThreshold < cumulativeProbability) {
        selectedPrizeId = localPrizeIds[i];

        // ...
        break;
    }
}

userToPrizesWon[user][selectedPrizeId] += 1;
```

However, when a user claims their prize, if the prize is an NFT, the contract simply assigns them the last available NFT in the list in [`Spin::_transferPrize`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L366-L368):

```solidity
uint256 tokenId = prize.availableERC721Ids[
    prize.availableERC721Ids.length - 1
];
```

Since NFTs are non-fungible, each `tokenId` represents a unique item, meaning that a user who wins can wait to claim their prize until the highest-value NFT remains in the collection. This allows them to strategically claim the best available token, potentially at the expense of users who claim their prizes immediately.

**Impact:** Users could delay claiming to secure a more valuable NFT from a collection, while other users who claim immediately may unknowingly receive lower-value tokens. This could create an unfair advantage for informed users who understand the mechanics of prize allocation.

**Recommended Mitigation:** There is no perfect solution, as all potential fixes come with trade-offs. One approach would be to assign a specific NFT at the time of winning in `_fulfillRandomness`. However, this would require tracking both which NFTs each user has won and which remain available, significantly increasing state complexity and gas costs.

Instead, the protocol should be aware of this issue and ensure that NFTs within each prize category have similar values. If a collection includes NFTs with widely varying values, they should be added as separate prizes, ensuring fairer distribution and preventing users from gaming the system.

**Linea:** Acknowledged. Higher value NFTs should be added as separate prizes.

**Cyfrin:** Acknowledged.


### Probability overflow can bypass `MaxProbabilityExceeded` check

**Description:** When adding new prizes, the contract includes a check to ensure that the total probability does not exceed 100% in [`Spin::_addPrizes#L511-L513`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L511-L513):

```solidity
if (totalProbabilities > BASE_POINT) {
    revert MaxProbabilityExceeded(totalProbabilities);
}
```

However, this check can be bypassed due to how `totalProbabilities` is calculated. The accumulation of probabilities happens in `unchecked` blocks at the following locations:

- First accumulation of individual probability values, [`Spin::_addPrizes#L503-L505`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L503-L505):

  ```solidity
  unchecked {
      totalProbIncrease += probability;
  }
  ```

- Final update of `totalProbabilities`, [`Spin::_addPrizes#L508-L510`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L508-L510):

  ```solidity
  unchecked {
      totalProbabilities += totalProbIncrease;
  }
  ```

Because both updates occur within `unchecked` blocks, a very large probability value can overflow, effectively bypassing the `MaxProbabilityExceeded` check. This could allow `totalProbabilities` to wrap around and appear valid, even if it exceeds `BASE_POINT`.

**Impact:** Although this function can only be called by trusted users (e.g., the `CONTROLLER` or `DEFAULT_ADMIN` role), a mistake or a compromised account could still trigger this issue by adding an excessively large probability value. This would cause an overflow, allowing the ``MaxProbabilityExceeded check to be bypassed and potentially breaking the integrity of the game by distorting the prize distribution.

**Proof of Concept:** Add the following test to `Spin.t.sol`:
```solidity
function testUpdateWithMoreThanMaxProba() external {
    MockERC721 nft = new MockERC721("Test NFT", "TNFT");
    nft.mint(address(spinGame), 10);
    nft.mint(address(spinGame), 21);

    ISpinGame.Prize[] memory prizesToUpdate = new ISpinGame.Prize[](2);
    uint256[] memory empty = new uint256[](0);

    uint256[] memory nftAvailable = new uint256[](2);
    nftAvailable[0] = 10;
    nftAvailable[1] = 21;

    prizesToUpdate[0] = ISpinGame.Prize({
        tokenAddress: address(nft),
        amount: 0,
        lotAmount: 2,
        probability: type(uint64).max - 1,
        availableERC721Ids: nftAvailable
    });

    prizesToUpdate[1] = ISpinGame.Prize({
        tokenAddress: address(0),
        amount: 1e18,
        lotAmount: 2,
        probability: 2,
        availableERC721Ids: empty
    });

    vm.prank(admin);
    spinGame.updatePrizes(prizesToUpdate);

    assertEq(spinGame.getPrize(1).probability, type(uint64).max - 1);
}
```

**Recommended Mitigation:** Consider removing the `unchecked` blocks in both calculations.

**Linea:** Fixed in commit [`e840e2f`](https://github.com/Consensys/linea-hub/commit/e840e2f04dca6006ac7b5782765c58e7a6869603)

**Cyfrin:** Verified.

\clearpage
## Informational


### Scaling `winningThreshold` incorrectly reduces randomness distribution

**Description:** When a user has a boost that results in a >100% probability of winning, the contract adjusts `winningThreshold` to match `boostedTotalProbabilities` in [`Spin::_fulfillRandomness`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L534-L557):

```solidity
uint256 winningThreshold = _randomness % BASE_POINT;

// ...

if (boostedTotalProbabilities > BASE_POINT) {
    winningThreshold =
        (winningThreshold * boostedTotalProbabilities) /
        BASE_POINT;
}
```

The issue here is that `_randomness` is first scaled down to `BASE_POINT` before being scaled up to `boostedTotalProbabilities`. This process reduces the effective randomness (entropy) because some values in the original `_randomness` range will no longer be represented in the final `winningThreshold` after scaling. As a result, the final threshold may not be evenly distributed, potentially introducing bias.

Consider applying `_randomness` directly to `boostedTotalProbabilities` when the win probability exceeds 100%, ensuring no loss of entropy:

```diff
  if (boostedTotalProbabilities > BASE_POINT) {
-     winningThreshold =
-         (winningThreshold * boostedTotalProbabilities) /
-         BASE_POINT;

+     winningThreshold = _randomness % boostedTotalProbabilities;
  }
```

This preserves the full randomness range and ensures a more uniform distribution of possible winning thresholds.

**Linea:** Fixed in commit [`37a18ca`](https://github.com/Consensys/linea-hub/commit/37a18ca60b8e503643b5b6e996e9a0cd7c257ec2)

**Cyfrin:** Verified.


### Native token transfers lack explicit balance check

**Description:** One possible prize type is native tokens, represented by `tokenAddress = address(0)`. A user who wins native tokens can claim them in [`Spin::_transferPrize`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L347-L352):

```solidity
if (prize.tokenAddress == address(0)) {
    (bool success, ) = _winner.call{value: prize.amount}("");
    if (!success) {
        revert NativeTokenTransferFailed();
    }
} else {
```

For ERC20 prizes ([handled here](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L353-L362)) and ERC721 prizes ([handled here](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L369-L371)), the contract explicitly checks whether it has a sufficient balance or ownership of the token before proceeding with the transfer.

While the current implementation would still revert if the contract lacks the required native token balance, consider adding an explicit balance check for native tokens as it would provide consistency across all prize types and ensure uniform error messages, improving usability and debugging.

**Linea:** Fixed in commit [`7675766`](https://github.com/Consensys/linea-hub/commit/7675766ba45bd87888897ac130a587a45e47e96b)

**Cyfrin:** Verified.


### Race Condition in `updatePrizes` Leading to Unexpected Prizes

**Description:** The `updatePrizes` function allows modifying the list of available prizes. However, it does not consider ongoing participations where the randomness request has not yet been fulfilled, leaving some participants without an assigned prize ID. This means a participant can initiate a spin, and before the VRF provides the random number, the `updatePrizes` function can be called. As a result, the prize mapping is updated, causing the participant to receive a prize from a different list than the one they originally played for.

**Impact:** Participants may receive prizes from an updated list rather than the one that was active when they initially participated.

**Proof of Concept:**
1. A participant initiates a spin.
2. Before the VRF fulfills the randomness request, updatePrizes is called, modifying the prize distribution.
3. The participant then receives a prize from the updated list rather than the expected one.

**Recommended Mitigation:** Ensure that all pending VRF requests are fulfilled before allowing any updates to the prize list.

**Linea:** Acknowledged. Acceptable behavior.

**Cyfrin:** Acknowledged.


### Assembly blocks could benefit from `"memory-safe"` annotation

**Description:** When hashing request data in [`Spin::_hashParticipation`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L383-L409) and [`Spin::_hashClaim`](https://github.com/Consensys/linea-hub/blob/295344925ec4321265f7cbac174fcf903b529a4e/contracts/src/Spin.sol#L411-L438), inline assembly is used to efficiently compute the hash:
```solidity
assembly {
    let mPtr := mload(0x40)
    mstore(
        mPtr,
        0x4635ca970da82693e235d3cdaa3678d42c6824330c48b4135f080d655e54da78 // keccak256("ClaimRequest(address user,uint256 expirationTimestamp,uint64 nonce,uint32 prizeId)")
    )
    mstore(add(mPtr, 0x20), _user)
    mstore(add(mPtr, 0x40), _expirationTimestamp)
    mstore(add(mPtr, 0x60), _nonce)
    mstore(add(mPtr, 0x80), _prizeId)
    claimHash := keccak256(mPtr, 0xa0)
}
```

To improve compiler optimizations, consider adding a [`memory-safe`](https://docs.soliditylang.org/en/latest/assembly.html#memory-safety) annotation to the assembly block:

```diff
+ assembly ("memory-safe") {
```

Since the assembly block only accesses memory after the free memory pointer (`0x40`), this annotation poses no risk and can allow the Solidity compiler to apply additional optimizations, improving gas efficiency.

**Linea:** Fixed in commit [`b4aaffc`](https://github.com/Consensys/linea-hub/commit/b4aaffc43e496b085e54ef2b08397fcb3c310e68)

**Cyfrin:** Verified.

\clearpage