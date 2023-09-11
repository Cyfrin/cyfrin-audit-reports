## Low Risk


### An expired claim can be revived by a contract owner well past the expiry date

**Description:** Contract owners can use the `setClaims` function to configure claim parameters for each claim contract, including settings such as `expiry` and `minFee`. For a claim to be considered valid, claimers must pay a fee that exceeds the specified `minFee` and claim the expiry date.

However, it is important to note that the `setClaims` function allows contract owners to add or update a claim with an expiry date that has already passed. While this may initially seem like a harmless side-effect, as claimers cannot claim on such contracts, it has a more significant implication. Contract owners can effectively revive airdrops that have already expired, enabling them to carry out airdrops that should no longer be active.

[Affected lines of code in `DropClaims::setClaims`](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L77-L83)

**Impact:** Contract owners can modify a claim even after it has expired. This allows retroactively adding claimers by extending the validity period of a claim that should have already ended.

**Recommended Mitigation:** While the `setClaims` function is limited to contract owners and certain trust assumptions are made by protocol developers, we recommend implementing additional controls to mitigate the unrestricted powers granted to contract owners.

Consider validating the claim time before adding/updating an existing claim.

```diff
// DropClaim::setClaims
    for (uint256 i; i < arrLength;) {
+       if(expiries[i] <= block.timsetstamp) revert ERROR_EXPIRE_TIME_SHOULD_BE_GREATER_THAN_NOW;
        claims[claimContractHashes[i]] = ClaimData(uint64(expiries[i]), uint128(minFees[i]));

        unchecked {
            ++i;
        }
    }
```
**Bankless:** Acknowledged. Team will not make any changes related to this finding as this is intended functionality.

**Cyfrin:** Acknowledged.


### Changing minimum fee and expiry midway through an active airdrop can be unfair to existing/future claimers

**Description:** `DropClaim::setClaims` allows users to overwrite claim parameters, `expiry`, and `minimumFee` of an existing claim contract hash.

```solidity
  function setClaims(bytes32[] calldata claimContractHashes, uint256[] calldata expiries, uint256[] calldata minFees)
        external
        onlyOwner
    {
        if (claimContractHashes.length != expiries.length) revert MismatchedArrayLengths();
        if (claimContractHashes.length != minFees.length) revert MismatchedArrayLengths();

        uint256 arrLength = claimContractHashes.length;
        for (uint256 i; i < arrLength;) {
            claims[claimContractHashes[i]] = ClaimData(uint64(expiries[i]), uint128(minFees[i]));
            // @audit -> claim parameters for an existing claim contract hash can be overwritten for an active airdrop
            unchecked {
                ++i;
            }
        }
    }
```

When users commence claiming airdrops, it is important to consider the potential consequences of following actions that the protocol may initiate:

1. Adjusting the validity period for future claimers by extending or reducing it.
2. Modifying the fees for future claimers by increasing or decreasing them.

In both cases, it is crucial to recognize that such actions have the potential to create unfairness, whether it is for existing claimers or future claimers. Even the protocol owners should not be able to manipulate airdrop parameters once the airdrop has been activated.

In the case of using the `allowList` mode for claims, a similar concern arises regarding the `setMerkleRoot` function. Owners can update the Merkle root even after the airdrop has been activated and some users have made their claims.

**Impact:** A decrease in `minFees` benefits future claimers, while an increase in `minFees` benefits existing claimers. Similarly, shortening validity benefits past claimers while extending validity benefits future claimers. Allowing owners to update the Merkle root once the airdrop is activated has the potential to render previously eligible claimers ineligible and vice versa.


**Recommended Mitigation:** Consider tracking an additional parameter, `numClaimers`, in the `ClaimData` struct. Note that even with this addition, `ClaimData` still fits in a single slot.

```diff
  struct ClaimData {
        uint64 expiry; // Timestamp beyond which claims are disallowed
        uint128 minFee; // Minimum ETH fee amount
+        uint64 numClaimers;// Number of users who already claimed //@audit -> add this variable to ClaimData struct
    }
```

Increment `numClaimers` every time a new claim is successful. Allow changes in `setClaims` and `setMerkleRoot` only if no existing claimers exist.

`DropClaim::setClaims`

```diff

    function setClaims(bytes32[] calldata claimContractHashes, uint256[] calldata expiries, uint256[] calldata minFees)
        external
        onlyOwner
    {
        if (claimContractHashes.length != expiries.length) revert MismatchedArrayLengths();
        if (claimContractHashes.length != minFees.length) revert MismatchedArrayLengths();

        uint256 arrLength = claimContractHashes.length;
        for (uint256 i; i < arrLength;) {
+         require(claims[claimContractHashes[i]].numClaimers ==0, "Airdrop already activated");
            claims[claimContractHashes[i]] = ClaimData(uint64(expiries[i]), uint128(minFees[i]));
            unchecked {
                ++i;
            }
        }
    }

```

**Bankless:** Acknowledged. Team will not change as is worth the trade-off for us.

**Cyfrin:** Acknowledged.

\clearpage

## Informational


### `allowlistClaim` allows users to access `claimContract` unlimited times creating a potential for duplicate calls

**Description:** The `allowlistClaim` function enables claimers to repeatedly access the functions of the `claimContract`. However, it doesn't track whether a claimer has already submitted proof for verification. This can be a problem for contracts that involve airdrops, as it's important to limit the number of successful interactions with the `claimContract`.

Currently, checking for duplicate interactions lies solely with the `claimContract` because `dropClaim` contract only verifies Merkle proofs.

In contrast, the [claim function in the MerkleDistributor contract](https://etherscan.io/address/0x090D4613473dEE047c3f2706764f49E0821D256e#code) deployed by Uniswap and 1inch handles both verification of proofs submitted by claimers and ensuring that each claimer can only have one successful call.

Here's a snippet of the Uniswap `Merkledistributor` contract at 0x090D4613473dEE047c3f2706764f49E0821D256e:


```solidity
  function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external override {
        require(!isClaimed(index), 'MerkleDistributor: Drop already claimed.'); //@restricting each user to 1 successful claim
       //@audit -> this verifies if already claimed or not
        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(merkleProof, merkleRoot, node), 'MerkleDistributor: Invalid proof.');

        // Mark it claimed and send the token.
        _setClaimed(index);
        require(IERC20(token).transfer(account, amount), 'MerkleDistributor: Transfer failed.');

        emit Claimed(index, account, amount);
    }
```

**Impact:** In situations such as claiming airdrops, minting NFTs or claiming vested shares, it's crucial to limit the number of calls made by each claimer. Allowing duplicate access to key functions like `claim` without explicit handling of duplications can result in losses for the protocol. Relying solely on `claimContracts` to handle these duplications can potentially increase the attack surface.

**Recommended Mitigation:** We propose considering an enhancement to the `DropClaim` logic that would take into account the number of claims per `claimContract` for each user. To achieve this, we suggest introducing a mapping system that associates user addresses with the number of successful claims they have made.

In line with the existing configuration options, such as `minFee` and `expiry` parameters for each `claimContract`, we recommend the addition of a new parameter called `maxCallsPerContract`. This parameter would allow owners to limit the number of claims a user can make for a specific `claimContract`.

This added layer of security provided by the `DropClaim` contract will involve verifying if the total claims made by a user for a given `claimContract` are below the set `maxCallsPerContract` value for that particular contract. Although more gas expensive, this enhancement reduces attack surface corresponding to duplicate claims.

**Bankless:** Acknowledged. Team will not make any changes related to this finding as this is intended functionality.

**Cyfrin:** Acknowledged.

\clearpage

## Gas Optimization


### Use storage pointer rather than copy in memory

To avoid copying every element of the struct when only one element is required, it is more efficient to use a storage pointer rather than copy the element in memory.

```diff
// DropClaim::claim
-   ClaimData memory claimData = claims[getClaimContractHash(claimContract, salt)];
+   ClaimData storage claimData = claims[getClaimContractHash(claimContract, salt)];
```
[Line 100](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L100)

```diff
// DropClaim::batchClaim
-   ClaimData memory claimData = claims[getClaimContractHash(claimContracts[i], salts[i])];
+   ClaimData storage claimData = claims[getClaimContractHash(claimContracts[i], salts[i])];
```
[Line 131](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L131)

```diff
// DropClaim::_claim
-   ClaimData memory claimData = claims[getClaimContractHash(claimContract, salt)];
+   ClaimData storage claimData = claims[getClaimContractHash(claimContract, salt)];
```
[Line 200](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L200)

**Bankless:** Acknowledged & fixed in [commit 020bb4c49a281af32898f951b784d7748dac049f](https://github.com/kadenzipfel/drop-claim/commit/020bb4c49a281af32898f951b784d7748dac049f).

**Cyfrin:** Verified.


### Bool comparison to constant values should be avoided

Comparing to a constant (true or false) is a bit more expensive than directly checking the returned boolean value.

```diff
// DropClaim::allowlistClaim
-   if (MerkleProof.verify(merkleProof, merkleRoot, bytes32(uint256(uint160(msg.sender)))) == false) {
+   if (!MerkleProof.verify(merkleProof, merkleRoot, bytes32(uint256(uint160(msg.sender))))) {
```
[Line 158](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L158)

```diff
// DropClaim::allowlistBatchClaim
-   if (MerkleProof.verify(merkleProof, merkleRoot, bytes32(uint256(uint160(msg.sender)))) == false) {
+   if (!MerkleProof.verify(merkleProof, merkleRoot, bytes32(uint256(uint160(msg.sender))))) {
```
[Line 181](https://github.com/kadenzipfel/drop-claim/blob/9fb36aab457b1ad3ea27351b004ddcdc5ef30682/src/DropClaim.sol#L181)

**Bankless:** Acknowledged & fixed in [commit 0d3ccd6eb7ad266be54598a52d321cb9bb17e7af](https://github.com/kadenzipfel/drop-claim/commit/0d3ccd6eb7ad266be54598a52d321cb9bb17e7af).

**Cyfrin:** Verified

\clearpage
