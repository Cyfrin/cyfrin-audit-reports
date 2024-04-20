**Lead Auditors**

[Dacian](https://twitter.com/DevDacian)
 
[Carlitox477](https://twitter.com/carlitox477)

**Assisting Auditors**

  


---

# Findings
## Medium Risk


### Attacker can abuse `RewardsDistributor::triggerRoot` to block reward claims and unpause a paused state

**Description:** Consider the code of [`RewardsDistributor::triggerRoot`](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L511-L516):
```solidity
    function triggerRoot() external {
        bytes32 rootCandidateAValue = rootCandidateA.value;
        if (rootCandidateAValue != rootCandidateB.value || rootCandidateAValue == bytes32(0)) revert RootCandidatesInvalid();
        root = Root({value: rootCandidateAValue, lastUpdatedAt: block.timestamp});
        emit RootChanged(msg.sender, rootCandidateAValue);
    }
```

This function:
* can be called by anyone
* if it succeeds, sets `root.value` to `rootCandidateA.value` and `root.lastUpdatedAt` to `block.timestamp`
* doesn't reset `rootCandidateA` or `rootCandidateB`, so it can be called over and over again to continually update `root.lastUpdatedAt` or to set `root.value` to `rootCandidateA.value`.

**Impact:** An attacker can abuse this function in 2 ways:
* by calling it repeatedly an attacker can continually increase `root.lastUpdatedAt` to trigger the [claim delay revert](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L190-L191) in `RewardsDistributor::claimAll` effectively blocking reward claims
* by calling it after reward claims have been paused, an attacker can effectively unpause the paused state since `root.value` is over-written with the valid value from `rootCandidateA.value` and claim pausing [works](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L547) by setting `root.value == zeroRoot`.

**Recommended Mitigation:** Two possible options:
* Make `RewardsDistributor::triggerRoot` a permissioned function such that an attacker can't call it
* Change `RewardsDistributor::triggerRoot` to reset `rootCandidateA.value = zeroRoot` such that it can't be successfully called repeatedly.

**Solidly:**
Fixed in commits [653c196](https://github.com/SolidlyV3/v3-rewards/commit/653c19659474c93ef0958479191d8103bc7b7e82) & [1170eac](https://github.com/SolidlyV3/v3-rewards/commit/1170eacc9b08bed9453a34fdf498f8bb10457f17).

**Cyfrin:**
Verified. One consequence of the updated implementation is that the contract will start in the "paused" state and root candidates will be unable to be set. This means that the admin will have to set the first valid root via `setRoot` in order to "unpause" from the initial state post-deployment.


### `RewardsDistributor` doesn't correctly handle deposits of fee-on-transfer incentive tokens

**Description:** `the kenneth` stated in telegram that Fee-On-Transfer tokens are fine to use as incentive tokens with `RewardsDistributor`, however when receiving Fee-On-Transfer tokens and storing the reward amount the accounting does not account for the fee deducted from the transfer amount in-transit, [for example](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L348-L359):

```solidity
function _depositLPIncentive(
    StoredReward memory reward,
    uint256 amount,
    uint256 periodReceived
) private {
    IERC20(reward.token).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );

    // @audit stored `amount` here will be incorrect since it doesn't account for
    // the actual amount received after the transfer fee was deducted in-transit
    _storeReward(periodReceived, reward, amount);
}
```

**Impact:** The actual reward calculation is done off-chain and is outside the audit scope nor do we have visibility of that code. But events emitted by `RewardsDistributor` and the stored incentive token deposits in `RewardsDistributor::periodRewards` use incorrect amounts for Fee-On-Transfer incentive token deposits.

**Recommended Mitigation:** In `RewardsDistributor::_depositLPIncentive` & `depositVoteIncentive`:
* read the `before` transfer token balance of `RewardsDistributor` contract
* perform the token transfer
* read the `after` transfer token balance of `RewardsDistributor` contract
* calculate the difference between the `after` and `before` balances to get the true amount that was received by the `RewardsDistributor` contract accounting for the fee that was deducted in-transit
* use the true received amount to generate events and write the received incentive token amounts to `RewardsDistributor::periodRewards`.

Also note that `RewardsDistributor::periodRewards` is never read in the contract, only written to. If it is not used by off-chain processing then consider removing it.

**Solidly:**
Fixed in commit [be54da1](https://github.com/SolidlyV3/v3-rewards/commit/be54da1fea0f1f6f3e4c6ee20464b962cbe2077f).

**Cyfrin:**
Verified.


### Attacker can corrupt `RewardsDistributor` internal accounting forcing LP token incentive deposits to revert for tokens like `cUSDCv3`

**Description:** Some tokens like [cUSDCv3](https://etherscan.io/address/0x9e4dde024f7ea5cf13d5f09c51a1555305c99f0c#code#F1#L930) contains a special case for `amount == type(uint256).max` in their transfer functions that results in only the user's balance being transferred.

For such tokens in this case incentive deposits via `depositLPTokenIncentive` will transfer less tokens than expected. The consequence of this is if a protocol like Compound wanted to incentivize a pool with a token like `cUSDCv3`, an attacker can front-run their transaction to corrupt the internal accounting forcing it to revert.

**Impact:** Corrupted accounting for incentive reward deposits with tokens like `cUSDCv3` can be exploited to deny future incentive reward deposits using the same token.

**POC:**
Consider the following functions:
```solidity
function _validateIncentive(
    address token,
    uint256 amount,
    uint256 distributionStart,
    uint256 numDistributionPeriods
) private view {
    // distribution must start on future epoch flip and last for [1, max] periods
    if (
        numDistributionPeriods == 0                  || // Distribution in 0 periods is invalid
        numDistributionPeriods > maxIncentivePeriods || // Distribution over max period is invalid
        distributionStart % EPOCH_DURATION != 0      || // Distribution must start at the beginning of a week
        distributionStart < block.timestamp             // Distribution must start in the future
    ) revert InvalidIncentiveDistributionPeriod();

    // approvedIncentiveAmounts indicates the min amount of
    // tokens to distribute per period for a whitelisted token
    uint256 minAmount = approvedIncentiveAmounts[token] * numDistributionPeriods;

    // @audit validation passes for `amount == type(uint256).max`
    if (minAmount == 0 || amount < minAmount)
        revert InvalidIncentiveAmount();
}

function _depositLPIncentive(
    StoredReward memory reward,
    uint256 amount,
    uint256 periodReceived
) private {
    // @audit does not guarantee that `amount`
    // is transferred if `amount == type(uint256).max`
    IERC20(reward.token).safeTransferFrom(msg.sender, address(this), amount);

    // @audit incorrect `amount` will be stored in this case
    _storeReward(periodReceived, reward, amount);
}
```
If a protocol like Compound wanted to incentivize a pool with a token like `cUSDCv3` for 2 periods:
1. Bob see this in the mempool and calls `RewardsDistributor.depositLPTokenIncentive(pool that compound want to incentivize, cUSDCv3, type(uint256).max, distribution start to DOS, valid numDistributionPeriods)`
2. When Compound try to do a valid call, `_storeReward` will revert because `periodRewards[period][rewardKey] += amount` will overflow since its amount value is `type(uint256).max` due to Bob's front-run transaction.


**Recommended mitigation:**
One possible solution:

1) Divide `_validateIncentive` into 2 functions:

```solidity
function _validateDistributionPeriod(
    uint256 distributionStart,
    uint256 numDistributionPeriods
) private view {
    // distribution must start on future epoch flip and last for [1, max] periods
    if (
        numDistributionPeriods == 0                  || // Distribution in 0 periods is invalid
        numDistributionPeriods > maxIncentivePeriods || // Distribution over max period is invalid
        distributionStart % EPOCH_DURATION != 0      || // Distribution must start at the beginning of a week
        distributionStart < block.timestamp             // Distribution must start in the future
    ) revert InvalidIncentiveDistributionPeriod();
}

// Before calling this function, _validateDistributionPeriod must be called
function _validateIncentive(
    address token,
    uint256 amount,
    uint256 numDistributionPeriods
) private view {
    uint256 minAmount = approvedIncentiveAmounts[token] * numDistributionPeriods;

    if (minAmount == 0 || amount < minAmount)
        revert InvalidIncentiveAmount();
}
```

2) Change `_depositLPIncentive` to return the actual amount received and call `_validateIncentive`:

```diff
function _depositLPIncentive(
    StoredReward memory reward,
+   uint256 numDistributionPeriods
    uint256 amount,
    uint256 periodReceived
-) private {
+) private returns(uint256 actualDeposited) {
+   uint256 tokenBalanceBeforeTransfer = IERC20(reward.token).balanceOf(address(this));
    IERC20(reward.token).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
-   _storeReward(periodReceived, reward, amount);
+   actualDeposited = IERC20(reward.token).balanceOf(address(this)) - tokenBalanceBeforeTransfer;
+   _validateIncentive(reward.token, actualDeposited, numDistributionPeriods);
+   _storeReward(periodReceived, reward, actualDeposited);
}
```

3) Change `depositLPTokenIncentive` to use the new functions, read the actual amount returned and use that in the event emission:

```diff
function depositLPTokenIncentive(
    address pool,
    address token,
    uint256 amount,
    uint256 distributionStart,
    uint256 numDistributionPeriods
) external {
-   _validateIncentive(
-       token,
-       amount,
-       distributionStart,
-       numDistributionPeriods
-   );
+   // Verify that number of period is and start time is valid
+   _validateDistributionPeriod(
+       uint256 distributionStart,
+       uint256 numDistributionPeriods
+   );
    StoredReward memory reward = StoredReward({
        _type: StoredRewardType.LP_TOKEN_INCENTIVE,
        pool: pool,
        token: token
    });
    uint256 periodReceived = _syncActivePeriod();
-   _depositLPIncentive(reward, amount, periodReceived);
+   uint256 actualDeposited = _depositLPIncentive(reward, amount, periodReceived);

    emit LPTokenIncentiveDeposited(
        msg.sender,
        pool,
        token,
-       amount,
+       actualDeposited
        periodReceived,
        distributionStart,
        distributionStart + (EPOCH_DURATION * numDistributionPeriods)
    );
}
```

This mitigation also resolves the issue related to incorrect accounting for fee-on-transfer tokens.

**Solidly:**
Fixed in commit [be54da1](https://github.com/SolidlyV3/v3-rewards/commit/be54da1fea0f1f6f3e4c6ee20464b962cbe2077f).

**Cyfrin:**
Verified.

\clearpage
## Low Risk


### Use low level `call()` to prevent gas griefing attacks when returned data not required

**Description:** Using `call()` when the returned data is not required unnecessarily exposes to gas griefing attacks from huge returned data payload. For [example](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L563-L564):

```solidity
(bool sent, ) = _to.call{value: _amount}("");
require(sent);
```

Is the same as writing:

```solidity
(bool sent, bytes memory data) = _to.call{value: _amount}("");
require(sent);
```

In both cases the returned data will be copied into memory exposing the contract to gas griefing attacks, even though the returned data is not used at all.

**Impact:** Contract unnecessarily exposed to gas griefing attacks.

**Recommended Mitigation:** Use a low-level call when the returned data is not required, eg:

```solidity
bool sent;
assembly {
    sent := call(gas(), _to, _amount, 0, 0, 0, 0)
}
if (!sent) revert FailedToSendEther();
```

**Solidly:**
Fixed in commit [be54da1](https://github.com/SolidlyV3/v3-rewards/commit/be54da1fea0f1f6f3e4c6ee20464b962cbe2077f).

**Cyfrin:**
Verified.


### Check for valid pool in `RewardsDistributor::depositLPSolidEmissions`, `depositLPTokenIncentive` and `_collectPoolFees`

**Description:** `RewardsDistributor::depositLPSolidEmissions` and `depositLPTokenIncentive` contain no validation that `pool` is a valid pool address, while `depositVoteIncentive` does perform some validation of the pool parameter. Consider adding validation to ensure LP emissions/incentives are recorded against a valid `pool` parameter.

Similarly `RewardsDistributor::_collectPoolFees` never validates if the pool is legitimate and anyone can call its parent function `collectPoolFees`. An attacker could create their own fake pool which implements `ISolidlyV3PoolMinimal::collectProtocol` but doesn't transfer any tokens just returns large output amounts, and for `token0` and `token1` return the address of popular high-profile tokens.

This could make it appear like `RewardsDistributor` has received significantly more rewards than it actually has by corrupting the event log and `periodRewards` storage location with false information. Consider validating the pool in `RewardsDistributor::_collectPoolFees` and potentially whether `RewardsDistributor` has actually received the tokens.

Also note that `RewardsDistributor::periodRewards` is never read in the contract, only written to. If it is not used by off-chain processing then consider removing it.

**Solidly:**
Acknowledged. The off-chain processor only computes pools that are validated through the factory.


### `SolidlyV3Pool::_mint` and `_swap` don't verify tokens were actually received by the pool

**Description:** Some versions of [`SolidlyV3Pool::_mint`](https://github.com/SolidlyV3/v3-core/blob/main/contracts/SolidlyV3Pool.sol#L288-L291) & [`_swap`](https://github.com/SolidlyV3/v3-core/blob/callbacks/contracts/SolidlyV3Pool.sol#L644-L650) don't verify tokens were actually received by the pool. In contrast UniswapV3's equivalent [`mint`](https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L483-L484) & [`swap`](https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L777-L783) functions always verify tokens were received by the pool.

**Impact:** Solidly will be more vulnerable to malicious tokens or tokens with non-standard behavior. One possible attack path is a token which has a blacklist that doesn't process transfers for blacklisted accounts but also doesn't revert and simply returns `true`. The token owner can execute a more subtle rug-pull by:
* allowing the pool to grow to a sufficient size
* adding themselves to the blacklist
* calling `swap` to drain the other token without actually transferring any of the malicious token, draining the liquidity pool.

**Recommended Mitigation:** `_mint` and `_swap` functions should check that the expected token amounts were transferred into the pool.

**Solidly:**
We ommited this on purpose for gas savings since we don't support exotic ERC20s on v3-core. Users can create such a pool if they want since it's permission-less, but it's something we explicitly and officially don't support.


### Change `v3-rewards/package.json` to require minimum OpenZeppelin v4.9.2 as prior versions had a security vulnerability in Merkle Multi Proof

**Description:** `v3-rewards/package.json` currently [specifies](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/package.json#L7) a minimum OpenZeppelin version of 4.5.0. However some older OZ versions contained a security [vulnerability](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-wprv-93r4-jj2p) in the Merkle Multi Proof which was fixed in 4.9.2.

**Recommended Mitigation:** Change `v3-rewards/package.json` to require minimum OpenZeppelin v4.9.2:
```solidity
"@openzeppelin/contracts": "^4.9.2",
```

**Solidly:**
Fixed in commit [6481747](https://github.com/SolidlyV3/v3-rewards/commit/6481747737b98c8650a36f87b1aeace815505ba9).

**Cyfrin:**
Verified.

\clearpage
## Informational


### Refactor hard-coded max pool fee into a constant as it is used in multiple places

**Description:** `100000` is the hard-coded max pool fee. There are two require statements enforcing this hard-coded value in `SolidlyV3Factory::enableFeeAmount` [L90](https://github.com/SolidlyV3/v3-core/blob/main/contracts/SolidlyV3Factory.sol#L90) and `SolidlyV3Pool::setFee` [L794](https://github.com/SolidlyV3/v3-core/blob/main/contracts/SolidlyV3Pool.sol#L794).

Using the same hard-coded value in multiple places throughout the code is error-prone as when making future code updates a developer can easily update one place but forget to update the others; recommend refactoring to use a constant which can be referenced instead of hard-coding.

**Solidly:**
Acknowledged.


### Prefer explicit function for renouncing ownership and 2-step ownership transfer

**Description:** [`RewardsDistributor::setOwner`](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L459-L462) and [`SolidlyV3Factory::setOwner`](https://github.com/SolidlyV3/v3-core/blob/callbacks/contracts/SolidlyV3Factory.sol#L60-L64) allow the current owner to brick the ownership by setting `owner = address(0)`, which would prevent future access to admin functionality. Prefer an explicit function for renouncing ownership to prevent this occurring by mistake and prefer a 2-step ownership transfer mechanism. Both of these features are available in OZ [Ownable2Step](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol).

**Solidly:**
Acknowledged.


### `require` and `revert` statements should have descriptive reason strings

**Description:** `require` and `revert` statements should have descriptive reason strings:

```solidity
File: SolidlyV3Factory.sol

46:         require(tokenA != tokenB);

48:         require(token0 != address(0));

50:         require(tickSpacing != 0);

51:         require(getPool[token0][token1][tickSpacing] == address(0));

61:         require(msg.sender == owner);

68:         require(msg.sender == owner);

75:         require(msg.sender == owner);

88:         require(msg.sender == owner);

89:         require(fee <= 100000);

94:         require(tickSpacing > 0 && tickSpacing < 16384);

95:         require(feeAmountTickSpacing[fee] == 0);

```

```solidity
File: SolidlyV3Pool.sol

116:         require(success && data.length >= 32);

127:         require(success && data.length >= 32);

302:         require(amount > 0);

327:         require(amount > 0);

947:         require(fee <= 100000);

```

```solidity
File: libraries/FullMath.sol

34:             require(denominator > 0);

43:         require(denominator > prod1);

120:             require(result < type(uint256).max);

```

```solidity
File: RewardsDistributor.sol

564:        require(sent);

595:        require(success && data.length >= 32);

```

**Solidly:**
Acknowledged.


### Functions not used internally could be marked external

**Description:** Functions not used internally could be marked external:

```solidity
File: SolidlyV3Factory.sol

87:     function enableFeeAmount(uint24 fee, int24 tickSpacing) public override {

```

**Solidly:**
Acknowledged.


### Refactor `zeroRoot` declared in multiple functions into a private constant

**Description:** `zeroRoot` is declared and used in `RewardsDistributor::pauseClaimsGovernance` [L546](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L546) and `pauseClaimsPublic` [L554](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L554). Consider refactoring it into a private constant to avoid declaring it in multiple functions.

**Solidly:**
Fixed in commit [653c196](https://github.com/SolidlyV3/v3-rewards/commit/653c19659474c93ef0958479191d8103bc7b7e82).

**Cyfrin:**
Verified.


### Hard-coded pause collateral fee not appropriate for multi-chain usage

**Description:** As Solidly aims to be multi-chain in the future, [hard-coding](https://github.com/SolidlyV3/v3-rewards/blob/6dfb435392ffa64652c8f88c98698756ca80cf28/contracts/RewardsDistributor.sol#L553) a pause collateral fee of 5 ether in `RewardsDistributor::pauseClaimsPublic` may not be appropriate on other chains as this amount would represent very little value. Consider having a `public` storage variable for the pause collateral fee and an `onlyOwner` function to set it.

**Solidly:**
Fixed in commit [653c196](https://github.com/SolidlyV3/v3-rewards/commit/653c19659474c93ef0958479191d8103bc7b7e82).

**Cyfrin:**
Verified.


### `RewardsDistributor::_claimSingle` should emit `RewardClaimed` using `amountDelta`

**Description:** In `RewardsDistributor::_claimSingle`, the `amount` parameter gets subtracted from the `previouslyClaimed` parameter. Consider the case where a user is entitled to 10 reward tokens.

The user claims their 10 tokens.

Then later on the user becomes entitled to another 10 tokens for the same pool/token/type (`rewardKey`). If the user tries to claim with `amount = 10` this would now fail; the user must claim with `amount = 20` to pass the subtraction of the previously claimed amount.

This design seems kind of confusing; users have to keep track of the total amount they have claimed, then add to that the new amount they can claim, and call claim with that total amount.

Even though only the difference `amountDelta` is sent to the user, the `RewardClaimed` event is emitted with `amount`. So in the above scenario there would be two `RewardClaimed` events emitted with `amount (10)` and `amount(20)` even though the user only received 20 total reward tokens.

Consider refactoring this function such that users can simply call it with the amount they are entitled to claim, or at least changing the event emission to use `amountDelta` instead of `amount`.

**Solidly:**
Acknowledged.


### `CollateralWithdrawn` and `CollateralDeposited` events should include relevant amounts

**Description:** In `RewardsDistributor::withdrawCollateral` add the `_amount` parameter when emitting the `CollateralWithdrawn` event. This is required as the amount sent does not have to be the same as the amount deposited.

Consider adding the amount deposited to the `CollateralDeposited` event as well, since the required collateral amount could be changed meaning that the current value may not be true for every collateral deposit that has occurred.

**Solidly:**
Fixed in commit [6481747](https://github.com/SolidlyV3/v3-rewards/commit/6481747737b98c8650a36f87b1aeace815505ba9).

**Cyfrin:**
Verified.

\clearpage
## Gas Optimization


### Cache array length outside of loop

**Description:** Cache array length outside of loop:

```solidity
File: contracts/RewardsDistributor.sol
// @audit use `numLeaves` from L263 instead of `earners.length`
265:         for (uint256 i; i < earners.length; ) {
```

**Solidly:**
Fixed in commit [6481747](https://github.com/SolidlyV3/v3-rewards/commit/6481747737b98c8650a36f87b1aeace815505ba9).

**Cyfrin:**
Verified.


### Don't initialize variables with default value

**Description:** Don't initialize variables with default value:

```solidity
File: contracts/RewardsDistributor.sol

184:         for (uint256 i = 0; i < numClaims; ) {

```

```solidity
File: libraries/TickMath.sol

67:         uint256 msb = 0;

```

**Solidly:**
Fixed in commit [6481747](https://github.com/SolidlyV3/v3-rewards/commit/6481747737b98c8650a36f87b1aeace815505ba9) for `RewardsDistributor`; v3-core is already deployed and not upgradeable.

**Cyfrin:**
Verified.


### Prefer `++x` to `x++`

**Description:** Prefer `++x` to `x++`:

File: `TickBitmap.sol`
```solidity
48:        if (tick < 0 && tick % tickSpacing != 0) compressed--; // round towards negative infinity
```

File: `SolidlyV3Pool.sol`
```solidity
965:            if (amount0 == poolFees.token0) amount0--; // ensure that the slot is not cleared, for gas savings
```

File: `SolidlyV3Pool.sol`
```solidity
970:            if (amount1 == poolFees.token1) amount1--; // ensure that the slot is not cleared, for gas savings
```

File: `FullMath.sol`
```solidity
120:            result++;
```

**Solidly:**
Acknowledged.


### Cache storage variables in memory when read multiple times without being changed

**Description:** Cache storage variables in memory when read multiple times without being changed:

File: `SolidlyV3Pool.sol`
```solidity
// @audit no need to load `slot0.fee` twice from storage since it doesn't change;
// load from storage once into memory then use in-memory copy
913:        uint256 fee0 = FullMath.mulDivRoundingUp(amount0, slot0.fee, 1e6);
914:        uint256 fee1 = FullMath.mulDivRoundingUp(amount1, slot0.fee, 1e6);


// @audit `poolFees.token0` and `poolFees.token1` are read from storage multiple times
// but don't get changed until L966 & L971. Load them both from storage once into memory
// then use the in-memory copy instead of repeatedly reading the same value from storage
961:        amount0 = amount0Requested > poolFees.token0 ? poolFees.token0 : amount0Requested;
962:        amount1 = amount1Requested > poolFees.token1 ? poolFees.token1 : amount1Requested;

964:        if (amount0 > 0) {
965:            if (amount0 == poolFees.token0) amount0--; // ensure that the slot is not cleared, for gas savings
966:            poolFees.token0 -= amount0;
967:            TransferHelper.safeTransfer(token0, recipient, amount0);
968:        }
969:        if (amount1 > 0) {
970:            if (amount1 == poolFees.token1) amount1--; // ensure that the slot is not cleared, for gas savings
971:            poolFees.token1 -= amount1;
972:            TransferHelper.safeTransfer(token1, recipient, amount1);
973:        }
```

File: `SolidlyV3Factory.sol`
```solidity
// @audit `owner` is read from storage twice returning the same value each time. Read it from
// storage once into memory, then use the in-memory copy both times
61:        require(msg.sender == owner);
62:        emit OwnerChanged(owner, _owner);
```

**Solidly:**
Acknowledged.


### Use multiple requires instead of a single one with multiple statements is better for gas consumption

**Description:** Use multiple requires instead of a single one with multiple `&&` is better for gas consumption. The reason is because `require` is translated as [revert which does not consume gas](https://ethereum-org-fork.netlify.app/developers/docs/evm/opcodes) if it reverts. However `&&` consume gas. Therefore, opting for multiple require is more gas efficient than opting for a single one with multiple statements that mus be true.

```solidity
// SolidlyV3Pool.sol
116:    require(success && data.length >= 32);
127:    require(success && data.length >= 32);
278:    require(amount0 >= amount0Min && amount1 >= amount1Min, 'AL');
293:    require(amount0 >= amount0Min && amount1 >= amount1Min, 'AL');
391:     require(amount0FromBurn >= amount0FromBurnMin && amount1FromBurn >= amount1FromBurnMin, 'AL');
456:    require(amount0 >= amount0Min && amount1 >= amount1Min, 'AL');

// RewardsDistributor.sol
607:    require(success && data.length >= 32);
```

**Solidly:**
Acknowledged.


### Optimize away two memory variables in `RewardsDistributor::generateLeaves`

**Description:** Optimize away two memory variables in `RewardsDistributor::generateLeaves` by using a named return variable and removing the temporary `leaf` variable:

```solidity
function _generateLeaves(
    address[] calldata earners,
    EarnedRewardType[] calldata types,
    address[] calldata pools,
    address[] calldata tokens,
    uint256[] calldata amounts
) private pure returns (bytes32[] memory leaves) {
    uint256 numLeaves = earners.length;
    // @audit using named return variable
    leaves            = new bytes32[](numLeaves);

    // @audit using cached array length in loop
    for (uint256 i; i < numLeaves; ) {
        // @audit assign straight to return variable
        leaves[i] = keccak256(
            bytes.concat(
                keccak256(
                    abi.encode(
                        earners[i],
                        types[i],
                        pools[i],
                        tokens[i],
                        amounts[i]
                    )
                )
            )
        );
        unchecked {
            ++i;
        }
    }
    return leaves;
}
```

**Solidly:**
Acknowledged.

\clearpage