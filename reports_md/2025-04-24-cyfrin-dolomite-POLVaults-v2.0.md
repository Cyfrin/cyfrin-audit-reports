**Lead Auditors**

[0kage](https://x.com/0kage_eth)

[Farouk](https://x.com/Ubermensh3dot0)

**Assisting Auditors**



---

# Findings
## High Risk


### InfraVault's Permissionless Reward Claiming Can Allow Anyone to Lock Rewards in the MetaVault

**Description:** The `InfraredBGTMetaVault` relies on `_performDepositRewardByRewardType` to handle newly claimed rewards by either depositing them into DolomiteMargin or sending them directly to the vault owner. However, the onchain Infrared vault [contract](https://berascan.com/address/0x67b4e6721ad3a99b7ff3679caee971b07fd85cd1#code) allows anyone to call `getRewardForUser` on any user’s rewards. Note that this function is defined in the `MultiRewards.sol`, the contract that infrared vault derives from.

This can trigger a reward transfer to the MetaVault unexpectedly. Because the code that deposits or forwards these tokens (`_performDepositRewardByRewardType`) only runs during the normal “self-claim” flow, rewards triggered through a third-party call would not go through the intended deposit or distribution logic.

```solidity
/// @inheritdoc IMultiRewards
function getRewardForUser(address _user)
    public
    nonReentrant
    updateReward(_user)
{
    onReward();
    uint256 len = rewardTokens.length;
    for (uint256 i; i < len; i++) {
        address _rewardsToken = rewardTokens[i];
        uint256 reward = rewards[_user][_rewardsToken];
        if (reward > 0) {
            (bool success, bytes memory data) = _rewardsToken.call{
                gas: 200000
            }(
                abi.encodeWithSelector(
                    ERC20.transfer.selector, _user, reward
                )
            );
            if (success && (data.length == 0 || abi.decode(data, (bool)))) {
                rewards[_user][_rewardsToken] = 0;
                emit RewardPaid(_user, _rewardsToken, reward);
            } else {
                continue;
            }
        }
    }
}
```

**Impact:** An attacker could force rewards to be sent to the MetaVault’s address without triggering `_performDepositRewardByRewardType`. As a result, those newly arrived tokens could stay in the MetaVault contract, never being staked or deposited into DolomiteMargin or distributed to the vault owner.

We note that the token loss is not permanent as the InfraredBGTMetaVault contract is upgradeable. Nevertheless this can cause delays as every user has an independent vault and upgrading each vault would be cumbersome. In the meanwhile, vault owners cannot use their received rewards within the Dolomite Protocol.


**Proof of Concept:** Consider the following scenario:
	1.	An attacker calls `infravault.getRewardForUser(metaVaultAddress)`.
	2.	The reward is transferred to metaVaultAddress rather than going through the `_performDepositRewardByRewardType` logic.
	3.	The tokens remain stuck in the MetaVault contract if there is no fallback mechanism to move or stake them again.

**Recommended Mitigation:** Consider modifying the `_performDepositRewardByRewardType` to add the token balance in the vault to the reward amount and routing all BGT token vault staking into Infrared vaults via the metavault.

```diff
  function _performDepositRewardByRewardType(
        IMetaVaultRewardTokenFactory _factory,
        IBerachainRewardsRegistry.RewardVaultType _type,
        address _token,
        uint256 _amount
    ) internal {
++ _amount += IERC20(token).balanceOf(address(this));
}
```

**Dolomite:** Fixed in [d0a638a](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/d0a638aefdda72925329b2da60f405cd4450f78a).

**Cyfrin:** Verified

\clearpage
## Medium Risk


### User rewards may remain unclaimed after calling `InfraredBGTIsolationModeTokenVaultV1::exit()` function

**Description:** When a user calls `InfraredBGTIsolationModeTokenVaultV1::exit` in a scenario where rewards are in the same token (iBGT), the function correctly unstakes their original deposit but:

- The rewards are credited to the user's Dolomite Margin account balance
- The same tokens are simultaneously re-staked in the Infrared vault

This creates a situation where users may believe they've fully exited the protocol, but in reality, they have rewards still staked. The `_exit()` function calls `_handleRewards()` which processes any rewards earned. The issue occurs when `_handleRewards()` automatically deposits iBGT rewards back into Dolomite Margin and re-stakes them:


```solidity
function _exit() internal {
    IInfraredVault vault = registry().iBgtStakingVault();

    IInfraredVault.UserReward[] memory rewards = vault.getAllRewardsForUser(address(this));
    vault.exit();

    _handleRewards(rewards);
}

function _handleRewards(IInfraredVault.UserReward[] memory _rewards) internal {
    IIsolationModeVaultFactory factory = IIsolationModeVaultFactory(VAULT_FACTORY());
    for (uint256 i = 0; i < _rewards.length; ++i) {
        if (_rewards[i].amount > 0) {
            if (_rewards[i].token == UNDERLYING_TOKEN()) {
                _setIsDepositSourceThisVault(true);
                factory.depositIntoDolomiteMargin(
                    DEFAULT_ACCOUNT_NUMBER,
                    _rewards[i].amount
                ); //@audit restakes the reward amount
                assert(!isDepositSourceThisVault());
            } else {
                // Handle other tokens...
            }
        }
    }
}
```

**Impact:**
- Users may never realize they still have assets staked in the protocol
- Rewards remain locked in a separate vault that users might not know to check
- For smaller reward amounts, gas costs might exceed the value, effectively trapping these funds
- Poor user experience when "exit" doesn't fully exit the protocol

**Proof of Concept:** Add the following test to the `#exit` class of tests in `InfraredBGTIsolationModeTokenVaultV1.ts`

```typescript
    it('should demonstrate that iBGT rewards are re-staked after exit', async () => {
      await testInfraredVault.setRewardTokens([core.tokens.iBgt.address]);
      await core.tokens.iBgt.connect(iBgtWhale).approve(testInfraredVault.address, rewardAmount);
      await testInfraredVault.connect(iBgtWhale).addReward(core.tokens.iBgt.address, rewardAmount);
      await registry.connect(core.governance).ownerSetIBgtStakingVault(testInfraredVault.address);

      await iBgtVault.depositIntoVaultForDolomiteMargin(defaultAccountNumber, amountWei);
      await expectProtocolBalance(core, iBgtVault, defaultAccountNumber, iBgtMarketId, amountWei);

      // Get   the initial staking balance before exit
      const initialStakingBalance = await testInfraredVault.balanceOf(iBgtVault.address);
      expect(initialStakingBalance).to.eq(amountWei);

      // Call exit which should unstake original amount but rewards will be re-staked
      await iBgtVault.exit();

      // Check that staking balance equals reward amount (rewards were re-staked)
      const finalStakingBalance = await testInfraredVault.balanceOf(iBgtVault.address);
      expect(finalStakingBalance).to.eq(rewardAmount, "Staking balance should equal reward amount after exit");

      // Verify original deposit is in the wallet (but not rewards)
      await expectWalletBalance(iBgtVault, core.tokens.iBgt, amountWei);

      // Verify protocol balance now includes both original deposit and rewards
      await expectProtocolBalance(core, iBgtVault, defaultAccountNumber, iBgtMarketId, amountWei.add(rewardAmount));
    });
```

**Recommended Mitigation:** Consider avoiding restaking when the user calls `exit` explicitly - it is counter-intuitive even from a UX standpoint to restake assets in the same vault when the user has expressed intent to exit the vault completely. Also add clear documentation explaining how rewards are handled across different vaults

**Dolomite:** Fixed in [d0a638a](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/d0a638aefdda72925329b2da60f405cd4450f78a).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Missing validation for initialization calldata in `POLIsolationModeWrapperUpgradeableProxy` constructor

**Description:** The `POLIsolationModeWrapperUpgradeableProxy` constructor accepts initialization calldata without performing any validation on its content before executing it via `delegatecall` to the implementation contract. Specifically:

- The constructor does not verify that the `calldata` targets the expected initialize(address) function
- The constructor does not verify that the provided vaultFactory address parameter is non-zero

```solidity
// POLIsolationModeWrapperUpgradeableProxy.sol
constructor(
    address _berachainRewardsRegistry,
    bytes memory _initializationCalldata
) {
    BERACHAIN_REWARDS_REGISTRY = IBerachainRewardsRegistry(_berachainRewardsRegistry);
    Address.functionDelegateCall(
        implementation(),
        _initializationCalldata,
        "POLIsolationModeWrapperProxy: Initialization failed"
    );
}
```
This lack of validation means the constructor will blindly execute any calldata, potentially setting critical contract parameters incorrectly during deployment.

Note that a similar issue exists in `POLIsolationModeUnwrapperUpgradeableProxy`


**Impact:** The proxy could be initialized with a zero or invalid vaultFactory address, rendering it non-functional or insecure.  Additionally, if the implementation contract is upgraded and introduces new functions with weaker access controls, this pattern would allow those functions to be called during initialization of new proxies.

**Recommended Mitigation:** Consider adding explicit validation for both the function selector and parameters in the constructor:

```solidity
constructor(
    address _berachainRewardsRegistry,
    bytes memory _initializationCalldata
) {
    BERACHAIN_REWARDS_REGISTRY = IBerachainRewardsRegistry(_berachainRewardsRegistry);

    // Validate function selector is initialize(address)
    require(
        _initializationCalldata.length == 36 &&
        bytes4(_initializationCalldata[0:4]) == bytes4(keccak256("initialize(address)")),
        "Invalid initialization function"
    );

     // Decode and validate the vaultFactory address is non-zero
    address vaultFactory = abi.decode(_initializationCalldata[4:], (address));
    require(vaultFactory != address(0), "Zero vault factory address");

    Address.functionDelegateCall(
        implementation(),
        _initializationCalldata,
        "POLIsolationModeWrapperProxy: Initialization failed"
    );
}
```

**Dolomite:**
Acknowledged.

**Cyfrin:** Acknowledged.


### Reward loss risk when transitioning between reward vault types

**Description:** When a user's default reward vault type for an asset is changed (e.g., from NATIVE or BGTM to INFRARED) in the `InfraredBGTMetaVault` contract, current logic attempts to claim outstanding rewards before switching the type. However, the implementation fails to retrieve rewards from the user's current vault type, leading to permanent loss of accrued rewards.

The issue occurs in the relationship between `_setDefaultRewardVaultTypeByAsset` and `_getReward` functions:

- When staking tokens via `_stake`, the function calls `_setDefaultRewardVaultTypeByAsset` to ensure the asset uses the INFRARED reward type.
- If the asset's current reward type is not INFRARED, `_setDefaultRewardVaultTypeByAsset` calls `_getReward` to claim pending rewards for the asset before changing the type.
-  However, `_getReward` hardcodes the reward vault type to INFRARED instead of using the user's current reward type

```solidity
function _getReward(address _asset) internal {
    IBerachainRewardsRegistry.RewardVaultType rewardVaultType = IBerachainRewardsRegistry.RewardVaultType.INFRARED;
    IInfraredVault rewardVault = IInfraredVault(REGISTRY().rewardVault(
        _asset,
        rewardVaultType  // Always uses INFRARED, ignoring user's current type
    ));
    // ... claim rewards logic ...
}
```

This means that when transitioning from another reward type (e.g., NATIVE or BGTM) to INFRARED, the contract attempts to claim rewards from the INFRARED vault even though the user's rewards are accrued in a different vault type.

Additionally, the assertion that should prevent changing types when a user has a staked balance is ineffective for non-INFRARED types:

```solidity
assert(getStakedBalanceByAssetAndType(_asset, currentType) == 0);
```

This assertion will always pass for non-INFRARED types because `getStakedBalanceByAssetAndType` only can have non-zero balances for INFRARED due to the `onlyInfraredType` modifier on all staking functions.


**Impact:** While the protocol currently only intends to support the INFRARED reward type, this issue creates a potential risk for future expansion.

If/when the protocol adds support for additional reward types (NATIVE, BGTM) and users accrue rewards in these vaults, they would permanently lose these rewards when transitioning to the INFRARED type. Once the registry is updated to use INFRARED as the default reward type, the rewards in the original vault become inaccessible through normal contract interactions.

The severity of this issue depends on the protocol's roadmap for supporting multiple reward types. If there are definite plans to expand beyond INFRARED, this represents a significant risk of permanent reward loss for users.

**Proof of Concept:** Consider following scenario:
- In a future version, assume a user has accrued rewards in a NATIVE reward vault
- User calls a function that triggers `_setDefaultRewardVaultTypeByAsset` to transition to INFRARED
- The assertion `assert(getStakedBalanceByAssetAndType(_asset, currentType) == 0)` passes because balances in this contract are only tracked for INFRARED
- `_getReward(_asset)` is called but retrieves from INFRARED vault instead of NATIVE vault
- The registry is updated via `REGISTRY().setDefaultRewardVaultTypeFromMetaVaultByAsset(_asset, _type)`
- User's rewards in the NATIVE vault are now inaccessible

**Recommended Mitigation:** If the protocol plans to support multiple reward types in the future, modify the `_getReward` function to claim rewards from the user's current reward vault type.

Additionally, considering implementing proper balance tracking for all reward types if multiple types will be supported, or clearly document that transitioning between reward types requires manual reward claiming first.

If only INFRARED vault is supported, consider removing `_setDefaultRewardVaultTypeByAsset` as it is not serving any purpose. Since this is called in the `stake` function, removing this will simplify the code and save gas.

**Dolomite:**
Acknowledged. We know code will have to change a good bit to allow multiple reward types.

**Cyfrin**
Acknowledged.



### Rewards in iBGT cannot be redeemed when infrared vault staking is paused

**Description:** Current reward handling mechanism enforces automatic reinvestment of iBGT rewards back into the staking pool, without providing an alternative when staking is disabled.

When the Infrared protocol pauses staking (which can happen for various reasons such as security emergencies or technical issues), users are left with no way to access their earned rewards, effectively freezing these assets until staking is resumed. It is noteworthy that [InfraredVault](https://berascan.com/address/0x67b4e6721ad3a99b7ff3679caee971b07fd85cd1#code) does not prevent redeeming rewards/ unstaking even when staking is paused

The issue lies in the `_handleRewards` function, which automatically attempts to reinvest iBGT rewards:

```solidity
function _handleRewards(IInfraredVault.UserReward[] memory _rewards) internal {
    IIsolationModeVaultFactory factory = IIsolationModeVaultFactory(VAULT_FACTORY());
    for (uint256 i = 0; i < _rewards.length; ++i) {
        if (_rewards[i].amount > 0) {
            if (_rewards[i].token == UNDERLYING_TOKEN()) {
                _setIsDepositSourceThisVault(true);
                factory.depositIntoDolomiteMargin(
                    DEFAULT_ACCOUNT_NUMBER,
                    _rewards[i].amount
                );
                assert(!isDepositSourceThisVault());
            } else {
                // ... handle other token types ...
            }
        }
    }
}
```

When the staking function in the Infrared vault is paused, as it can be through the pauseStaking() function...

```solidity
/// @inheritdoc IInfraredVault
function pauseStaking() external onlyInfrared {
    if (paused()) return;
    _pause();
}
```

...the staking operation in `executeDepositIntoVault` will fail due to the whenNotPaused modifier in the InfraredVault:

```solidity
function stake(uint256 amount) external whenNotPaused {
     // code
```

**Impact:** Users on Dolomite are unable to access their earned rewards during periods when staking is paused in the Infrared vault even though such redemption is allowed on Infrared vaults.


**Proof of Concept:** The `TestInfraredVault` is made `Pausable` to align with the on-chain Infrared vault contract and `whenNotPaused` modifier is added to the `stake` function.

```solidity
contract TestInfraredVault is ERC20, Pausable {

   function unpauseStaking() external {
        if (!paused()) return;
        _unpause();
    }

    function pauseStaking() external {
        if (paused()) return;
        _pause();
    }

    function stake(uint256 amount) external whenNotPaused {
        _mint(msg.sender, amount);
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
    }
}
```

Add the following test to the #getReward class of tests in `InfraredBGTIsolationModeTokenVaultV1.ts`

```typescript
  it('should revert when staking is paused and rewards are in iBGT', async () => {
      await testInfraredVault.setRewardTokens([core.tokens.iBgt.address]);

      // Add iBGT as reward token and fund the reward
      await core.tokens.iBgt.connect(iBgtWhale).approve(testInfraredVault.address, rewardAmount);
      await testInfraredVault.connect(iBgtWhale).addReward(core.tokens.iBgt.address, rewardAmount);
      await registry.connect(core.governance).ownerSetIBgtStakingVault(testInfraredVault.address);

      // Deposit iBGT into the vault
      await iBgtVault.depositIntoVaultForDolomiteMargin(defaultAccountNumber, amountWei);
      await expectProtocolBalance(core, iBgtVault, defaultAccountNumber, iBgtMarketId, amountWei);

      // Advance time to accumulate rewards
      await increase(ONE_DAY_SECONDS * 30);

      // Pause staking in the InfraredVault
      await testInfraredVault.pauseStaking();
      expect(await testInfraredVault.paused()).to.be.true;

      //Calling getReward should revert because reinvesting iBGT rewards will fail due to staking being paused
      await expectThrow(
        iBgtVault.getReward()
      );


      // Verify balances remain unchanged
      await expectWalletBalance(iBgtVault, core.tokens.iBgt, ZERO_BI);
      await expectProtocolBalance(core, iBgtVault, defaultAccountNumber, iBgtMarketId, amountWei);

      // Unpause to allow normal operation to continue
      await testInfraredVault.unpauseStaking();
      expect(await testInfraredVault.paused()).to.be.false;

      // Now getReward should succeed
      await iBgtVault.getReward();
      await expectWalletBalance(iBgtVault, core.tokens.iBgt, ZERO_BI);
      await expectProtocolBalance(core, iBgtVault, defaultAccountNumber, iBgtMarketId, amountWei.add(rewardAmount));

      // Verify the reward was restaked
      expect(await testInfraredVault.balanceOf(iBgtVault.address)).to.eq(amountWei.add(rewardAmount));
    });
```


**Recommended Mitigation:** Consider checking if the BGT staking vault is `paused` before attempting to re-invest the rewards. If vault is paused, rewards can either be retained in the vault or transferred back to the vault owner.

**Dolomite:** Fixed in [7b83e77](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/7b83e778d739c9afb039a8a8d4fe06d931f4bb22).

**Cyfrin:** Verified

\clearpage
## Informational


### Redundant check for non-zero reward amount in `_handleRewards` function

**Description:** In `InfraredBGTIsolationModeTokenVaultV1.sol`, the `_handleRewards` function includes a redundant check for positive reward amounts, as shown below:

```solidity
//InfraredBGTIsolationModeTokenVaultV1.sol
function _handleRewards(IInfraredVault.UserReward[] memory _rewards) internal {
    IIsolationModeVaultFactory factory = IIsolationModeVaultFactory(VAULT_FACTORY());
    for (uint256 i = 0; i < _rewards.length; ++i) {
        if (_rewards[i].amount > 0) {  // <-- This check is redundant
            if (_rewards[i].token == UNDERLYING_TOKEN()) {
                _setIsDepositSourceThisVault(true);
                factory.depositIntoDolomiteMargin(
                    DEFAULT_ACCOUNT_NUMBER,
                    _rewards[i].amount
                );
                assert(!isDepositSourceThisVault());
            } else {
                // ... rest of function
            }
        }
    }
}
```

This check is redundant because the getAllRewardsForUser function in the [InfraredVault](https://berascan.com/address/0x67b4e6721ad3a99b7ff3679caee971b07fd85cd1#code) only returns rewards with a positive amount:

```solidity
// InfraredVault.sol
function getAllRewardsForUser(address _user) external view returns (UserReward[] memory) {
    uint256 len = rewardTokens.length;
    UserReward[] memory tempRewards = new UserReward[](len);
    uint256 count = 0;
    for (uint256 i = 0; i < len; i++) {
        uint256 amount = earned(_user, rewardTokens[i]);
        if (amount > 0) {  // @audit <-- Already filtering for positive amounts
            tempRewards[count] = UserReward({token: rewardTokens[i], amount: amount});
            count++;
        }
    }
    // Create a new array with the exact size of non-zero rewards
    UserReward[] memory userRewards = new UserReward[](count);
    for (uint256 j = 0; j < count; j++) {
        userRewards[j] = tempRewards[j];
    }
    return userRewards;
}
```

**Recommended Mitigation:** Consider removing the redundant check.

**Dolomite:**
No longer applicable. Code changed a good bit because of bricked rewards fix

**Cyfrin**
Acknowledged.



### Inconsistent ETH handling pattern in Proxy Contracts

**Description:** There is an inconsistency in how proxy contracts handle incoming ETH transactions through their `receive()` and `fallback()` functions. Some proxy contracts delegate both functions to their implementation, while others only delegate the fallback() function while leaving the receive() function empty.

For example, in `MetaVaultUpgradeableProxy.sol`, both functions delegate:

```solidity
// MetaVaultUpgradeableProxy
receive() external payable requireIsInitialized {
    _callImplementation(implementation());
}

fallback() external payable requireIsInitialized {
    _callImplementation(implementation());
}
```

Whereas in `POLIsolationModeWrapperUpgradeableProxy.sol`  and `POLIsolationModeUnwrapperUpgradeableProxy`, only the `fallback()` function delegates:

```solidity
// POLIsolationModeWrapperUpgradeableProxy
receive() external payable {} // solhint-disable-line no-empty-blocks

fallback() external payable {
    _callImplementation(implementation());
}
```

While this is a design choice and not a security issue per se, it could lead to potential confusion among developers who might expect all proxies to handle ETH transfers in a similar manner.

**Recommended Mitigation:** Consider documenting the chosen approach and reasoning in the contract comments to clarify the intended behavior for other developers.

**Dolomite:** Fixed [d4ceeef](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/d4ceeefc9c2a5b8c51c8ea77512e499a2e0bc811).

**Cyfrin:** Verified.


### Missing event emissions for some important state changes

**Description:** The POL contracts are missing event emissions for several important state-changing operations.


_1. POLIsolationModeTokenVaultV1_

- `prepareForLiquidation`: No event when a position is prepared for liquidation
- `stake/unstake`: No event for (un)staking actions
- `getReward`: No event for reward claims
- `exit`:  No event for exiting positions

_2. InfraredBGTMetaVault_
- `chargeDTokenFee`: No event for fee charging

_3. POLIsolationModeTraderBaseV2_
- `_POLIsolationModeTraderBaseV2__initialize`:  No event when vault factory is set

_4. MetaVaultRewardTokenFactory_
- `depositIntoDolomiteMarginFromMetaVault`: No event for deposit from meta vault
- `depositIntoDolomiteMarginFromMetaVault`: No event for deposit of other token from meta vault


**Recommended Mitigation:** Consider reviewing the codebase and adding events that track important state changes.


**Dolomite:** Fixed in [e556252](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/e556252bc49d222ea80540242f832fc996711c26) and [ccfcd12](https://github.com/dolomite-exchange/dolomite-margin-modules/commit/ccfcd1278afafae355020bdee4673c792687a109).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### `_handleRewards` gas optimisation

**Description:** `InfraredBGTMetaVault._performDepositRewardByRewardType` is a function that will be called every time rewards are fetched from Infrared vault. The function can be optimized as follows:

- Remove the reward amount > 0 check (as listed in [*Redundant check for non-zero reward amount in `_handleRewards` function*](#redundant-check-for-nonzero-reward-amount-in-handlerewards-function) )
- Cache frequently used functions `DOLOMITE_MARGIN()`, `OWNER()`
- Cache reward token and reward amount at the start of the loop
- Use unchecked integer for incrementing reward counter


**Recommended Mitigation:** Consider using the below optimized version:

```solidity
function _handleRewards(IInfraredVault.UserReward[] memory _rewards) internal {
    IIsolationModeVaultFactory factory = IIsolationModeVaultFactory(VAULT_FACTORY());
    address owner = OWNER();
    IDolomiteMargin dolomiteMargin = DOLOMITE_MARGIN();

    for (uint256 i = 0; i < _rewards.length;) {
        //@audit Removed redundant check since InfraredVault only sends non-zero rewards
        address rewardToken = _rewards[i].token;
        uint256 rewardAmount = _rewards[i].amount;

        if (rewardToken == UNDERLYING_TOKEN()) {
            _setIsDepositSourceThisVault(true);
            factory.depositIntoDolomiteMargin(
                DEFAULT_ACCOUNT_NUMBER,
                rewardAmount
            );
            assert(!isDepositSourceThisVault());
        } else {
        try dolomiteMargin.getMarketIdByTokenAddress(rewardToken) returns (uint256 marketId) {
                        IERC20(rewardToken).safeApprove(address(dolomiteMargin), rewardAmount);
                        try factory.depositOtherTokenIntoDolomiteMarginForVaultOwner(
                            DEFAULT_ACCOUNT_NUMBER,
                            marketId,
                           rewardAmount
                        ) {} catch {
                            IERC20(rewardToken).safeApprove(address(dolomiteMargin), 0);
                            IERC20(rewardToken).safeTransfer(owner, rewardAmount);
                        }
                    } catch {
                        IERC20(rewardToken).safeTransfer(owner,  rewardAmount);
                    }
        }
        unchecked { ++i; }
    }
}
```


**Dolomite:**
No longer applicable. Code changed a good bit because of bricked rewards fix.

**Cyfrin:** Acknowledged.

\clearpage