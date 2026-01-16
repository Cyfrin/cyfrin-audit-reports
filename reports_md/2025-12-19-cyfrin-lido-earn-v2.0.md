**Lead Auditors**

[Stalin](https://x.com/0xStalin)

[Immeas](https://x.com/0ximmeas)

**Assisting Auditors**



---

# Findings
## Low Risk


### `ERC4626Adapter::maxMint` reverts for uncapped target vaults

**Description:** `ERC4626Adapter::maxMint` forwards `TARGET_VAULT.maxDeposit(address(this))` into `_convertToShares`:
```solidity
function maxMint(address /* user */ ) public view override returns (uint256) {
    if (paused() || emergencyMode) return 0;
    uint256 maxAssets = TARGET_VAULT.maxDeposit(address(this));
    return _convertToShares(maxAssets, Math.Rounding.Floor);
}
```
The [EIP-4626 standard for `maxMint`/`maxDeposit`](https://eips.ethereum.org/EIPS/eip-4626#maxdeposit) states that:
> MUST return `2 ** 256 - 1` if there is no limit on the maximum amount of assets that may be deposited.

Standard ERC4626 implementations (like OpenZeppelin’s), `maxDeposit` / `maxMint` therefore return `type(uint256).max` as a default. Passing this value into `_convertToShares` causes `Math.mulDiv` to overflow and revert, so `maxMint` itself reverts instead of returning a valid upper bound.

**Impact:** `ERC4626Adapter::maxMint` reverts for vaults without any cap which disagrees with the [EIP-4626 standard](https://eips.ethereum.org/EIPS/eip-4626#maxmint) that `maxMint` "MUST NOT revert.".

**Proof of Concept:** Add the following test to `ERC4626Adapter.MaxDeposit.t.sol`:
```solidity
function test_MaxMintReverts() public {
    vm.expectRevert(stdError.arithmeticError);
    vault.maxMint(alice);
}
```

**Recommended Mitigation:** Add a check for the “unbounded” result from the target vault and avoid feeding `type(uint256).max` into `_convertToShares`. For example:

```solidity
function maxMint(address /* user */ ) public view override returns (uint256) {
    if (paused() || emergencyMode) return 0;

    uint256 maxAssets = TARGET_VAULT.maxDeposit(address(this));
    if (maxAssets == type(uint256).max) {
        // Underlying vault is effectively uncapped: propagate this instead of converting
        return type(uint256).max;
    }

    return _convertToShares(maxAssets, Math.Rounding.Floor);
}
```

**Lido:** Fixed in commit [`af57eb5`](https://github.com/lidofinance/defi-interface/commit/af57eb5e85911976b76318d9a527319812fb3130)

**Cyfrin:** Verified. Suggested fix implemented.


### Non-compliant events emitted on vault deposits and withdrawals

**Description:** `Vault` emits custom `Deposited` and `Withdrawn` events in `Vault::deposit`/`mint` and `withdraw`/`redeem`, while [EIP-4626](https://eips.ethereum.org/EIPS/eip-4626#events) specifies standard `Deposit` and `Withdraw` event names.

**Impact:** The implementation is non-conformant at the event level and may break tooling or integrations that rely on the canonical ERC-4626 events for indexing or accounting.

**Recommended Mitigation:** Emit standard `Deposit` and `Withdraw` events with the exact EIP-4626 signatures instead of the custom `Deposited` / `Withdrawn`.

**Lido:** Fixed in commit [`52217ad`](https://github.com/lidofinance/defi-interface/commit/52217ad4ad48f0f8fc8534e78ad1032af66c4152)

**Cyfrin:** Verified. Correct EIP-4626 events are not emitted.


### Griefing attack on depositors by manipulating the exchange rate during `recoveryMode` via a donation of `TARGET_VAULT`s shares in between `emergencyMode` and `recoveryMode`

**Description:** During the activation of the recovery mode is executed a call to harvest fees, which, in the scenario that it detects any profit since the last update to `lastTotalAssets` would mint more shares.
But, given the design of the system, where once the `recoveryMode` is enabled:
- It is no longer possible to withdraw from the TARGET_VAULT
- Harvesting fees consider the LidoVault's holdings on the TARGET_VAULT as part of the totalAssets, despite any leftover TARGET_VAULT's shares being no redeemable from that point onwards.

The exchange rate for the vault once the recoveryMode kicks in is based on the actual balance of underlyingToken on the LidoVault and the totalSupply at the moment of the recovery mode activation.

That setup allows for a griefing attack where the execution to activate the recovery mode is front-run, and TARGET_VAULT's shares are donated into the LidoVault. This donation will effectively increase the totalAssets, tricking the system into thinking that there are profits to charge fees on, as such, minting new shares, which effectively dilutes the exchange rate compared to the actual underlyingTokens on the LidoVault's balance.
```solidity
    function activateRecovery() external virtual onlyRole(EMERGENCY_ROLE) nonReentrant {
        if (recoveryMode) revert RecoveryModeAlreadyActive();
        if (!emergencyMode) revert EmergencyModeNotActive();

        //@audit => The donation of TARGET_VAULT shares causes more shares to be minted
        _harvestFees();

        uint256 actualBalance = IERC20(asset()).balanceOf(address(this));
        if (actualBalance == 0) revert InvalidRecoveryAssets(actualBalance);

        uint256 supply = totalSupply();
       ...

        recoveryAssets = actualBalance;
        recoverySupply = supply;
        recoveryMode = true;

        emit RecoveryModeActivated(actualBalance, supply, protocolBalance, implicitLoss);
    }

    function convertToAssets(uint256 shares) public view virtual override returns (uint256) {
        //@audit => exchange rate during recovery mode no longer considers the TARGET_VAULT's shares worth in underlying token.
        if (recoveryMode) {
            return shares.mulDiv(recoveryAssets, recoverySupply, Math.Rounding.Floor);
        }
        return super.convertToAssets(shares);
    }
```

**Impact:** The recovery exchange rate can be manipulated, effectively causing depositors to recover fewer tokens than they could've otherwise gotten.

Given that this grief attack requires the "attacker" to incur a loss, the probability is low; nevertheless, the impact is considerable, given that depositors would incur a loss of assets.

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Vault} from "src/Vault.sol";
import "./ERC4626AdapterTestBase.sol";

contract ERC4626AdapterPoCs is ERC4626AdapterTestBase {

    function test_PoC_manipulateShareRatioOnRecoveryMode() public {
        //@audit-info => The mitigation would be to swap `_harvestFees()` to `emergencyWithdraw()` and add a function to allow Governance withdrawing from vault once recoveryMode is enabled!
        uint256 depositAmount = 100e6;
        vault.setRewardFee(2000);

        vm.prank(alice);
        vault.deposit(depositAmount, alice);

        vault.emergencyWithdraw();
        assertEq(vault.totalAssets(),depositAmount);

        uint256 aliceAssetsDuringEmergency = vault.convertToAssets(vault.balanceOf(alice));
        assertEq(aliceAssetsDuringEmergency, depositAmount);

        uint256 snapshot = vm.snapshot();
        {
            //@audit-info => A donation to the LidoVault of TARGET_VAULT's shares
            vm.startPrank(bob);
            usdc.approve(address(targetVault), depositAmount);
            targetVault.deposit(depositAmount, address(vault));
            vm.stopPrank();

            vault.activateRecovery();
            assertEq(depositAmount, vault.recoveryAssets());

            //@audit => Manipulation -> depositor gets less assets that could've otherwise got
            uint256 aliceAssetsOnRecoveryMode = vault.convertToAssets(vault.balanceOf(alice));
            assertTrue(aliceAssetsDuringEmergency > aliceAssetsOnRecoveryMode);

            emit log_named_uint("aliceAssetsDuringEmergency: ", aliceAssetsDuringEmergency);
            emit log_named_uint("aliceAssetsOnRecoveryMode: ", aliceAssetsOnRecoveryMode);
        }

        vm.revertTo(snapshot);

        vault.activateRecovery();

        //@audit => No manipulation -> depositor gets the correct exchange rate during recoveryMode
        uint256 aliceAssetsOnRecoveryMode = vault.convertToAssets(vault.balanceOf(alice));
        assertEq(aliceAssetsOnRecoveryMode, aliceAssetsDuringEmergency);
    }
}
```

**Recommended Mitigation:**
1. Consider harvesting the fees during the emergency withdrawal process, rather than during the activation of recovery mode.
2. Consider allowing the `ERC4626Adapter::recoverERC20` function to sweep TARGET_VAULT's leftover tokens once the `recoveryMode` is enabled.

This is a more defensive strategy to protect users' funds by prioritizing the preservation of the expected exchange rate based on the actual underlyingTokens on the LidoVault and deferring the potential gains in fees as a secondary action by sweeping any leftover TARGET_VAULT's shares.

**Lido**
Fixed in commit [4fd0eb7](https://github.com/lidofinance/defi-interface/commit/4fd0eb7207f607179bf470c77877baafd79dfd53) and [ee29862](https://github.com/lidofinance/defi-interface/commit/ee298626d62e4d18f44b10a5cd6cbcbd3cae7188)

**Cyfrin:** Verified. `_harvestFees` is now called during the activation of the `emergencyMode`. Any leftover `TARGET_VAULT` shares can now be recovered by governance when `recoveryMode` has been enabled via the `recoverERC20`.


### `EmergencyVault::activateRecovery` can be DoS by a reverting `TARGET_VAULT` calls

**Description:** `EmergencyVault::activateRecovery` does external calls to the `TARGET_VAULT` through `_harvestFees()` (which in turn calls `totalAssets()` then `_getProtocolBalance()`) and `_getProtocolBalance()` directly. `_getProtocolBalance()` performs external view calls to `TARGET_VAULT.balanceOf(address(this))` and `TARGET_VAULT.convertToAssets(...)`, which can revert if the target vault is compromised/upgradeable/misbehaving. As a result the recovery activation path can be DoSed by a reverting target vault, even when the adapter already holds recoverable assets locally.

**Impact:** In an incident where `TARGET_VAULT` becomes untrusted and its view functions revert, the vault may be unable activate `recoveryMode`. This can lock any assets already recovered to the vault contract, since users cannot redeem under the recovery flow until `recoveryMode` is set.

**Recommended Mitigation:** Refactor `activateRecovery()` to avoid relying on external target vault calls that can revert in incident scenarios. Remove `_getProtocolBalance()` from `activateRecovery()` (it’s only for event info) and let the fee harvesting be done manually after calls to `emergencyWithdraw` (if the `emergencyMode` restriction is removed or limited to only `EMERGENCY_ROLE`). Alternatively, add `_harvestFees()` at the end of `emergencyWithdraw()`.

**Lido:** Fixed in commit [`ee29862`](https://github.com/lidofinance/defi-interface/commit/ee298626d62e4d18f44b10a5cd6cbcbd3cae7188)

**Cyfrin:** Verified. `_harvestFees()` moved to `emergencyWithdraw()` and a `try/catch` added around the call to `_getProtocolBalance`.


### `ERC4626Adapter::maxMint` doesn't consider pending fees to be harvested which leads to under-calculating the real shares that can be minted

**Description:** The ERC4626Adapter::maxMint function computes the maximum quantity of shares that the Vault may mint by converting the maximum depositable assets in the underlying TARGET_VAULT into corresponding vault shares. However, this conversion process does not account for any pending fees.

As a consequence, the returned share amount underestimates the actual maximum mintable shares on the Vault. Specifically, upon harvesting the pending fees, additional shares are minted, thereby increasing the total supply and the effective conversion rate from assets to shares. This results in a post-harvest scenario where a greater number of shares can be minted for the same quantity of deposited assets than what `maxMint` initially indicates.

**Impact:** `maxMint` won't accurately report the actual maximum number of shares that can be minted.

**Proof of Concept:** Add the next test to `ERC4626Adapter.MaxDeposit.t.sol` test file
```solidity
    function test_PoC_MaxMint_DoesNotConsiderPendingYield() public {
        uint256 yield = 50_00e6;
        targetVault.setLiquidityCap(500_000e6);

        _seedVaults(yield);

        //@audit-info => Vault has pending yield

        uint256 snapshot = vm.snapshot();
            uint256 maxDeposit = vault.maxDeposit(alice);
            vm.prank(alice);
            vault.deposit(maxDeposit, alice);
            assertEq(vault.maxDeposit(alice), 0);
            assertEq(vault.maxMint(alice), 0);
        vm.revertTo(snapshot);

        //@audit-info => Given that Vault has pending yield, maxMint() is not accurate and will mint less shares than the actual maxMint post harvesting fees
        uint256 maxMintShares = vault.maxMint(alice);
        vm.prank(alice);
        vault.mint(maxMintShares, alice);
        assertGt(vault.maxDeposit(alice), 0);
        assertGt(vault.maxMint(alice), 0);

        //@audit-info => After attempting to mint the maxShares reported by the vault (and fees have been harvested during the mint), a second mint is possible when it shouldn't be because the previous mint was supposed to mint the max
        maxMintShares = vault.maxMint(alice);
        vm.prank(alice);
        vault.mint(maxMintShares, alice);
        assertEq(vault.maxDeposit(alice), 0);
        assertEq(vault.maxMint(alice), 0);
    }

    function _seedVaults(uint256 yield) internal {
        vm.prank(alice);
        vault.deposit(100_000e6, alice);

        vm.startPrank(bob);
        usdc.approve(address(targetVault), 100_000e6);
        targetVault.deposit(100_000e6, bob);
        vault.deposit(100_000e6, alice);
        vm.stopPrank();

        // mint yield to targetVault
        usdc.mint(address(targetVault), yield);
    }

```

**Recommended Mitigation:** Consider calculating the amount of shares by taking into account the pending fees to be harvested, similar to how the `previewMint` and `previewDeposit` functions do.

**Lido:** Fixed in commit [fc15b10](https://github.com/lidofinance/defi-interface/commit/fc15b104d3859955ed341e2785059e2806c6aa36).

**Cyfrin:** Verified. `maxMint` calls `previewDeposit` forwarding the `maxAssets` that can be deposited on the `TARGET_VAULT`. `previewDeposit` correctly accounts for any pending fees, meaning the calculated number of shares for the `maxAssets` correctly represents the actual maximum shares that can be minted post-harvesting pending fees.

\clearpage
## Informational


### Use named mappings to explicitly denote the purpose of keys and values

**Description:** Use named mappings to explicitly denote the purpose of keys and values:
```solidity
RewardDistributor.sol
52:    mapping(address => bool) private recipientExists;
```

**Lido:** Fixed in commit [4898c26](https://github.com/lidofinance/defi-interface/commit/4898c26cd0abc8426ad9e2220a8d7cac487ab9b8).

**Cyfrin:** Verified.


### In Solidity don't initialize to default values

**Description:** In Solidity don't initialize to default values:
```solidity
RewardDistributor.sol
143:        uint256 totalBps = 0;
145:        for (uint256 i = 0; i < recipients_.length; i++) {
230:        for (uint256 i = 0; i < recipientsLength; i++) {
```

**Lido:** Fixed in commit [4898c26](https://github.com/lidofinance/defi-interface/commit/4898c26cd0abc8426ad9e2220a8d7cac487ab9b8) for `totalBps`.

**Cyfrin:** Verified.


### `Vault::decimals` does not reflect correct decimals when `OFFSET` is used

**Description:** [`Vault::decimals`](https://github.com/lidofinance/defi-interface/blob/99fd2b2c64c345a3c14b023dca4cb6393ffce5aa/src/Vault.sol#L543-L545) simply returns the asset decimals:
```solidity
function decimals() public view virtual override(ERC20, ERC4626) returns (uint8) {
    return IERC20Metadata(asset()).decimals();
}
```
This is different to the OpenZeppelin [ERC4626 implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC4626.sol#L129-L131), where they account for any decimal offset:
```solidity
function decimals() public view virtual override(IERC20Metadata, ERC20) returns (uint8) {
    return _underlyingDecimals + _decimalsOffset();
}
```

**Impact:** Although the issue will not cause any calculation errors it will cause the exchange rate and share tokens to look strange.

**Recommended Mitigation:** Consider replicating the OpenZeppelin implementation and adding the `OFFSET` to the decimals:
```diff
- return IERC20Metadata(asset()).decimals();
+ return IERC20Metadata(asset()).decimals(); + OFFSET;
```

**Lido:** FIxed in commit [`9ce9c0a`](https://github.com/lidofinance/defi-interface/commit/9ce9c0a5bef423933ec357ab3900d899069f2107)

**Cyfrin:** Verified. `OFFSET` is now added to the decimals.


### `EmergencyVault::activateRecovery` NatSpec references wrong event name

**Description:** The NatSpec for  `EmergencyVault::activateRecovery` states that it emits `RecoveryActivated`:
```solidity
*      Emits RecoveryActivated(actualBalance, totalSupply, protocolBalance, implicitLoss)
```
While it actually emits: `RecoveryModeActivated`
```solidity
emit RecoveryModeActivated(actualBalance, supply, protocolBalance, implicitLoss);
```
Consider changing the NatSpec to refer the correct event name.

**Lido:** Fixed in commit [`3d89267`](https://github.com/lidofinance/defi-interface/commit/3d89267ee409eb0857abb9302dcc42337429e4f9)

**Cyfrin:** Verified.


### `nonReentrant` is not the first modifier

**Description:** `EmergencyVault::emergencyWithdraw` and `EmergencyVault::activateRecovery` place `nonReentrant` as the second modifier rather than first. To protect against reentrancy in other modifiers, the `nonReentrant` modifier should be the first modifier in the list of modifiers.

**Lido:** Fixed in commit [`3d89267`](https://github.com/lidofinance/defi-interface/commit/3d89267ee409eb0857abb9302dcc42337429e4f9)

**Cyfrin:** Verified.


### Not including `_decimalsOffset` when calculating the fee shares

**Description:** Formulas converting assets to shares across the codebase utilize the virtual supply to prevent rate manipulation. However, when calculating the number of shares to be minted for accrued fees, the conversion formula does not call `_calculateFeeShares()` and omits `_decimalsOffset()` when calculating the fee shares.

Add the next PoC to `ERC4626Adapter.Fees.t.sol`.

```solidity
    function test_PoC_InflateRatioViaFees() public {
        vm.prank(alice);
        uint256 alice_receivedShares = vault.deposit(1, alice);

        emit log_named_uint("totalAssets", vault.totalAssets());
        emit log_named_uint("totalSupply", vault.totalSupply());

        emit log_named_uint("assets per wei of share", vault.convertToAssets(alice_receivedShares));

        usdc.mint(address(targetVault), 1_000e18); //
        vault.harvestFees();

        emit log_named_uint("totalSupply", vault.totalSupply());
        emit log_named_uint("assets per wei of share", vault.convertToAssets(alice_receivedShares));

        vm.prank(bob);
        uint256 bob_receivedShares = vault.deposit(100e18, bob);

        uint256 bobAssetsBeforeRedeem = usdc.balanceOf(bob);

        vm.prank(bob);
        vault.redeem(bob_receivedShares, bob, bob);

        uint256 bobAssetsAfterRedeem = usdc.balanceOf(bob);

        emit log_named_uint("bob assets withdrawn", bobAssetsAfterRedeem
         - bobAssetsBeforeRedeem);
        assertTrue(bobAssetsAfterRedeem - bobAssetsBeforeRedeem > 99e18);

        // @audit //
        // With current formula, bob withdraws: 99999880924647933225 [9.999e19])

        // With formula using _decimalsOffset(): val: 99999803787934739453 [9.999e19])

        // @audit => Difference is neglegible for the required amount to donate to inflate the ratio //

    }

```

**Lido:** Acknowledged. Precision loss doesn't exceed one wei, no impact to the value received by the fee receiver.

\clearpage
## Gas Optimization


### Use `ReentrancyGuardTransient` for faster `nonReentrant` modifiers

**Description:** Use [ReentrancyGuardTransient](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) for faster `nonReentrant` modifiers:
```solidity
Vault.sol
10:import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
32:abstract contract Vault is ERC4626, ERC20Permit, AccessControl, ReentrancyGuard, Pausable {
```

**Lido:** Fixed in commit [3d89267](https://github.com/lidofinance/defi-interface/commit/3d89267ee409eb0857abb9302dcc42337429e4f9).

**Cyfrin:** Verified.


### Use more efficient method of reading recipient account and basis points

**Description:** In `RewardsDistributor::getRecipient` reduce gas cost 791 -> 716 by:
```solidity
function getRecipient(uint256 index) external view returns (address account, uint256 basisPoints) {
    Recipient storage recipient = recipients[index];
    (account, basisPoints) = (recipient.account, recipient.basisPoints);
}
```

In `RewardsDistributor::distribute` reduce gas costs 59254 -> 59172 by:
```solidity
for (uint256 i = 0; i < recipientsLength; i++) {
    Recipient storage recipient = recipients[i];
    (address account, uint256 basisPoints) = (recipient.account, recipient.basisPoints);

    uint256 amount = (balance * basisPoints) / MAX_BASIS_POINTS;

    if (amount > 0) {
        tokenContract.safeTransfer(account, amount);
        emit RecipientPaid(account, token, amount);
    }

    totalAmount += amount;
}
```

**Proof of Concept:** To verify in `RewardDistributor.t.sol`:
1) In function `test_ReplaceRecipient_Succeeds` add snapshot after last call:
```diff
function test_ReplaceRecipient_Succeeds() public {
    RewardDistributor distributor = _deployDefaultDistributor();
    address newRecipient = makeAddr("newRecipient");

    (address oldRecipient,) = distributor.getRecipient(0);

    vm.expectEmit(true, true, true, true);
    emit RewardDistributor.RecipientReplaced(0, oldRecipient, newRecipient);

    vm.prank(admin);
    distributor.replaceRecipient(0, newRecipient);

    (address updatedRecipient,) = distributor.getRecipient(0);
+   vm.snapshotGasLastCall("RewardsDistributor", "getRecipient");
    assertEq(updatedRecipient, newRecipient);
}
```

2) In function `test_Distribute_DistributesAccordingToBps` add snapshot after first call:
```diff
function test_Distribute_DistributesAccordingToBps() public {
    RewardDistributor distributor = _deployDefaultDistributor();
    uint256 amount = 10_000e6;
    asset.mint(address(distributor), amount);

    address[] memory recipients = new address[](2);
    recipients[0] = recipientA;
    recipients[1] = recipientB;

    uint256[] memory expectedAmounts = new uint256[](2);
    expectedAmounts[0] = (amount * 4_000) / MAX_BPS;
    expectedAmounts[1] = (amount * 6_000) / MAX_BPS;

    vm.recordLogs();
    vm.prank(admin);
    distributor.distribute(address(asset));
+   vm.snapshotGasLastCall("RewardsDistributor", "distribute");

    Vm.Log[] memory entries = vm.getRecordedLogs();
    // snip remaining code...
```

3) Run the test contract: `forge test --match-contract RewardDistributorTest`

4) Examine the gas snapshots: `more snapshots/RewardsDistributor.json`

5) After making the recommended changes, execute 3) and 4) again

**Lido:** Fixed in commit [4898c26](https://github.com/lidofinance/defi-interface/commit/4898c26cd0abc8426ad9e2220a8d7cac487ab9b8).

**Cyfrin:** Verified.

\clearpage