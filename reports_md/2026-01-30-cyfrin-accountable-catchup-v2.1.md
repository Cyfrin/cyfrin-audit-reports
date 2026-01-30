**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

**Assisting Auditors**



---

# Findings
## Low Risk


### `managerSplit` can be misconfigured above `BASIS_POINTS`

**Description:** The `FeeManager` allows setting the manager fee (e.g., `managerSplit`) without enforcing that it is `<= BASIS_POINTS` (100%). As a result, the manager fee can be set to an invalid value greater than `BASIS_POINTS`.

**Impact:** If `managerSplit > BASIS_POINTS` is set, fee calculations can become nonsensical or revert. In particular, any logic that derives a complementary “protocol split” as `BASIS_POINTS - managerSplit` may underflow and revert, potentially breaking fee settlement paths and causing operational failures (e.g., inability to collect or distribute fees).

**Recommended Mitigation:** Add an explicit bounds check when setting the manager fee in `_requireValidFeeStructure`:
```
  function _requireValidFeeStructure(FeeStructure memory fees) private pure {
+    if (fees.managerSplit > BASIS_POINTS) revert InvalidManagerSplit();
      if (fees.performanceFee > MAX_PERFORMANCE_FEE) revert InvalidPerformanceFee();
      if (fees.establishmentFee > MAX_ESTABLISHMENT_FEE) revert InvalidEstablishmentFee();
  }
```


**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified. `managerSplit` now validated to be below `BASIS_POINTS`.


### `AccountableOpenTerm::accrueInterest` does not refresh delinquency status

**Description:** `AccountableOpenTerm::accrueInterest` only calls `_accrueInterest()` and does not call `_updateDelinquentStatus()`, unlike `updateLateStatus()` which accrues and then updates delinquency state.

**Impact:** Third parties (keepers/UIs) can advance interest accrual while leaving delinquency state stale until a later call updates it. This can cause temporary inconsistencies in delinquency tracking (e.g., delayed/incorrect `delinquencyStartTime` updates and penalty application timing), which may affect monitoring/automation that relies on delinquency status.

**Recommended Mitigation:** Either (a) have `accrueInterest()` also call `_updateDelinquentStatus()`, (b) document that keepers should call `updateLateStatus()` when delinquency correctness is required, or (c) remove it and just use `updateLateStatus()` (or vice versa).

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified. `accrueInterest` now calls `_updateDelinquentStatus()`


### `AccountableAsyncRedeemVault::maxDeposit` / `maxMint` can be stale due to non-accrued `scaleFactor` breaking EIP-4626 compliancy

**Description:** `AccountableOpenTerm.maxDeposit()` computes remaining capacity using `principalAssets = debtShares * _scaleFactor`, but `_scaleFactor` is only updated when `_accrueInterest()` is executed. Since `maxDeposit()` is a view and does not “virtually accrue,” it can return a value based on an outdated `_scaleFactor`. The vault’s `maxMint()` / `maxDeposit()` inherit this staleness and may report limits that don’t match the current economic state.

**Impact:** Integrators/users may see `maxDeposit` / `maxMint` values that are too high, then have `deposit()` / `mint()` unexpectedly revert once the state-changing path accrues interest and enforces capacity. This is non-compliant with [EIP-4626](https://eips.ethereum.org/EIPS/eip-4626) expectations which states:
> MUST return the maximum amount of assets `deposit` would allow to be deposited for `receiver` and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted

**Recommended Mitigation:** Use “virtual accrual” in view functions: compute an up-to-date scale factor for the current timestamp (without writing state) and use it in `maxDeposit` and share-price/limit calculations backing `maxMint` (and related previews/limits). Possibly by splitting `_accrueInterest()` into a view and a state changing part.


**Accountable:** Fixed in commit [`5891946`](https://github.com/Accountable-Protocol/credit-vaults-internal/pull/54/commits/58919467552c7993b115bc1c30c7f8520de2c2c3)

**Cyfrin:** Verified. `_accrueInterest` now split into `_previewAccruedInterest` which is called from `_accrueInterest`.


### Protocol fees are not auto-collected before treasury address update

**Description:** Function `setTreasury` can be used to update the existing `treasury` to a new address. However, before updating the treasury address, any existing protocol fees are not auto-collected to the current treasury. While this is not a major issue, it could be problematic if the treasury is updated to a dead or invalid address intentionally or unintentionally.

```solidity
function withdrawProtocolFee(address asset) public nonReentrant onlyTreasury {
        uint256 amount = protocolFees[asset];
        if (amount > 0) {
            protocolFees[asset] = 0;
            IERC20(asset).safeTransfer(treasury, amount);

            emit Withdraw(asset, address(0), treasury, amount);
        }
    }

function setTreasury(address treasury_) public onlyOwner {
        if (treasury_ == address(0)) revert ZeroAddress();
        address oldTreasury = treasury;
        treasury = treasury_;
        emit TreasurySet(oldTreasury, treasury_);
    }
```

**Recommended Mitigation:** Consider collecting any protocol fees before updating the treasury address. Additionally, consider adding a two-step transfer when changing the treasury address.

**Accountable:** Acknowledged. There is no case when we will update the treasury to a dead address such that uncollected fees get lost.


### Incorrect delinquency status update due to missing interest accrual

**Description:** In the AccountableOpenTerm contract, the `_scaleFactor`  is updated in function `_accrueInterest`. This means that any operation relying on an accurate `_scaleFactor` should accrue interest beforehand.

```solidity
_scaleFactor += baseInterest + delinquencyFee;
```

Function `_calculateRequiredLiquidity` uses the `_scaleFactor` variable to calculate the required reserves, which is then used by function `_isDelinquent` to determine whether the loan is delinquent or not.  The boolean value returned from `_isDelinquent` is used by function `_updateDelinquentStatus` to determine the latest status of loan payments. Function `setReserveThreshold` calls `_updateDelinquentStatus` however it does not accrue interest. Due to this, the delinquency status is updated based on a stale `_scaleFactor` value.

```solidity
function setReserveThreshold(uint256 threshold)
        external
        override(AccountableStrategy, IAccountableStrategy)
        onlyManager
    {
        if (threshold > BASIS_POINTS) revert ThresholdTooHigh();
        _loan.reserveThreshold = threshold;

        _updateDelinquentStatus();

        emit ReserveThresholdSet(threshold);
    }
```

**Recommended Mitigation:** Consider accruing interest before updating the delinquency status.

**Accountable:** Fixed in commit [`809813f`](https://github.com/Accountable-Protocol/credit-vaults-internal/pull/54/commits/809813f5d12c28977c93075d459a38e5fa0014ae)

**Cyfrin:** Verified. `_accrueInterest` now called before `_updateDelinquentStatus` when the loan is ongoing.

\clearpage
## Informational


### Unused errors

**Description:** Consider using or removing the unused errors in `src/constants/Errors.sol`:

- [Line: 40](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L40)

	```solidity
	error CancelDepositRequestFailed();
	```

- [Line: 67](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L67)

	```solidity
	error NoCancelRedeemRequest();
	```

- [Line: 79](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L79)

	```solidity
	error NoQueueRequests();
	```

- [Line: 113](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L113)

	```solidity
	error InterestAlreadyClaimed();
	```

- [Line: 122](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L122)

	```solidity
	error InvalidVaultManager();
	```

- [Line: 156](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/constants/Errors.sol#L156)

	```solidity
	error ZeroAmount();
	```

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### Unused state variable

**Description:** The constant `FeeManager._protocolSplit` is unused. Consider removing or using this unused variable.

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### Unused imports

**Description:** Redundant import statements in `src/strategies/AccountableStrategy.sol`. Consider removing them:


- [Line: 6](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/strategies/AccountableStrategy.sol#L6)

	```solidity
	import {RewardsType} from "../interfaces/IRewards.sol";
	```

- [Line: 8](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/strategies/AccountableStrategy.sol#L8)

	```solidity
	import {IRewardsFactory} from "../interfaces/IRewardsFactory.sol";
	```

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### State change without event

**Description:** There is important state changes in this function but no event is emitted. Consider emitting an event to enable offchain indexers to track the changes.

* [AccountableOpenTerm::setProposer](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/strategies/AccountableOpenTerm.sol#L197-L199)

**Accoutable:**
Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### Prepayment fee is unbounded

**Description:** The prepayment fee can be set without an upper bound. Governance could set an extreme prepayment fee, making early repayment prohibitively expensive or potentially causing unexpected behavior/reverts. This creates user trust and predictability risk.

Consider adding a cap when setting the prepayment fee (e.g., `if(prepaymentFee > MAX_PREPAYMENT_FEE)`).

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### `_updateDelinquentStatus` called in both branches in `AccountableOpenTerm::repay`

**Description:** `_updateDelinquentStatus` is called in both branches in `AccountableOpenTerm::repay`
```solidity
if (_loan.outstandingPrincipal == 0) {
    loanState = LoanState.Repaid;
    _updateDelinquentStatus();
} else {
    _updateDelinquentStatus();
}
```
Consider simplifying it to:
```solidity
if (_loan.outstandingPrincipal == 0) {
    loanState = LoanState.Repaid;
}
_updateDelinquentStatus();
```

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### `AccountableOpenTerm`-functions incorrectly under `View Functions` header

**Description:** The functions `AccountableOpenTerm::updateLateStatus`, `accrueInterest`, and `processAvailableWithdrawals` are all located under the header:
```solidity
// ========================================================================== //
//                          View Functions                                    //
// ========================================================================== //
```
Consider moving them from there as they are not view functions.

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### State variables can be immutable

**Description:** State variables that are only changed in the constructor should be declared immutable to save gas. Add the `immutable` attribute to state variables that are only changed in the constructor

- [AccountableVault.sol#L44](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/vault/AccountableVault.sol#L44):

	```solidity
	    IStrategyVaultHooks public strategy;
	```

- [AccountableVault.sol#L47](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/277d154d9faf9164c6cd32d66cf38f12a73c5087/src/vault/AccountableVault.sol#L47)

	```solidity
	    uint256 public precision;
	```

 - [AccessBase.sol#15](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/0cee6b3d1713a5f5fd21412d89d3cb4da7537a16/src/access/AccessBase.sol#L15)

	```solidity
	    PermissionLevel public permissionLevel;
	```

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### Unnecessary `FeeManager::managerSplit` call

**Description:** In `FeeManager::_collectFeeSplit`, if it enters the `else` branch, there's two calls to `managerSplit(strategy)` done:
```solidity
if (managerSplit(strategy) == 0) {
    managerFee = 0;
    protocolFee = amount;
} else {
    managerFee = _split(amount, managerSplit(strategy));
    protocolFee = amount - managerFee;
}
```
This is unnecessary, consider doing just one call:
```solidity
uint256 managerSplit = managerSplit(strategy);
if (managerSplit == 0) {
    managerFee = 0;
    protocolFee = amount;
} else {
    managerFee = _split(amount, managerSplit);
    protocolFee = amount - managerFee;
}
```

**Accountable:** Fixed in commit [`fa6f74c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fa6f74c23dc359176ed2dbb9faba4f0b4077e2b2)

**Cyfrin:** Verified.


### Unnecessary check in `AccountableAsyncRedeemVault::maxRedeem`

**Description:** The last check in `AccountableAsyncRedeemVault::maxRedeem` is unnecessary as if it's zero, zero will just be returned
```solidity
function maxRedeem(address controller) public view override returns (uint256 maxShares) {
    VaultState storage state = _vaultStates[controller];
    maxShares = state.redeemShares;
    if (maxShares == 0) return 0; // @audit-issue GAS unnecessary
}
```

**Accountable:** Fixed in commit [`78cd5c7`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/78cd5c7350cfc60367a2a7d7553c3e766d7064fc)

**Cyfrin:** Verified.


### `AccountableAsyncRedeemVault::maxWithdraw` can be optimized when `state.redeemShares == 0`

**Description:** In `AccountableAsyncRedeemVault::maxWithdraw` the `redeemShares` can be done first and save a read if `redeemShares` is zero:
```diff
  function maxWithdraw(address controller) public view override returns (uint256 maxAssets) {
      VaultState storage state = _vaultStates[controller];
+     if (state.redeemShares == 0) return 0;
      maxAssets = state.maxWithdraw;
-     if (state.redeemShares == 0) return 0;
  }
```

**Accountable:** Fixed in commit [`78cd5c7`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/78cd5c7350cfc60367a2a7d7553c3e766d7064fc)

**Cyfrin:** Verified.


### Emit events early to save gas

**Description:** Function `setTreasury` creates a memory variable `oldTreasury` which is used in the emission of event `TreasurySet`. However, creating this memory variable is not required if the event is emitted before the state change.


`FeeManager.sol`
```solidity
function setTreasury(address treasury_) public onlyOwner {
        if (treasury_ == address(0)) revert ZeroAddress();
        address oldTreasury = treasury;
        treasury = treasury_;
        emit TreasurySet(oldTreasury, treasury_);
    }
```

`AccountableOpenTerm`
```solidity
function approveInterestRateChange() external onlyManager {
        uint256 pendingRate_ = pendingInterestRate;

        _accrueInterest();

        _loan.interestRate = pendingRate_;
        delete pendingInterestRate;

        _updateInterestParams();

        emit InterestRateApproved(pendingRate_);
    }
```

`AccountableStrategy.sol`
```solidity
function acceptBorrowerRole() external virtual {
        if (msg.sender != pendingBorrower) revert InvalidPendingBorrower();

        address oldBorrower = borrower;
        borrower = msg.sender;
        pendingBorrower = address(0);

        emit BorrowerChanged(oldBorrower, msg.sender);
    }
```

**Recommended Mitigation:** Consider updating the functions in the following manner
````solidity
function setTreasury(address treasury_) public onlyOwner {
        if (treasury_ == address(0)) revert ZeroAddress();
        emit TreasurySet(treasury, treasury_);
        treasury = treasury_;
    }
````

**Accountable:** Fixed in commit [`78cd5c7`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/78cd5c7350cfc60367a2a7d7553c3e766d7064fc)

**Cyfrin:** Verified.

\clearpage