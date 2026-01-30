**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

---

# Findings
## Medium Risk


### `AtomicBatcher` uses placeholder ERC-7201 namespace

**Description:** `AtomicBatcher` derives its nonce storage slot from an ERC-7201 namespace constant that is still a placeholder:

```solidity
/// @notice ERC-7201 namespace for nonce storage
string private constant _NAMESPACE = "<namespace>";
```

If this is not replaced with a unique, project-specific namespace, different contracts/tools that reuse the same placeholder can end up writing to the same storage slot.

**Impact:** Nonce storage can collide with other code using the same placeholder namespace, potentially breaking replay protection (unexpected nonce changes), causing failed executions, or enabling cross-application interference when running in shared storage contexts (e.g., EIP-7702 style execution in an EOA’s storage).

**Recommended Mitigation:** Replace `"<namespace>"` with a unique, stable identifier (e.g., `"accountable.atomicbatcher.nonce.v1"`), and treat it as immutable across upgrades/deployments.

**Accountable:** Fixed in commit [`2247cec`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/2247cec53a91ccc8f2d47d6d976d99308d676b85)

**Cyfrin:** Verified. Namespace is now `accountable.atomicbatcher.nonce.v1`.


### Immediate withdrawals possible even when NAV is stale through `AccountableYield::accrueAndProcess`

**Description:** When NAV is stale, `AccountableYield::onRequestRedeem` disables “instant fulfill” by forcing requests into the queue:

```solidity
canFulfill = liquidity >= assets && !_navIsStale();
```

However, `AccountableYield::accrueAndProcess` is publicly callable and is not gated by `whenNotStale`. It processes the withdrawal queue immediately:

```solidity
function accrueAndProcess() external ... {
    _accrueFees();
    usedAssets = _processAvailableWithdrawals();
    _updateDelinquentStatus();
}
```

As a result, a user can queue a redeem request and then immediately call `accrueAndProcess()` (potentially in the same transaction via a router/multicall) to have the request processed even while NAV is stale.

**Impact:** This undermines the intended protection of “no immediate withdrawals when NAV is stale.” Withdrawals can still be processed at the last known (stale) NAV-derived price, which may be economically incorrect during periods when NAV updates are unavailable.

**Recommended Mitigation:** Gate queue processing while NAV is stale (e.g., add `whenNotStale` to `accrueAndProcess()` and any other public entrypoints that trigger `_processAvailableWithdrawals()`, like `AccountableYield::repay`)


**Accountable:** Fixed in commit [`ddcbfa5`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/ddcbfa5faac90cc6e6ff3c1f1a0e754951363ba1)

**Cyfrin:** Verified. Both `repay` and `accrueAndProcess` now have the `whenNotStale` modifier.


### `AccountableYield::repay` vs `publishRate` transaction ordering can undo repayment accounting

**Description:** `AccountableYield::repay` reduces `deployedAssets` based on the repaid amount:

```solidity
uint256 deployed = deployedAssets;
deployedAssets -= Math.min(remaining, deployed);
```

But `publishRate(uint256 newDeployedValue)` later overwrites `deployedAssets` with the DVN-reported value:

```solidity
uint256 oldValue = deployedAssets;
deployedAssets = newDeployedValue;
```

Because these are independent transactions, ordering matters. If `repay()` executes first (reducing `deployedAssets`), and then `publishRate()` executes with a value that still reflects the pre-repayment NAV, the overwrite can effectively “reverse” the accounting effect of the borrower’s repayment by setting `deployedAssets` back up.

**Impact:** Transaction ordering can materially change outcomes. In congested conditions, a DVN update can effectively “undo” the accounting effect of a borrower repayment by resetting `deployedAssets` upward, impacting reported NAV/share price, fee accrual, and whether the loan can reach a fully repaid state. This risk is amplified when the NAV grace period is configured to be short (default is 24h, but it can be as low as 1h), increasing the frequency/urgency of updates and making collisions more likely. It is further increased by the DVNPublisher’s async publish/execute flow, since there is an inherent delay between when a value is proposed and when it is executed on-chain, making it more likely that repayments occur in between.

**Recommended Mitigation:** `DVNPublisher.PublishRequest` already includes a `timestamp`, pass that through to `AccountableYield.publishRate` (e.g., `publishRate(uint256 value, uint256 measuredAt)`) and store `lastNavMeasuredAt`. Reject/ignore updates with `measuredAt <= lastNavMeasuredAt` and/or `measuredAt < lastRepayTime` so a stale snapshot cannot overwrite newer repayment accounting.


**Accountable:** Fixed in commits [`5b6498a`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/5b6498af30c542f93118e5d05206b70aeeb3b17f), [`6756c97`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/6756c97db4aa2595045576bada90ba0705bb2f03) and [`06b6c4c`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/06b6c4c0238f8241a440861a578f1e6a701ff4b8)

**Cyfrin:** Verified. Code now compares to the timestamp of the measurement, if the value is a mean of the two middle measurements, the older timestamp is used.


### Cancelling a later-batch request in `AccountableOpenTerm` can delay earlier withdrawals

**Description:** The Vault allows cancelling any queued redeem request via `AccountableAsyncRedeemVault::cancelRedeemRequest(controller, receiver)`, which removes that controller’s queued shares.

To keep batching metadata in sync, the Vault calls the strategy hook `AccountableOpenTerm::onCancelRedeemRequest(...)`. However, the strategy reduces batch totals starting from `pendingBatch` (oldest batch) and walks forward, without knowing which batch the cancelled request actually belonged to:

```solidity
uint256 batch = pendingBatch;
...
while (shares > 0 && batch <= maxBatch && maxIter > 0) {
    uint256 batchShares = _withdrawalBatches[batch].totalShares;
    if (batchShares >= shares) {
        _withdrawalBatches[batch].totalShares -= shares;
        break;
    } else {
        _withdrawalBatches[batch].totalShares = 0;
        shares -= batchShares;
        batch++;
    }
    --maxIter;
}
```

If a user cancels a request that was created in a later batch, this logic subtracts the cancelled shares from the earliest batch’s `totalShares`. That can make `pendingBatch.totalShares` smaller than the actual FIFO-queued shares at the head of the Vault queue.

During processing, the strategy limits processing by `min(queueMaxShares, batch.totalShares)` and stops once it reaches the next (not-yet-expired) batch.

**Impact:** Queued withdrawals that should be eligible (earlier batch already expired and liquidity exists) can be artificially delayed until a later batch expires, because the strategy advances to a future batch while some earlier-batch shares still remain in the queue head. This can degrade withdrawal liveness and create unexpected waiting periods for lenders.

**Proof of Concept:** Add the following test to `test/strategies/AccountableOpenTermBatch.t.sol`:
```solidity
function test_cancelFromFutureBatch_canDelayEarlierBatchProcessing() public {
    _setupLoanWithBatches(4 days, 7 days);

    // Three lenders deposit, borrower borrows everything (no immediate liquidity).
    vm.prank(alice);
    usdcOpenTermVault.deposit(USDC_AMOUNT, alice, alice);
    vm.prank(bob);
    usdcOpenTermVault.deposit(USDC_AMOUNT, bob, bob);
    vm.prank(charlie);
    usdcOpenTermVault.deposit(USDC_AMOUNT, charlie, charlie);

    vm.prank(borrower);
    usdcOpenTermLoan.borrow(USDC_AMOUNT * 3);

    // Batch 0: Alice + Bob queue withdrawals in the first interval.
    uint256 aliceB0 = USDC_AMOUNT / 2;
    uint256 bobB0 = USDC_AMOUNT / 3;
    vm.prank(alice);
    usdcOpenTermVault.requestRedeem(aliceB0, alice, alice);
    vm.prank(bob);
    usdcOpenTermVault.requestRedeem(bobB0, bob, bob);

    WithdrawalBatch memory b0Before = usdcOpenTermLoan.withdrawalBatches(0);
    assertEq(b0Before.totalShares, aliceB0 + bobB0, "batch0 tracks Alice+Bob");

    // Move to next interval -> Batch 1 is created by Charlie.
    vm.warp(block.timestamp + 7 days);
    uint256 charlieB1 = USDC_AMOUNT / 5;
    vm.prank(charlie);
    usdcOpenTermVault.requestRedeem(charlieB1, charlie, charlie);

    assertEq(usdcOpenTermLoan.currentBatch(), 1, "batch1 created");

    WithdrawalBatch memory b1Before = usdcOpenTermLoan.withdrawalBatches(1);
    assertEq(b1Before.totalShares, charlieB1, "batch1 tracks Charlie");

    // Charlie cancels. Strategy reduces starting from pendingBatch (0),
    // even though Charlie's request was created in batch 1.
    vm.prank(charlie);
    usdcOpenTermVault.cancelRedeemRequest(charlie, charlie);

    WithdrawalBatch memory b0AfterCancel = usdcOpenTermLoan.withdrawalBatches(0);
    WithdrawalBatch memory b1AfterCancel = usdcOpenTermLoan.withdrawalBatches(1);

    // NOTE: This shows the core accounting problem: batch0 shrinks (even though Alice+Bob are still queued),
    // and batch1 stays unchanged (even though Charlie is no longer queued).
    assertEq(
        b0AfterCancel.totalShares,
        (aliceB0 + bobB0) - charlieB1,
        "batch0 reduced by Charlie cancel (mis-attributed)"
    );
    assertEq(b1AfterCancel.totalShares, charlieB1, "batch1 unchanged (stale metadata)");

    // Queue now contains only Alice+Bob.
    assertEq(usdcOpenTermVault.totalQueuedShares(), aliceB0 + bobB0, "queue excludes cancelled Charlie");

    // We are already past batch0 expiry (4d) and before batch1 expiry (7d+4d).
    assertGe(block.timestamp, b0Before.expiry, "past batch0 expiry");
    assertLt(block.timestamp, b1Before.expiry, "before batch1 expiry");

    // Borrower repays enough liquidity to process ALL queued shares (Alice+Bob).
    // Due to understated batch0.totalShares, processing only does (alice+bob-charlie) shares and then stops at batch1.
    usdc.mint(borrower, USDC_AMOUNT * 3);
    vm.startPrank(borrower);
    usdc.approve(address(usdcOpenTermLoan), type(uint256).max);
    usdcOpenTermLoan.repay(USDC_AMOUNT * 3);
    vm.stopPrank();

    // Remaining queue shares == the "missing" amount (charlieB1), even though Charlie cancelled.
    // These are actually part of Alice/Bob's earlier requests that got pushed into the next batch window.
    assertEq(
        usdcOpenTermVault.totalQueuedShares(),
        charlieB1,
        "earlier requests rolled into next batch window (delayed until batch1 expiry)"
    );
    assertEq(usdcOpenTermLoan.pendingBatch(), 1, "pendingBatch advanced to batch1 and now blocks further processing");

    // Alice requested 500e11 shares and should be fully claimable:
    uint256 aliceClaimableShares = usdcOpenTermVault.maxRedeem(alice);
    assertEq(aliceClaimableShares, 500_000_000_000, "Alice fully claimable in batch0");

    // Bob requested 333333333333 shares, but only part of it was processed due to the bug.
    // From the trace: bob got RedeemClaimable(..., shares: 133333333333)
    uint256 bobClaimableShares = usdcOpenTermVault.maxRedeem(bob);
    assertEq(bobClaimableShares, 133_333_333_333, "Bob only partially claimable in batch0 (bug)");

    // The remainder should still be queued (333333333333 - 133333333333 = 200000000000)
    assertEq(usdcOpenTermVault.totalQueuedShares(), 200_000_000_000, "Remaining Bob shares still queued");

    // Demonstrate users can redeem what is currently claimable:
    vm.prank(alice);
    usdcOpenTermVault.redeem(aliceClaimableShares, alice, alice);

    vm.prank(bob);
    usdcOpenTermVault.redeem(bobClaimableShares, bob, bob);

    // After redeeming claimable amounts, queue should still contain Bob's remainder
    assertEq(usdcOpenTermVault.totalQueuedShares(), 200_000_000_000, "Bob remainder still queued after partial redeem");

    // Remaining shares can't become claimable until batch1 expires.
    // Warp past batch1 expiry and trigger processing again.
    WithdrawalBatch memory batch1 = usdcOpenTermLoan.withdrawalBatches(1);
    vm.warp(batch1.expiry + 1);
    usdcOpenTermLoan.processAvailableWithdrawals();

    // Now Bob's remainder should become claimable:
    uint256 bobClaimableAfter = usdcOpenTermVault.maxRedeem(bob);
    assertEq(bobClaimableAfter, 200_000_000_000, "Bob remainder becomes claimable only after batch1 expiry");

    // And Bob can finally redeem the rest:
    vm.prank(bob);
    usdcOpenTermVault.redeem(bobClaimableAfter, bob, bob);

    assertEq(usdcOpenTermVault.totalQueuedShares(), 0, "Queue fully drained after delayed processing");
}
```

**Recommended Mitigation:** Ensure cancellations decrement the correct batch. Track the batch id for each redeem request (or controller’s pending request) at queue time and subtract from that batch on cancel.

**Accountable:** Fixed in commit [`ec9ec5e`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/ec9ec5e489c4b02c4b5cee6debced79bcf7c3e3b)

**Cyfrin:** Verified. Cancellation now subtracts shares from the correct batch(es) via per-controller batch tracking.


### Missing modifiers on `YieldStrategyFactory.createYieldStrategy` can lead to deployment of unverified strategies

**Description:** Function `createYieldStrategy` enables permissionless deployment of `AccountableYield` strategies. However, during the deployment process, the function does not:
1. Verify the paused status using the `whenNotPaused` modifier
2. Verify the transaction authentication data using `onlyVerified` (if a signer is set)
3. Verify whether the asset is whitelisted using `onlyWhitelistedAsset`

**Proof of Concept:** As we can observe, other strategy factories such as `OpenTermFactory` and `FixedTermFactory` implement this verification.

[`YieldStrategyFactory.sol`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/main2/src/factory/YieldStrategyFactory.sol)
```solidity
function createYieldStrategy(YieldFactoryParams memory params)
        external
        returns (address strategyProxy, address vault)
    {
```

[`OpenTermFactory.sol`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/main2/src/factory/OpenTermFactory.sol)
```solidity
function createOpenTermLoan(OpenTermFactoryParams memory params)
        external
        whenNotPaused
        onlyVerified
        onlyWhitelistedAsset(params.asset)
        returns (address strategyProxy, address vault)
    {
```

[`FixedTermFactory.sol`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/main2/src/factory/FixedTermFactory.sol)
```solidity
function createFixedTermLoan(FixedTermFactoryParams memory params)
        external
        whenNotPaused
        onlyVerified
        onlyWhitelistedAsset(params.asset)
        returns (address strategyProxy, address vault)
    {
```

**Recommended Mitigation:** Consider applying the `whenNotPaused`, `onlyVerified` and `onlyWhitelistedAsset` modifiers on the function `createYieldStrategy`.

**Accountable:** Fixed in commit [`f8d4a3f`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/f8d4a3fbb19ea995cc27a7a8fb4a9896129247e7)

**Cyfrin:** Verified. Modifiers now applied.

\clearpage
## Low Risk


### `AccountableOpenTerm` rate publish/rollback does not refresh delinquency status

**Description:** In `AccountableOpenTerm`, the new rate update flows (`publishRate()` / `rollbackRate()`) call `_accrueInterest()` and then update core economic parameters (e.g., `interestRate`, scale-factor–related state, and accrual timestamps). However, these functions do not call `_updateDelinquentStatus()` after mutating the loan’s economic state.

**Impact:** Delinquency status can remain stale until a later interaction triggers `_updateDelinquentStatus()`. This can cause temporary inconsistencies in delinquency tracking and penalty timing, and may affect monitoring/automation that relies on delinquency state immediately after rate changes.

**Recommended Mitigation:** Call `_updateDelinquentStatus()` at the end of both `publishRate()` and `rollbackRate()` so delinquency state always reflects the latest rate/accrual state.

**Accountable:** Fixed in commits [`39c60c7`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/39c60c7c2ceaf4a7de87013aeb27acabbff088b5) and [`f350a8d`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/f350a8dc1769f9401b4d1ef62d3748540545ca4d).

**Cyfrin:** Verified. `_updateDelinquentStatus()` now called from both `publishRate()` and `rollbackRate()`.


### Fee structure updates can trigger accrual after loan has ended

**Description:** In both `AccountableYield` and `AccountableOpenTerm`, `onFeeStructureChange()` only checks `if (_loan.startTime != 0)` before accruing:

```solidity
if (_loan.startTime != 0) {
    _accrueFees();     // AccountableYield
    // or _accrueInterest(); // AccountableOpenTerm
}
```

Since `startTime` is set once and not reset when a loan is `Repaid` or in default, fee-structure changes can still trigger accrual logic after the loan is no longer ongoing.

**Impact:** In `AccountableYield`, management fees are time-based; if no accrual happens after repayment, a later fee-structure update can “catch up” and mint a large amount of fee shares for the elapsed time since the last fee accrual, diluting holders unexpectedly. In `AccountableOpenTerm`, the hook can similarly update interest bookkeeping (or potentially revert if accrual assumes an ongoing loan). However this requires the protocol to update the fee structure after the loan has ended, which is unlikely.

**Recommended Mitigation:** Gate `onFeeStructureChange()` by loan state (e.g., only accrue when the loan is ongoing), rather than `startTime != 0`. For example, require `loanState == Ongoing*` before calling `_accrueFees()` / `_accrueInterest()`, or use `_requireLoanOngoing()` similar to other calls.

**Accountable:** Fixed in commit [`5f8fd3`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/5f8fd343287101ae69b6bc767e9459a9543526ab)

**Cyfrin:** Verified. Check changed to `loanState == LoanState.OngoingDynamic`.


### Delinquency status update in `AccountableOpenTerm` hooks uses pre-queue state

**Description:** The Vault calls strategy hooks (e.g., `AccountableStrategy::onRequestRedeem`, `onDeposit`, `onMint`) before the Vault updates the state that these actions affect (queue totals for redeem requests, and `totalAssets`/liquidity for deposits/mints).

However, `AccountableOpenTerm` updates delinquency status inside the hooks.

As a result, delinquency calculations that depend on Vault-side values (e.g., queued shares / available liquidity derived from `totalAssets`, `reservedLiquidity`, `totalQueuedShares`, etc.) can be evaluated using a pre-action snapshot:

* `AccountableOpenTerm::onRequestRedeem`: for queued (non-instant) requests, the request is only enqueued after the hook returns, so delinquency is checked before the new queued shares are reflected.
* `AccountableOpenTerm::onDeposit` / `onMint`: the hook runs before the Vault receives assets / updates totals, so delinquency can be checked before the new liquidity from the deposit/mint is reflected.

**Impact:** Delinquency status may lag by one interaction (or until another status update is triggered). For example:

* a queued redeem may not immediately mark the loan delinquent, and/or
* a deposit/mint that would restore liquidity may not immediately clear delinquency.

This is primarily a correctness / timing issue unless delinquency gating is expected to be exact within the same transaction.

**Recommended Mitigation:** Consider passing the changes in shares and assets to the delinquency calculation so that it can account for the added/removed shares/assets. Or use the same pattern as `Vault::cancelRedeemRequest` where the. `strategy.updateLateStatus()` hook is called at the end.

**Accountable:** Fixed in commit [`5f815ee`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/5f815ee49e6f88585befd3061abf2bc081ae3d8c)

**Cyfrin:** Verified. Delinquency update removed from the strategy hooks and each vault function now calls `trategy.updateLateStatus`.


### Increasing `AccountableOpenTerm.loan.withdrawalPeriod` from `0` can cause withdrawals to become stuck

**Description:** When `LoanTerms.withdrawalPeriod == 0`, `AccountableOpenTerm::_createOrAddWithdrawalBatch` returns immediately and does not create/update any batch metadata.

However, users can still end up queued (e.g., insufficient liquidity → `requestRedeem()` is not immediately fulfillable). If terms are later updated to a non-zero `withdrawalPeriod`, `_processAvailableWithdrawals()` switches into “batch mode” and processes shares bounded by `WithdrawalBatch.totalShares`, meaning queued shares that were accumulated while `withdrawalPeriod == 0` may have no corresponding batch totals to drive processing.

**Impact:** Queued withdrawals created while `withdrawalPeriod == 0` can become stuck or perceived as stuck after switching to `withdrawalPeriod > 0`, because batch-mode processing depends on batch metadata that was never created for those queued shares. This can lead to delayed withdrawals and operational term toggling to recover.

**Recommended mitigation:**
Either don't allow increases of the `withdrawalPeriod` when there's still queued shares or:

When transitioning from `withdrawalPeriod == 0` → `withdrawalPeriod > 0`, ensure queued withdrawals are materialized into batch metadata. Options include:

* In `acceptTerms()` (or the terms-activation path), if the *new* `withdrawalPeriod > 0` and `totalQueuedShares() > 0`, **initialize/seed** the current batch with `totalShares = totalQueuedShares()`, with appropriate `startTime/expiry` alignment.
* Alternatively, adjust `_processAvailableWithdrawals()` so that if `withdrawalPeriod > 0` but batch metadata is missing/empty while the queue is non-empty, it either:

  * falls back to the “zero-period” processing path once, or
  * auto-creates a batch reflecting the current queued amount before processing.

**Accountable:** Fixed in commit [`10396d4`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/10396d49bbdd747cf76e961091a2c869b1194a27)

**Cyfrin:** Verified. `acceptTerms` now reverts if the withdrawal period is increased from 0 and there's still queued shares.


### Function `execute` overwrites seenSigner values irrespective of request age

**Description:** Function `publish` allows authenticated signers to publish requests for the current batch in process. By design, signers are allowed publish multiple requests in a batch, with each request having its own distinct timestamp.

When an authorized executor calls the `execute` function, this for loop will overwrite the signer's first request value with the second request value (assuming only two requests have been published). However, it is possible that the `request.timestamp` of the second request is older than the timestamp of the first request. In this case, the function uses the seen signer's relatively older request value instead of the latest, which can lead to slightly inaccurate publish rates.
```solidity
          for (uint256 j = 0; j < uniqueSigners; ++j) {
                if (requests[i].signer == seenSigners[j]) {
                    // Update to latest value from this signer
                    values[j] = requests[i].value;
                    isDuplicate = true;
                    break;
                }
            }
```

**Proof of Concept:** Let's take a simple example:
 - Alice submits two requests - R1 and R2
 - The timestamps of R1 and R2 are 20 and 10 respectively.
 - During execution, R1's value is overwritten by R2's value even though R2 is a relatively older request.

**Recommended Mitigation:** If a signer has multiple requests in a batch, ensure the value is not overwritten unless the timestamp of the request is fresher.

**Accountable:** Fixed in commit [`141ca3b`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/141ca3b7025ddb9316eb55b0399ed9999daf60aa)

**Cyfrin:** Verified. Only updates if timestamp is later.


### `lastTotalAssets` stores stale value due to update before penalty accrual

**Description:** Across the `AccountableYield` strategy, variable `lastTotalAssets` stores the value returned from function `_totalAssets`. Since `accruedPenalties` is a factor taken into consideration  in `_totalAssets`, the code should ensure penalties are accrued before updating the `lastTotalAssets`.
```solidity
/// @dev Total assets managed = vault assets + deployed assets + accrued penalties
    function _totalAssets(address vault_) internal view returns (uint256) {
        return IAccountableVault(vault_).totalAssets() + deployedAssets + accruedPenalties;
    }
```

However, in all instances across the `AccountableYield` contract, `lastTotalAssets` does not accrue penalties before.

[`AccountableYield.borrow`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L282)

[`AccountableYield.onDeposit`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L367)

[`AccountableYield.onMint`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L392)

[`AccountableYield._accrueFees/_accruedFeeShares`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L463)

Similar instances also exist when `_totalAssets` is accessed directly before accruing penalties:

[`AccountableYield._accruedFeeShares`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L515)  -  In this particular instance, function `_accruedFeeShares` also returns this `newTotalAssets` value to function `_sharePrice`, which leads to a stale share price.

[`AccountableYield._calculateRequiredLiquidity`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L620)


**Recommended Mitigation:** Consider accruing penalties before updating `lastTotalAssets` as well as before directly accessing the value returned from function `_totalAssets`.

**Accountable:** Fixed in commit [`97f8b1a`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/97f8b1aed9e52e67c788892e97346d9b83bcacb1)

**Cyfrin:** Verified. Penalties now accrued in the above stated cases.

\clearpage
## Informational


### `AccountableOpenTerm` manual interest rate proposal is unbounded

**Description:** The manual interest rate path can propose/queue an interest rate without enforcing an upper bound. By contrast, the DVN publishing path enforces a cap when applying rates:

* DVN flow: `AccountableOpenTerm::publishRate(uint256 newRate)` checks `newRate` against `MAX_PUBLISH_RATE` before applying it.
* Manual flow: `AccountableOpenTerm::proposeInterestRate(...)` queues a pending rate, and `approveInterestRateChange()` applies it, but the queued rate is not capped.

**Recommended Mitigation:** Add the same bounds check in `proposeInterestRate(...)` (preferred), so invalid/extreme rates cannot be queued.

**Accountable:** Fixed in commit [`4a737a6`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/4a737a63a92cff754a0e712ce5f8124f601829c1)

**Cyfrin:** Verified.


### `AccountableYield::setNavGracePeriod` uses `Unauthorized` error for invalid input

**Description:** `AccountableYield.setNavGracePeriod()` reverts with `Unauthorized()` when `period < MIN_NAV_GRACE_PERIOD`, even though this is an input validation failure rather than an access control issue.

Consider using a dedicated error for invalid parameters (e.g., `InvalidNavGracePeriod()`), or reuse a generic input-validation error.

**Accountable:** Fixed in commit [`d051169`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/d05116991e253ad2e348604c3ca50770ee554607)

**Cyfrin:** Verified.


### `DVNPublisher::publish` does not enforce a maximum age for updates

**Description:** `DVNPublisher::publish` validates that `request.timestamp` is not in the future, but it does not enforce a maximum age (i.e., it does not reject requests that are already stale at submission time). Staleness is only handled later during `DVNPublisher::execute`.

Consider adding a check in `publish()` to reject already-stale requests, e.g. `require(request.timestamp + maxStaleness >= block.timestamp)`, to reduce clutter in `_pendingRequests`.

**Accountable:** Fixed in commit [`5afc5fd`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/5afc5fd48b7ee0e2649c46e6c1dd261f9e00de49)

**Cyfrin:** Verified.


### Consider reverting in `publishedDataByBatchId` for invalid batch IDs

**Description:** Function `publishedDataByBatchId` returns published data however it does not ensure the `id` parameter is less than the `currentBatchId`. Due to this, the function will still return an empty PublishedData struct for invalid IDs. While this poses no immediate risk, it is safer to reject invalid ID values to avoid issues in the future with integrations.

```solidity
function publishedDataByBatchId(uint256 id) external view returns (PublishedData memory) {
        return _publishedData[id];
    }
```

**Recommended Mitigation:** Consider reverting if `id` is greater than or equal to the `currentBatchId`.

**Accountable:** Fixed in commit [`d721846`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/d721846475486afd796fd6fa159e95143e7d4b98)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Precompute `baseSlot` in `AtomicBatcher::_getNonceSlot`

**Description:** `AtomicBatcher::_getNonceSlot` computes the ERC-7201 namespace base slot at runtime each time it is called:
```solidity
function _getNonceSlot(address account) private pure returns (bytes32) {
    bytes32 namespaceHash = keccak256(bytes(_NAMESPACE));
    bytes32 baseSlot = keccak256(abi.encode(uint256(namespaceHash) - 1)) & ~bytes32(uint256(0xff)); // @audit can be pre-computed
    return keccak256(abi.encode(account, uint256(baseSlot)));
}
```
Since the namespace is constant, the derived `baseSlot` can be precomputed and stored as a `bytes32` constant:
```solidity
// keccak256(abi.encode(uint256(keccak256("accountable.atomicbatcher.nonce.v1")) - 1)) & ~bytes32(uint256(0xff))
bytes32 private constant NONCE_BASE_SLOT = 0xa68386067ee8ee669468449acf0ad3e2ae0d09e4d99f78eaa329c6681c06b900;
```

**Accountable:** Fixed in commit [`fce94d2`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/fce94d2c67b3937ea1106f66138dbff7118227d8)

**Cyfrin:** Verified.


### Precompute `callTypeHash` in `AtomicBatcher::_hashCallArray`

**Description:** `AtomicBatcher::_hashCallArray` recomputes the call type hash (the `keccak256` of the call-type string / type description) on every invocation:
```solidity
function _hashCallArray(Call[] calldata calls) private pure returns (bytes32) {
    bytes32 callTypeHash = keccak256("Call(address target,uint256 value,bytes data)");
```
Since this value is constant, it can be precomputed once as a `bytes32` constant.

Consider defining `bytes32 private constant _CALL_TYPEHASH = keccak256("...");` and use `_CALL_TYPEHASH` in `_hashCallArray()` instead of computing it each time.

**Accountable:** Fixed in commit [`6a63afe`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/6a63afee9fca88312fad4c208797b4b27b2f9b28)

**Cyfrin:** Verified.


### Reuse `fm` Instead of re-instantiating `IFeeManager` in `AccountableOpenTerm::_mintFeeShares`

**Description:** In `AccountableOpenTerm::_mintFeeShares`, the treasury address is fetched by re-casting `feeManager`:

```solidity
address treasury_ = IFeeManager(feeManager).treasury();
```

However, the `IFeeManager fm` interface is already passed into the function, so this extra cast/load is unnecessary:

```solidity
address treasury_ = fm.treasury();
```

**Accountable:** Fixed in commit [`5e13285`](http://github.com/Accountable-Protocol/credit-vaults-internal/commit/5e132854c6ce3230350daf12feea77bb4a7e8586)

**Cyfrin:** Verified.


### Reuse `aum_` in `_accrueFeeShares` to avoid recomputing debt

**Description:** In `AccountableOpenTerm::_accrueFeeShares`, debt is recomputed as:

```solidity
uint256 debt = _loan.outstandingPrincipal.mulDiv(scaleFactor_, PRECISION);
```

However, the same debt/AUM value is already computed in `_accrueInterest()` and passed down as `aum_`. This makes the multiplication/division redundant and also keeps `scaleFactor_` as an unnecessary parameter.

Consider using `aum_` directly in `_accrueFeeShares` (e.g., `uint256 debt = aum_;`) and remove the `scaleFactor_` parameter from the function signature and call sites to save gas and simplify the code.

**Accountable:** Fixed in commit [`f350a8d`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/f350a8dc1769f9401b4d1ef62d3748540545ca4d)

**Cyfrin:** Verified.


### Only update `deployedAssets` when `remaining > 0` in `AccountableYield::repay`

**Description:** In `AccountableYield::repay`, `deployedAssets` is read and conditionally reduced unconditionally:

```solidity
uint256 deployed = deployedAssets;
deployedAssets -= Math.min(remaining, deployed);
```

However, this has no effect when `remaining == 0` (since `Math.min(0, deployed) == 0`). You already branch on `remaining > 0` immediately after for principal reduction:
```solidity
// Reduce outstanding principal
if (remaining > 0) {
     uint256 outstanding = _loan.outstandingPrincipal;
    _loan.outstandingPrincipal = outstanding > remaining ? outstanding - remaining : 0;
}
```

Consider reducing `deployedAssets` inside the existing `if (remaining > 0)` block to avoid an unnecessary storage read and write when there is no remaining repayment amount:
```solidity
// Reduce deployedAssets and outstanding principal
if (remaining > 0) {
    // Assets are moving from external → vault
    uint256 deployed = deployedAssets;
    deployedAssets -= Math.min(remaining, deployed);

     uint256 outstanding = _loan.outstandingPrincipal;
    _loan.outstandingPrincipal = outstanding > remaining ? outstanding - remaining : 0;
}
```

**Accountable:** Fixed in commit [`eec49ac`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/eec49ac44951a81228d0cd759b429f0ba13c5772)

**Cyfrin:** Verified.


### Consider removing redundant zero address check from `createYieldStrategy`

**Description:** Function `createYieldStrategy` deploys instances of the `AccountableYield` strategy using the `Create2` library's `deploy` function. After deployment, it ensures the `strategyProxy` is not `address(0)`.
```solidity
strategyProxy = Create2.deploy(0, params.salt, strategyProxyBytecode);
if (strategyProxy == address(0)) revert FailedDeployment(ZERO_LOAN_PROXY_ADDRESS);
```

However, this is not required since the `deploy` function already checks for this and reverts early.

```solidity
function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address addr) {
        if (address(this).balance < amount) {
            revert Create2InsufficientBalance(address(this).balance, amount);
        }
        if (bytecode.length == 0) {
            revert Create2EmptyBytecode();
        }
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        if (addr == address(0)) {
            revert Create2FailedDeployment();
        }
    }
```

**Recommended Mitigation:** Consider removing the zero address check

```diff
- if (strategyProxy == address(0)) revert FailedDeployment(ZERO_LOAN_PROXY_ADDRESS);
```

**Accountable:** Fixed in commit [`ec3b6b9`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/ec3b6b9d9e8c4bcaae7b913c1f00a2c6a11a4636)

**Cyfrin:** Verified. Optimization also done for Open- and FixedTerm factories.


### Consider emitting events early to save gas

**Description:** Function `DVNPublisherFactory.setImplementation` can emit event `ImplementationSet` before the `implementation` state change to avoid creating and accessing an unnecessary memory variable.

[`DVNPublisherFactory.sol#L34`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/factory/DVNPublisherFactory.sol#L34)
```solidity
function setImplementation(address implementation_) external onlyOwner {
        address oldImplementation = implementation;
        implementation = implementation_;
        emit ImplementationSet(oldImplementation, implementation_);
    }
```

Similar instances exist in the `DVNPublisher` and `AccountableYield` contract:

[`DVNPublisher.sol#L125`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/publisher/DVNPublisher.sol#L125)
```solidity
function setThreshold(uint256 threshold_) external onlyManager {
        if (threshold_ > MAX_THRESHOLD || threshold_ == 0) revert InvalidThreshold();

        uint256 oldThreshold = threshold;
        threshold = threshold_;

        emit ThresholdSet(oldThreshold, threshold_);
    }
```

[`DVNPublisher.sol#L153`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/publisher/DVNPublisher.sol#L153)

```solidity
function setMaxStaleness(uint256 maxStaleness_) external onlyManager {
        if (maxStaleness_ == 0) revert ZeroValue();

        uint256 oldMaxStaleness = maxStaleness;
        maxStaleness = maxStaleness_;

        emit MaxStalenessSet(oldMaxStaleness, maxStaleness_);
    }
```

[`DVNPublisher.sol#L163`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/publisher/DVNPublisher.sol#L163)
```solidity
    /// @inheritdoc IDVNPublisher
    function setMaxDeviation(uint256 maxDeviation_) external onlyManager {
        uint256 oldMaxDeviation = maxDeviation;
        maxDeviation = maxDeviation_;

        emit MaxDeviationSet(oldMaxDeviation, maxDeviation_);
    }
```

[`AccountableYield.sol#L226`](https://github.com/Accountable-Protocol/credit-vaults-internal/blob/ba1c7754f891dd6d28a4b47d1989c8b03073abe2/src/strategies/AccountableYield.sol#L226)
```solidity
function setNavGracePeriod(uint256 period) external onlyManager {
        if (period < MIN_NAV_GRACE_PERIOD) revert Unauthorized();

        uint256 oldPeriod = navGracePeriod;
        navGracePeriod = period;

        emit NavGracePeriodSet(oldPeriod, period);
    }
```

**Recommended Mitigation:** Consider emitting the event early before the state update.

**Accountable:** Fixed in commit [`1a7ce24`](https://github.com/Accountable-Protocol/credit-vaults-internal/commit/1a7ce24cd0a84ed56386c8061778480640ab8364)

**Cyfrin:** Verified.

\clearpage