**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

---

# Findings
## Medium Risk


### Owner can rescue the vault’s own share tokens

**Description:** [`SherpaVault::rescueTokens`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/blob/50eb8ad6ee048a767f7ed2265404c59592c098b7/contracts/SherpaVault.sol#L730-L740) forbids rescuing the wrapper token:
```solidity
// CRITICAL: Cannot rescue the wrapper token (user funds)
// This protects deposited SherpaUSD from being withdrawn by owner
if (token == stableWrapper) revert CannotRescueWrapperToken();
```

But it allows rescuing the vault’s own share token (`token == address(vault)`). Since[ newly minted shares](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/blob/50eb8ad6ee048a767f7ed2265404c59592c098b7/contracts/SherpaVault.sol#L543-L544) for pending deposits are held in vault custody at `address(this)` and user redemptions transfer from this balance:
```solidity
accountingSupply += mintShares;
_mint(address(this), mintShares);
```

The owner can transfer out custody shares via `rescueTokens`, reducing the vault-held pool that backs users’ pending/redemption balances.

**Impact:** An owner (or compromised owner key) can move vault-custodied shares away from `address(this)`, which they then can withdraw for the underlying deposit.

**Recommended Mitigation:** Disallow rescuing the vault’s own share token:

```diff
- if (token == stableWrapper) revert CannotRescueWrapperToken();
+ if (token == stableWrapper || token == address(this)) revert CannotRescueWrapperToken();
```

**Sherpa:** Fixed in commit [`1a634e0`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/1a634e0331968ea5a73f38a62ef824da9376ab52)

**Cyfrin:** Verified. The vault token is now also prevented from being rescued.


### Owner can chain admin calls for same-block drains

**Description:** The protocol’s admin controls let the owner chain privileged calls across the vault and wrapper in a single transaction:

* **Vault path:** Call `SherpaVault::setStableWrapper` to switch which token is protected from rescue. Then immediately call `SherpaVault::rescueTokens` to withdraw any balance of the old wrapper from the vault.
* **Wrapper operator path:** Call `SherpaUSD::setOperator`, then (as operator) use `SherpaUSD::transferAsset` to move USDC out of the wrapper.
* **Wrapper keeper path:** Call `SherpaUSD::setKeeper`, then use `SherpaUSD::depositToVault` to pull USDC from users who left approvals, mint SherpaUSD to the keeper, and extract value via the `transferAsset` path above.

All of these are owner-only and have no built-in delay, so they can be executed together in the same block.

**Impact:** Even though the code comments stress limiting owner power, the owner (or a compromised key) can immediately redirect custody and move funds with no user warning or reaction time. This creates a trust gap between stated intent and actual authority.

**Recommended Mitigation:** * Add a delay (at least one withdrawal epoch) to `SherpaVault.setStableWrapper`, `SherpaVault.rescueTokens`, `SherpaUSD.setOperator`, `SherpaUSD.setKeeper`, and consider delaying `SherpaUSD.transferAsset`.
* Make `SherpaVault.stableWrapper`, `SherpaUSD.keeper` immutable.
* Use a timelock (e.g., OpenZeppelin [`TimelockController`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/TimelockController.sol)) with a user-protective delay so people can withdraw or reduce approvals before changes take effect.

**Sherpa:**
> Vault path: Call SherpaVault::setStableWrapper to switch which token is protected from rescue. Then immediately call SherpaVault::rescueTokens to withdraw any balance of the old wrapper from the vault.
> Wrapper keeper path: Call SherpaUSD::setKeeper, then use SherpaUSD::depositToVault to pull USDC from users who left approvals, mint SherpaUSD to the keeper, and extract value via the transferAsset path above.

We're implementing a pseudo-immutable `stableWrapper` and `keeper` - both will be set once during deployment and cannot be changed after system initialization. This eliminates both attack surfaces while maintaining the deployment flexibility needed to solve the chicken-and-egg deployment problem: vault constructor requires wrapper address, but we can't deploy wrapper until vault exists. We solve this by deploying vault with a temporary wrapper address, then calling `setStableWrapper()` once to set the real wrapper and lock it permanently.

> Wrapper operator path: Call SherpaUSD::setOperator, then (as operator) use SherpaUSD::transferAsset to move USDC out of the wrapper.

Timelocks / delays on `setOperator` and related admin functions would be ineffective given our vault's trust model and architecture. The operator already has manual custody of strategy funds (transferred to fund manager for on and off-chain strategy delegation) and can pause the system at will, meaning any timelock delay could be circumvented by simply pausing withdrawals during the timelock window. The operator must remain changeable for operational flexibility (personnel changes, key rotation) so we cant make it immutable like we did with `keeper` and `setStableWrapper`. The owner role is a 2-of-3 multisig that controls operator selection, so centralization is lessened there as best as we can.

Fixed in commit [`15e2706`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/15e270673d42e02f1e3a08bcba6d1ac61f14010d)

**Cyfrin:** Verified. Both `stableWrapper` and `keeper` now locked after initial assignment which will effectively make them immutable. Operator concern acknowledged.



### Withdrawals can effectively only happen on the primary chain after any yield has accrued

**Description:** During round rolls, yield is only realized on the primary chain in `SherpaVault::_adjustBalanceAndEmit`. This leaves the system in a problematic state if withdrawals happens on another chain.

Imagine the scenario: there's 500 + 500 deposits of SherpaUSD on chain A and B, A being primary. 100 SherpaUSD is added as yield on A. The balance is 500 + 600, global total 1100 giving a share price of 1.1.
Alice, who has half the total shares decides do withdraw on chain B, giving her 550 SherpaUSD (USDC). Since this isn't available on chain B, the protocol needs to rebalance 50 SherpaUSD from A to B.

They do this by calling `SherpaUSD::ownerBurn(50)` on chain A followed by `SherpaUSD::ownerMint(50)` on chain B. This will store 50 in both `approvedTotalStakedAdjustment` and `approvedAccountingAdjustment` on both chains. The latter one being the issue.

Once `SherpaVault::adjustTotalStaked` is called by the operator, the rebalance of SherpaUSD is done, and Alice can effectively withdraw. However, there's no way to clear the state in `approvedAccountingAdjustment` as no shares were ever moved. If `SherpaVault::adjustAccountingSupply` is called, it will corrupt the `accountingSupply` as no shares were ever moved. So the states of `approvedAccountingAdjustment` are effectively permanently corrupted as `consumeAccountingApproval` can only be cleared from the vault.

In addition to this, if `SherpaVault::adjustAccountingSupply` was called on chain A, `accountingSupply` would be decremented and the `accountingSupply` subtraction in function `_unstake()` would underflow on chain A, hence bricking funds.


**Impact:** Withdrawals can only safely happen on the primary chain as soon as any yield is accrued. If yield is withdraw from the secondary chain that will corrupt either `SherpaUSD.approvedAccountingAdjustment` or `SherpaVault.accountingSupply` on both chains.

**Recommended Mitigation:** Consider split approval modes. Introduce explicit asset-only rebalancing (set `approvedTotalStakedAdjustment` without setting `approvedAccountingAdjustment`) and a share-sync mode (set both).

**Sherpa:** Fixed in commit [`34f2092`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/34f2092f8f882005304c8f1a2ad311ed91d9161a)

**Cyfrin:** Verified. Calls to rebalance assets only were added.

\clearpage
## Low Risk


### Misconfigured decimal scale can skew vault accounting

**Description:** The vault’s math assumes the same decimal scale as the wrapped asset (USDC, 6 decimals) and as the `globalPricePerShare` fed by ops. While deployment sets `vaultParams.decimals = 6` and the wrapper enforces USDC’s 6 decimals, a misconfiguration will skew conversions.

**Impact:** Configuring the vault with more than 6 decimals can cause incorrect accounting, and follow-on reverts in rebalancing.

**Recommended Mitigation:** Consider locking the vault decimals to 6, same as `SherpaUSD`.

**Sherpa:** Fixed in commit [`1a634e0`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/1a634e0331968ea5a73f38a62ef824da9376ab52)

**Cyfrin:** Verified. `_vaultParams.decimals` now verified to be 6 in the constructor.


### SherpaUSD does not work with fee-on-transfer tokens

**Description:** The SherpaUSD contract cannot work correctly with fee-on-transfer tokens. An example of such a token is USDT, which is expected to be supported as per comments. Note: Fees are not yet activated on USDT however they can be at any time in the future.

```solidity
        // CRITICAL: SherpaUSD only supports 6-decimal assets (USDC, USDT, etc.)
```

For example:
 - Assume 2% fees are charged by a fee-on-transfer token.
 - Keeper calls function depositToVault with 100e6 as amount.
 - 100 SherpaUSD are minted to the keeper
 - Due to fees charged on transfer, only 98 tokens are received by the contract.
 - This can build up over time and cause late withdrawers to incur a loss as they will be unable to withdraw fully or a partial amount of their tokens.
```solidity
function depositToVault(
    address from,
    uint256 amount
) external nonReentrant onlyKeeper {
    if (amount == 0) revert AmountMustBeGreaterThanZero();

    _mint(keeper, amount);
    depositAmountForEpoch += amount;

    emit DepositToVault(from, amount);

    IERC20(asset).safeTransferFrom(from, address(this), amount);
}
```

**Recommended Mitigation:** Consider adding support for fee-on-transfer tokens. Alternatively consider not supporting such tokens.

**Sherpa:** Fixed on commit [`0b32641`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/0b326416fc7312ee11b279964a947a10b642cc2d)

**Cyfrin:** Verified. Comment changed to explicitly say FOT tokens not supported (including USDT).


### Direct amount assignment in `SherpaUSD::ownerMint`/`ownerBurn` can break accounting for totalStaked and accountingSupply

**Description:** Functions `SherpaUSD::ownerMint` and `ownerBurn` directly assign the amount parameter to mappings `approvedTotalStakedAdjustment` and `approvedAccountingAdjustment`. This will however not work correctly if more tokens are minted or burned to/from the vault before the approvals are consumed.

For example:
 - Operator mints 100 SherpaUSD to SherpaVault.
 - This tracks `approvedTotalStakedAdjustment` and `approvedAccountingAdjustment` as 100 SherpaUSD each
 - Operator performs another mint of 200 tokens before the previous approvals are consumed.
 - Now the issue is that approvedTotalStakedAdjustment and approvedAccountingAdjustment will be overwritten to store 200 SherpaUSD each instead of 300 SherpaUSD.
 - This is clearly incorrect and breaks accounting since old approvals were not consumed yet by the vault.

```solidity
function ownerMint(address to, uint256 amount) external onlyOperator {
    _mint(to, amount);

    // Approve vault to adjust by this amount
    approvedTotalStakedAdjustment[to] = amount;
    approvedAccountingAdjustment[to] = amount;

    emit PermissionedMint(to, amount);
    emit RebalanceApprovalSet(to, amount, amount);
}

/**
 * @notice Operator-level burn for manual rebalancing across chains
 * @param from Address to burn from
 * @param amount Amount to burn
 * @dev Sets approval for vault to adjust totalStaked and accountingSupply
 */
function ownerBurn(address from, uint256 amount) external onlyOperator {
    _burn(from, amount);

    // Approve vault to adjust by this amount
    approvedTotalStakedAdjustment[from] = amount;
    approvedAccountingAdjustment[from] = amount;

    emit PermissionedBurn(from, amount);
    emit RebalanceApprovalSet(from, amount, amount);
}
```

**Recommended Mitigation:** Consider replacing direct amount assignments with the += and -= operators in ownerMint and ownerBurn respectively.

**Sherpa:** Fixed in commit [`1cd0018`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/1cd00183932d086b0fd07d6c34cd3f5aacb2b359)

**Cyfrin:** Verified. Checks to enforce that the approvals have been consumed are added. This prevents any accounting corruption.

\clearpage
## Informational


### `SherpaVault::_rollInternal` price calculation comment and math inconsistent

**Description:** When calculating a new price a script queries all vaults on all chains then passes that to `SherpaVault:: rollToNextRound`. This in turn calls [`SherpaVault::_rollInternal`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/blob/50eb8ad6ee048a767f7ed2265404c59592c098b7/contracts/SherpaVault.sol#L518-L529) where the new price is calculated:
```solidity
// Calculate global price using script-provided totals
// globalBalance must include pending deposits for correct price calculation
uint256 globalBalance = isYieldPositive
    ? globalTotalStaked + globalTotalPending + yield
    : globalTotalStaked + globalTotalPending - yield;

uint256 newPricePerShare = ShareMath.pricePerShare(
    globalShareSupply,
    globalBalance,
    globalTotalPending,
    _vaultParams.decimals
);
```
The code comments state that `globalBalance must include pending deposits` yet `globalBalance` is passed to [`ShareMath:pricePerShare`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/blob/50eb8ad6ee048a767f7ed2265404c59592c098b7/contracts/lib/ShareMath.sol#L66-L77), which immediately subtracts the `pending` amount: (`(totalBalance - pending) / totalSupply`):
```solidity
function pricePerShare(
    uint256 totalSupply,   // @audit-info globalShareSupply
    uint256 totalBalance,  // @audit-info globalBalance
    uint256 pendingAmount, // @audit-info globalTotalPending
    uint256 decimals
) internal pure returns (uint256) {
    uint256 singleShare = 10 ** decimals;
    return
        totalSupply > 0
            ? (singleShare * (totalBalance - pendingAmount)) / totalSupply
            : singleShare;
}
```
The comment in `_rollInternal` is inconsistent with the math applied as the actual price calculation doesn't include the `pendingAmount`.

Consider changing the comment or if the comment is correct, the math.


**Sherpa:** Fixed in commit [`9dbaf27`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/9dbaf277ec7b7349af682aa5d9f6a6ae78151db9)

**Cyfrin:** Verified. Comment was incorrect and is not fixed.


### `SherpaUSD::consumeTotalStakedApproval` and `SherpaUSD::consumeAccountingApproval` callable by anyone

**Description:** In the rebalancing/settlement flow for cross-chain accounting, [`SherpaUSD::consumeTotalStakedApproval`](48a767f7ed2265404c59592c098b7/contracts/SherpaUSD.sol#L282-L291) and [`SherpaUSD::consumeAccountingApproval`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/blob/50eb8ad6ee048a767f7ed2265404c59592c098b7/contracts/SherpaUSD.sol#L293-L302) serve as the “consume/clear” step for one-time approvals set by `SherpaUSD::ownerMint`/`SherpaUSD::ownerBurn`. They are invoked around `SherpaVault::adjustTotalStaked` and `SherpaVault::adjustAccountingSupply` to prevent reuse of an approval after the corresponding adjustment is applied.

Both functions are externally callable and accept a `vault` parameter, but state changes are gated by `if (msg.sender != vault) revert OnlyVaultCanConsume();` and approvals are keyed by the caller address:
```solidity
function consumeTotalStakedApproval(address vault) external {
    // @audit-issue anyone can call by passing their own address as `vault`
    if (msg.sender != vault) revert OnlyVaultCanConsume();
    approvedTotalStakedAdjustment[vault] = 0;
    emit TotalStakedApprovalConsumed(vault);
}
```
Consequently, any address may call the functions, yet the call can only clear its own approval entry, not a vault’s. Behavior is correct and non-exploitable in this design; however, the open callable surface combined with an explicit `vault` parameter can be confusing to integrators and reviewers.

Consider removing the `vault` parameter and only allow the actual vault to call by adding the `onlyKeeper` modifier. This would follow the principle of least privilege and limit the attack surfaces available.

**Sherpa:** Fixed in commit [`c33eb52`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/c33eb5212430b6c4115be9f87950e47540f20522)

**Cyfrin:** Verified. Both functions now have the `vault` parameter removed and the `onlyKeeper` modifier.


### `CCIPReceiver` dependency not necessary

**Description:** `SherpaVault` inherits `CCIPReceiver`, but the protocol’s cross-chain flow uses CCIP burn/mint token pools rather than ad-hoc message passing. Chainlink’s [cross-chain token pattern](https://docs.chain.link/ccip/concepts/cross-chain-token/evm/tokens) on EVM chains does not require a `CCIPReceiver` implementation on the token/vault contract, only pool authorization via `mint/burn` style hooks. Keeping `CCIPReceiver` (and its `_ccipReceive` stub) increases bytecode size, deployment cost, and surface area without delivering any functionality.

Consider removing the inheritance and associated code to simplify the contract, reduce gas/bytecode footprint, and avoid implying a message-bridge dependency that isn’t actually used.

**Sherpa:** Removed in commit [`59974b2`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/59974b29c59e2cc5afce87bbfd87a625bc05a94b)

**Cyfrin:** Verified. `CCIPReceiver` dependency now removed.


### `SherpaVault::redeem` naming ambiguous

**Description:** `SherpaVault` uses ERC-4626-adjacent terminology but different semantics. In ERC-4626, `redeem` means burning shares to withdraw assets. In `SherpaVault`, `redeem` means finalize a prior deposit by moving unredeemed shares into the user’s wallet. This naming can mislead integrators and tooling that assume ERC-4626 behavior.

Consider renaming `redeem` to `finalizeDeposit` / `claimShares` to prevent confusion.

**Sherpa:** Fixed in commit [`8e9ba92`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/8e9ba923e8402b877e16cd1d9a89143acdafe855)

**Cyfrin:** Verified. `claimShares` now used.


### Some SherpaUSD can never be unstaked due to minimumSupply check

**Description:** The `SherpaVault::_unstake` function in SherpaVault includes a check that ensures the total assets staked are never less than minimumSupply and greater than 0. However, it is possible for another user to intentionally or unintentionally block a user from unstaking permanently.

```solidity
// Ensure vault maintains minimum supply (allow full exit to 0)
        if (totalStaked - wrappedTokensToWithdraw < vaultParams.minimumSupply &&
            totalStaked - wrappedTokensToWithdraw > 0) {
            revert MinimumSupplyNotMet();
        }
```

For example:
 - Let's assume `minimumSupply` = 1000 SherpaUSD.
 - Alice deposits 1000 SherpaUSD.
 - Malicious Bob deposits 1 wei SherpaUSD. This is allowed since this if statement in function `_stakeInternal` -  `if (totalWithStakedAmount < _vaultParams.minimumSupply) revert MinimumSupplyNotMet();` checks the total staked supply + pending amount i.e. the totalWithStakedAmount, which is now 1000 SherpaUSD + 1 wei SherpaUSD.
 - Alice now cannot exit the system until Bob clears his withdrawal. This occurs due to the minimumSupply check in the `_unstake` function.
 - Alice can only withdraw 1 wei SherpaUSD while the remaining is permanently locked.

Based on the scripts shared, this issue does not pose a risk currently as `minimumSupply` is expected to be 1 USD.

**Recommended Mitigation:** It is recommended to implement either or both of the following recommendations as a safety measure:
1. Implement a setter function to keep the `minimumSupply` configurable.
2. Add check to ensure all users individually deposit above the minimum supply.

**Sherpa:** Fixed in commit [`720c2c0`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/720c2c053d4e22fcb73a7bda97e4282fc749f5f4)

**Cyfrin:** Verified. A minimum deposit enforced. `minimumSupply` left immutable.


### Consider implementing explicit rounding behaviour instead of default round down

**Description:** All functions in `ShareMath.sol` round down to the nearest integer currently. This can be unfavourable in certain instances for the SherpaVault.

For example, the `ShareMath.pricePerShare` function uses integer division which causes precision loss. Hence it would slightly underestimate the price per share.

```solidity
function pricePerShare(
    uint256 totalSupply,
    uint256 totalBalance,
    uint256 pendingAmount,
    uint256 decimals
) internal pure returns (uint256) {
    uint256 singleShare = 10 ** decimals;
    return
        totalSupply > 0
            ? (singleShare * (totalBalance - pendingAmount)) / totalSupply
            : singleShare;
}
```

**Recommended Mitigation:** It is recommend to perform explicit rounding in addition to adding comments that logically elaborate why the respective rounding direction is appropriate in each instance.

**Sherpa:** Fixed in commit [`61345a1`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/61345a1967311167ec8fe4dba81bb2a21247ea50)

**Cyfrin:** Verified. Documentation about the specific rounding directions added.

\clearpage
## Gas Optimization


### Optimize setters by emitting event before state updates

**Description:** Functions `SherpaUSD::setKeeper`, `SherpaUSD::setOperator`, `SherpaUSD::setAutoTransfer` and `SherpaVault::setDepositsEnabled`, `SherpaVault::setStableWrapper` create an unnecessary memory variable to store old values used for event emissions. However, this is not required if the event is emitted first.

For example, function setKeeper can be optimized in the following manner:

```solidity
function setKeeper(address _keeper) external onlyOwner {
    if (_keeper == address(0)) revert AddressMustBeNonZero();
    emit KeeperSet(keeper, _keeper);
    keeper = _keeper;
}
```

**Recommended Mitigation:** Consider removing the memory variables by emitting events first.

**Sherpa:** Fixed in commit [`7e34a6b`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/7e34a6b064b63d8f7a3f2c66c49e10adab0198b7)

**Cyfrin:** Verified.

\clearpage