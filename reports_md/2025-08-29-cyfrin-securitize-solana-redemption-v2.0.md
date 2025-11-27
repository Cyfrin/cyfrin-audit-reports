**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[Naman](https://x.com/namx05)

**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## High Risk


### Broken identity-to-wallet binding in redeem allows country restriction bypass

**Description:** The `redeem` instruction accepts three identity objects that should all refer to the same person and wallet: `IdentityRegistryAccount`, `IdentityAccount`, and `WalletIdentity`. The account constraints only ensure:
- `IdentityRegistryAccount` matches the `asset_mint`.
- `IdentityAccount` belongs to that registry.
- `WalletIdentity` is the PDA for `(redeemer, asset_mint)`.

There is no on-chain assertion that the provided `IdentityAccount` is the one linked to the `WalletIdentity` and the `redeemer`. As a result, the caller can mix a valid `WalletIdentity` for their wallet with someone else’s `IdentityAccount` that has a permitted country, then pass country checks.

```rust
/// Identity registry for asset mint compliance
#[account(
    has_one = asset_mint,
    seeds = [asset_mint.key().as_ref()],
    seeds::program = ::identity_registry::ID,
    bump = identity_registry.bump,
)]
pub identity_registry: Box<Account<'info, IdentityRegistryAccount>>,

/// User's identity account with country information
#[account(
    has_one = identity_registry,
    seeds = [identity_registry.key().as_ref(), identity_account.owner.as_ref()],
    seeds::program = ::identity_registry::ID,
    bump
)]
pub identity_account: Box<Account<'info, IdentityAccount>>,

/// Links wallet to identity account
#[account(
    seeds = [redeemer.key().as_ref(), asset_mint.key().as_ref()],
    seeds::program = ::identity_registry::ID,
    bump,
)]
pub wallet_identity: Box<Account<'info, WalletIdentity>>,
```

**Impact:** Country restriction bypass. A wallet from a restricted country can redeem by supplying a different user’s `IdentityAccount` that reports an allowed country.

**Recommended Mitigation:** Consider requiring the association between the provided `IdentityAccount` and the `WalletIdentity` .

**Securitize:** Fixed in [78ad18d](https://github.com/securitize-io/bc-solana-redemption-sc/commit/78ad18d0dc78f7468be0092667046bea021b7875).

**Cyfrin:** Verified.


\clearpage
## Medium Risk


### DoS in initialize via pre-created ATA for `off_ramp_authority`

**Description:** The `initialize` instruction creates the liquidity vault as an **associated token account** for the program PDA `off_ramp_authority`:
```rust
#[account(
    init,
    payer = admin,
    associated_token::mint = liquidity_token_mint,
    associated_token::authority = off_ramp_authority,
    associated_token::token_program = liquidity_token_program,
)]
pub liquidity_token_vault: Box<InterfaceAccount<'info, TokenAccount>>;
```
Associated token accounts are globally derivable and can be created by **anyone** for any owner without the owner’s signature. Because both `off_ramp_state` and `off_ramp_authority` PDAs are deterministically derived from public seeds (counter and state key), an attacker can precompute the vault ATA and create it first. When `initialize` later runs with `init`, Anchor will fail with “already in use,” reverting the whole transaction.

**Impact:** Hard denial of service on program initialization for a given `(off_ramp_state, liquidity_token_mint)`. An attacker can repeatedly grief by precreating the ATA for each anticipated off_ramp ID, blocking deployment unless the admin changes parameters. This is cheap for the attacker and can be repeated.

**Recommended Mitigation:** Switch to `init_if_needed` to make initialization idempotent and immune to precreation:
```rust
#[account(
    init_if_needed,
    payer = admin,
    associated_token::mint = liquidity_token_mint,
    associated_token::authority = off_ramp_authority,
    associated_token::token_program = liquidity_token_program,
)]
pub liquidity_token_vault: Box<InterfaceAccount<'info, TokenAccount>>;
```
This accepts a pre-existing correct ATA and proceeds.


**Securitize:** Fixed in [1a8a098](https://github.com/securitize-io/bc-solana-redemption-sc/commit/1a8a0989c940eb8978ff3556bfc513ee0606f6dc).

**Cyfrin:** Verified.



### Permissionless OffRampState initialization under official program ID enables spoofed “official” instances

**Description:** The `initialize` instruction lets any signer create a new `OffRampState` and become its `admin`. The global `OffRampCounter` is `init_if_needed` and unguarded, and the new state PDA is derived from `[OFF_RAMP_STATE_SEED, off_ramp_counter.counter.to_le_bytes()]`. There is no allowlist or registry check tying the initializer to an official Securitize operator.
This means anyone can spin up an OffRamp instance under the same Program ID and emit an `Initialized` event, which can be marketed as if it were an official, Securitize backed off ramp.
```rust
/// Global counter for generating unique off-ramp IDs
#[account(
    init_if_needed,
    payer = admin,
    space = 8 + OffRampCounter::INIT_SPACE,
    seeds = [OFF_RAMP_COUNTER_SEED],
    bump,
)]
pub off_ramp_counter: Box<Account<'info, OffRampCounter>>,

/// Off-ramp state containing configuration and settings
#[account(
    init,
    payer = admin,
    space = 8 + OffRampState::INIT_SPACE,
    seeds = [OFF_RAMP_STATE_SEED, off_ramp_counter.counter.to_le_bytes().as_ref()],
    bump,
)]
pub off_ramp_state: Box<Account<'info, OffRampState>>,
```

**Impact:** A third party can deploy a look alike instance with arbitrary fees, NAV provider, and recipient policy, then present it as “the Securitize off ramp” because it is hosted under the same Program ID.


**Recommended Mitigation:** Add a `GlobalConfig` PDA that stores an `authorized_initializer` or allowlist. In `initialize`, require the `admin` signer to be on that list.

**Securitize:** Fixed in [30362cf](https://github.com/securitize-io/bc-solana-redemption-sc/commit/30362cf3d6b349cad72134f843808464d7477502).

**Cyfrin:** Verified.


\clearpage
## Low Risk


### Silent truncation on u128 to u64 cast in liquidity token amount calculator

**Description:** The `utils::token_calculator::calculate_liquidity_token_amount` function computes the output in `u128` and returns it with a plain `as u64` cast:
```rust
let result = /* u128 math */;
Ok(result as u64)
```
If `result` fits in `u128` but exceeds `u64::MAX`, the cast truncates the high bits without error. The function then reports a much smaller number than intended. Both the quote path and `redeem` use this helper, so the truncation can silently underpay.

**Impact:** Silent underpayment and wrong accounting.


**Recommended Mitigation:** Replace the lossy cast with a checked conversion:
```rust
use core::convert::TryFrom;

let result_u64 = u64::try_from(result)
    .map_err(|_| SecuritizeOffRampError::Overflow)?;
Ok(result_u64)
```

**Securitize:** Fixed in [7172884](https://github.com/securitize-io/bc-solana-redemption-sc/commit/71728848f7ae01c3b686b343210bd6ae3143ab85).

**Cyfrin:** Verified.


\clearpage
## Informational


### Fee collector field ambiguity wallet vs token account

**Description:** `FeeManager::collector` is a `Pubkey` named like a wallet, but every place that uses it expects a **token account address** for the liquidity mint. In `initialize` and `update_fee_manager` you require `fee_collector_ta.address == fee_manager.fee_collector()` and enforce `token::mint = liquidity_token_mint`.

If an integrator sets `collector` to a wallet pubkey instead of the token account pubkey, the instruction fails or fees route incorrectly across environments.

```rust
/// Fee manager enum for fee strategies
pub enum FeeManager {
    /// Mbps-based fee manager
    MbpsFeeManager(MbpsFeeManager),
}
```
```rust
/// Mbps-based fee manager (basis points)
pub struct MbpsFeeManager {
    /// Fee numerator (bps)
    pub numerator: u32,
    /// Fee collector address
    pub collector: Pubkey,
}
```

**Recommended Mitigation:** Rename the field to `collector_token_account` to reflect intent.

**Securitize:** Fixed in [ab7f4d2](https://github.com/securitize-io/bc-solana-redemption-sc/commit/ab7f4d2f9110df2bf37ec1d2c8f7e2f4b1545310).

**Cyfrin:** Verified.



### Missing Two Step Ownership And Authority Transfer Validation

**Description:** Both `change_admin_handler` and `change_liquidity_withdraw_authority_handler` directly reassign critical control fields (`off_ramp_state.admin` and `off_ramp_state.liquidity_withdraw_authority`) in a single transaction without requiring confirmation from the proposed new key. This one-step transfer model increases the risk of accidental misconfiguration or malicious key injection. Additionally, neither function validates against assignment of the default zero address (`Pubkey::default()`), which could permanently lock the system by assigning an unusable authority.

**Impact:** If a privileged signer mistakenly or maliciously sets the new authority to the default address, administrative or liquidity withdrawal rights could be irreversibly lost. Furthermore, the absence of a two-step acceptance process enables unilateral transfers without the consent of the intended new owner, reducing operational safety and creating potential governance disputes.

**Recommended Mitigation:**
- Introduce a two-step transfer process where the current owner proposes a new authority, and the proposed authority must explicitly accept before finalization.
- Also, enforce non-default key validation to prevent assignment to the zero address.


**Securitize:** Acknowledged.



### Missing Liquidity Vault Balance Validation

**Description:** In `withdraw_liquidity_handler`, liquidity tokens are transferred from `liquidity_token_vault` to the withdrawer’s associated token account. While the instruction checks that the withdrawal amount is greater than zero and that the system is not paused, it does not validate whether the vault actually holds at least `amount` tokens before attempting the transfer.
This omission may allow withdrawal attempts that exceed the available vault balance, leading to failed transactions or unintended program behavior depending on the token program implementation.

**Impact:** If the vault contains fewer tokens than requested, the transfer may fail at runtime, causing unnecessary transaction failures.

**Recommended Mitigation:** Add a balance check to ensure that `liquidity_token_vault.amount >= amount` before executing the transfer.

```diff
+ let liquidity_vault = &ctx.accounts.liquidity_token_vault;
+    require_gte!(
+      liquidity_vault.amount,
+      amount,
+    SecuritizeOffRampError::InsufficientLiquidity
+);
```


**Securitize:** Fixed in [3163cd9](https://github.com/securitize-io/bc-solana-redemption-sc/commit/3163cd9a818e0d83222d9cc74edbd6a4e4fa2d1c).

**Cyfrin:** Verified.

\clearpage