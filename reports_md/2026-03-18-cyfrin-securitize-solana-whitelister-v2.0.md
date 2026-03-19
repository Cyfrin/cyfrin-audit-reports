**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[JesJupyter](https://x.com/jesjupyter)

[Ctrus](https://x.com/ctrusonchain)

**Assisting Auditors**



---

# Findings
## Medium Risk


### Improper investor-to-identity validation allows arbitrary wallet attachment to any investor identity

**Description:** `register_vault` is intended to protect wallet attachment with `require_investor_signature`, but the current implementation does not authenticate the investor whose identity is being modified.

The Solana flow only checks that:
1. `existing_investor_wallet` signed the transaction, and
2. `existing_investor_wallet_identity` is the PDA derived from that wallet.

It does **not** verify that `existing_investor_wallet_identity` is a valid `WalletIdentity` account bound to the same `identity_account` that is later passed into `attach_wallet_to_identity`. As a result, there is no on-chain binding between the purported “existing investor” and the identity actually being mutated.

This means an operator can satisfy the signer check with any wallet they control and still attach an attacker-controlled vault/wallet to an arbitrary victim `identity_account`. The downstream RBAC / Identity Registry CPI only uses the target `identity_account` and the new wallet being attached, so the “existing investor” accounts do not constrain the identity being modified.

`require_investor_signature = false` is obviously unsafe, but even `require_investor_signature = true` is still bypassable because the signer is not required to belong to the target investor identity. Unlike the EVM implementation, the Solana flow does not verify that the passed investor wallet actually corresponds to the investor whose identity is being updated.

**Impact:** A privileged operator can impersonate any investor identity by attaching an attacker-controlled wallet or vault to that identity.

Once attached, downstream DS-token infrastructure treats the attacker-controlled wallet as the victim identity for normal issuance, transfer, and compliance checks. This allows the attacker to:
1. receive and transfer DS tokens under the victim’s compliance profile;
2. bypass country / level-based restrictions that would apply to the attacker’s real identity;
3. pollute the victim’s identity-wide tracker state and potentially disrupt the real investor’s future transfers.

In integrated deployments, the impact becomes more severe. In the off ramp, `redeem_ds_token` accepts a valid `wallet_identity -> identity_account` binding as sufficient investor authorization. Therefore, once an attacker-controlled wallet has been fraudulently attached to a victim identity, the attacker can redeem DS tokens from that wallet into attacker-owned liquidity tokens through the off-ramp.

The worst case is:
1. attach attacker wallet to a privileged / unrestricted victim identity;
2. route DS tokens into that forged wallet through ordinary issuance or transfer flows;
3. redeem those DS tokens through the off-ramp into liquidity tokens controlled by the attacker.

**Recommended Mitigation:** Require the identity account to be owned by the `existing_investor_wallet`.

**Securitize:** Fixed in [c7e5ff7](https://github.com/securitize-io/bc-solana-whitelister/commit/c7e5ff78635e2ac59ce37ad9b3fb96f9e9cc55b0).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Investor's token balance is not checked prior to registration

**Description:** The Solana implementation of the `VaultRegistrar` does not enforce the investor token balance check present in the EVM equivalent. In the EVM protocol, the contract verifies that the investor holds the relevant asset (`IERC20(token).balanceOf(investorWalletAddress) > 0`) before allowing the registration of a new vault. The current Solana `register_vault_handler` only checks for the presence of the `existing_investor_wallet` and its identity PDA but fails to verify if the wallet actually holds any tokens of the `asset_mint`.

**Impact:** If the investor doesnt hold tokens it means maybe there is something that has not been complete from KYC or on boarding standpoint, and such investors must be prevented from registration.

**Recommended Mitigation:** Implement the evm equivalent check.

**Securitize:** Fixed in [f16257a](https://github.com/securitize-io/bc-solana-whitelister/commit/f16257a5ab55e5a3252dd2c0b87a3f471614490b).

**Cyfrin:** Verified.

\clearpage
## Informational


### `VaultRegistered` event omits investor signer when signature is required

**Description:** The `VaultRegistered` event at `register_vault.rs:138-144` emits `registrar`, `caller`, `vault`, `asset_mint`, and `identity_account`, but does not include the `existing_investor_wallet` pubkey when `require_investor_signature` is enabled.

```rust
emit!(VaultRegistered {
    registrar: ctx.accounts.vault_registrar_state.key(),
    caller: ctx.accounts.caller.key(),
    vault: ctx.accounts.vault_wallet.key(),
    asset_mint: ctx.accounts.asset_mint.key(),
    identity_account: ctx.accounts.identity_account.key(),
});
```

Off-chain monitoring systems cannot determine which investor provided consent from the event alone.

**Recommended Mitigation:** Add an optional `investor` field to the `VaultRegistered` event.

**Securitize:** Fixed in [17bb95e](https://github.com/securitize-io/bc-solana-whitelister/commit/17bb95e22b0d4130753c4d37ed1f9596c7f21f0e).

**Cyfrin:** Verified.



### `set_require_investor_signature` allows setting to current value, emitting misleading event

**Description:** `set_require_investor_signature` unconditionally sets the flag and emits a `RequireInvestorSignatureUpdated` event, even when the new value equals the current value. This produces misleading events suggesting a configuration change occurred when none did.

**Recommended Mitigation:** Add a guard to prevent no-op updates:

```rust
require!(
    state.require_investor_signature != require_investor_signature,
    VaultRegistrarError::AlreadySet // new error code
);
```

**Securitize:** Fixed in [3c93d56](https://github.com/securitize-io/bc-solana-whitelister/commit/3c93d56a0296d9cada6eb556fa8674dff0933689).

**Cyfrin:** Verified.


### Dead Error Variants and Documentation Inconsistency for Signature Requirements

**Description:** The error variants `VaultSignatureRequired` and `InvestorSignatureRequired` are defined in `errors.rs` but never used in the program logic. Additionally, the README references `require_investor_and_vault_signatures` and states that "both the investor and vault keypairs must sign," whereas the actual state field is `require_investor_signature` and vault signature is never enforced, creating documentation inconsistency.


In `programs/vault-registrar/src/errors.rs`:

```rust
#[msg("Vault signature required: vault wallet must sign the transaction")]
VaultSignatureRequired,

#[msg("Investor signature required: existing_investor_wallet must sign the transaction")]
InvestorSignatureRequired,
```

In `register_vault`, when `require_investor_signature` is true, only `InvestorAccountsRequired` is used:

```rust
if vault_registrar_state.require_investor_signature {
    require!(
        ctx.accounts.existing_investor_wallet.is_some()
            && ctx.accounts.existing_investor_wallet_identity.is_some(),
        VaultRegistrarError::InvestorAccountsRequired
    );
}
```

`VaultSignatureRequired` and `InvestorSignatureRequired` are never referenced in the program, so they are dead code.

Also,
> When `require_investor_and_vault_signatures` is true, pass `investorKp` and `existingInvestorWalletIdentity`:

> When `require_investor_and_vault_signatures` is true on the registrar, both the investor and vault keypairs must sign the transaction. Use `--investor-wallet-path` and `--vault-keypair-path` in that case.

The actual state field is `require_investor_signature` (singular), and `vault_wallet` is an `UncheckedAccount`—the program never enforces vault signature. Only the investor signature is enforced indirectly via `existing_investor_wallet: Option<Signer<'info>>` when the account is provided.

**Impact:**
- **Dead code**: Increases maintenance burden and may mislead future developers into believing vault signature verification exists.
- **Documentation mismatch**: The incorrect field name and the claim that "both" must sign can cause integration errors or incorrect expectations.

**Recommended Mitigation:** **Remove unused error variants** and **Fix README** if needed.

**Securitize:** Fixed in [2251615](https://github.com/securitize-io/bc-solana-whitelister/commit/2251615f8b553fd0c78685332eeb8164536ff939).

**Cyfrin:** Verified.



### Permissionless `Initialize` and Counter Saturation Edge Case

**Description:** There is no access control on `initialize`. Any payer can create a `VaultRegistrarState` with any `admin` (who must sign) and any `asset_mint`:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub admin: Signer<'info>,
    // ...
    pub asset_mint: InterfaceAccount<'info, anchor_spl::token_interface::Mint>,
    // ...
}
```

This allows arbitrary actors to create registrars with arbitrary configurations, which may pollute the namespace and complicate discovery of legitimate registrars.

Additionally, when the global counter reaches `u64::MAX`, `saturating_add(1)` saturates and subsequent `initialize` calls will fail because the PDA for that id already exists.


```rust
ctx.accounts.vault_registrar_counter.set_inner(VaultRegistrarCounter {
    count: id.saturating_add(1),
    bump: ctx.bumps.vault_registrar_counter,
});
```

When `count` reaches `u64::MAX`, it saturates and stays at `u64::MAX`. The next `initialize` call will attempt to create a `vault_registrar_state` with seeds `[VAULT_REGISTRAR_STATE_SEED, u64::MAX.to_le_bytes()]`, but that PDA already exists from the previous successful init. The `init` constraint will fail because the account cannot be created twice.

**Impact:**
- **Permissionless**: Spam or low-quality registrars may be created, but no direct security impact since each registrar is isolated.
- **Counter saturation**: Theoretically prevents new registrars once `u64::MAX` is reached. Reaching this value is economically infeasible.


**Recommended Mitigation:** If this intentional, document the permissionless design as intentional.

**Securitize:** Fixed in [4a09894](https://github.com/securitize-io/bc-solana-whitelister/commit/4a09894fe802d324d7dceee0442ab873841e4c3d).

**Cyfrin:** Verified.


### Insufficient validation on vaults

**Description:** The Solana implementation lacks the validation checks present in the EVM `VaultRegistrar` designed to verify if a vault has already been registered. In the EVM version, before a vault wallet is added, the protocol queries if the vault is already associated with an identity. If it is linked to a different investor, it purposefully reverts with `VaultBelongsToDifferentInvestor`; if it is linked to the same investor, it reverts with `VaultAlreadyRegistered`.

Currently, the Solana contract calls `rwa_rbac::cpi::attach_wallet_to_identity` directly. Our Solana flow calls the CPI directly without this pre-check., which breaks parity with the EVM architecture and sacrifices granular error handling.

**Recommended Mitigation:** Implement proper checks just like its evm equivalent.

**Securitize:** Fixed in [8e3b5f8](https://github.com/securitize-io/bc-solana-whitelister/commit/8e3b5f8753b86afc984ad5620e1865ed2db63106).

**Cyfrin:** Verified.


### Explicitly reject `Pubkey::default()` for `vault_wallet` or the `investor_wallet`

**Description:** EVM implementaion uses `notZeroAddress` for both `vaultAddress` and `investorWalletAddress` as a zero address check. We don’t currently explicitly reject `Pubkey::default()` for `vault_wallet` or the `investor_wallet` in solana implementation. It is advised to add this senity check prior to cpi.

**Impact:** ` vault_wallet` or the `investor_wallet` with default pubkeys can be passed.

**Recommended Mitigation:** Reject default keys when supplied.

**Securitize:** Fixed in [e4f82ff](https://github.com/securitize-io/bc-solana-whitelister/commit/e4f82ff30353e7b9ee58cb57fe918b1dfece524c).

**Cyfrin:** Verifed.

\clearpage
## Gas Optimization


### Redundant Zero-Address Check in `revoke_operator`

**Description:** The `operator != Pubkey::default()` check in `revoke_operator_handler` is redundant. Since `add_operator_handler` already prevents the zero address from being added to the operators list, it can never be present when revoking. The subsequent `state.operators.contains(&operator)` check will always fail for `Pubkey::default()` with `OperatorNotFound`, yielding the same outcome.


In `revoke_operator_handler`:

```rust
require!(
    operator != Pubkey::default(),
    VaultRegistrarError::InvalidOperator
);

require!(
    state.operators.contains(&operator),
    VaultRegistrarError::OperatorNotFound
);
```

In `add_operator_handler`, the zero address is already rejected:

```rust
require!(
    new_operator != Pubkey::default(),
    VaultRegistrarError::InvalidOperator
);
// ...
state.operators.push(new_operator);
```

Therefore, `Pubkey::default()` can never exist in `state.operators`. For `operator == Pubkey::default()`, `contains()` will return false and the handler will revert with `OperatorNotFound` regardless of the first check.

**Impact:**
- Redundant code increases maintenance burden.

**Recommended Mitigation:** Remove the redundant `operator != Pubkey::default()` check from `revoke_operator_handler`. Rely on `state.operators.contains(&operator)` to reject invalid operators, including the zero address.

**Securitize:** Fixed in [00d1f81](https://github.com/securitize-io/bc-solana-whitelister/commit/00d1f819c638d9495aab46ebf54e1a3be5c97017).

**Cyfrin:** Verified.

\clearpage