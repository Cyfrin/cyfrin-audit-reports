**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[Al-qaqa](https://x.com/Al_Qa_qa)

**Assisting Auditors**



---

# Findings
## Low Risk


### `spl_token_whitelist::change_admin` is single-step and accepts any `Pubkey` including the default zero key

**Description:** `change_admin_handler` writes the caller-supplied `new_admin` into `SplWhitelistState::admin` after only checking `state.admin != new_admin`. There is no `require_keys_neq!(new_admin, Pubkey::default(), ...)` filter, no validation that `new_admin` is a Signer in the same transaction, and no two-step propose-then-accept handshake. Because every other admin-gated instruction (`pause`, `unpause`, future `change_admin`) is bound by `has_one = admin`, a rotation to the all-zero pubkey or to any address whose private key is not held by the protocol team permanently locks those instructions - no further signer can satisfy `has_one = admin`, and the upgrade authority is not re-consulted after `initialize`.
```rust
/// Updates the admin pubkey stored in the whitelist state.
pub fn change_admin_handler(ctx: Context<ChangeAdmin>, new_admin: Pubkey) -> Result<()> {
    let spl_whitelist_state = &mut ctx.accounts.spl_whitelist_state;

    require!(
        spl_whitelist_state.admin != new_admin,
        SplWhitelistErrorCode::NoChange
    );

    spl_whitelist_state.admin = new_admin;

    emit!(crate::events::AdminChanged {
        admin: ctx.accounts.admin.key(),
        new_admin,
    });

    Ok(())
}
```

The same shape exists in the `dstoken-whitelist` program's `change_admin` handler (out of formal audit scope; included for context - the mitigation should be applied symmetrically across both programs).

**Impact:** If the admin signs a `change_admin` instruction with `new_admin = Pubkey::default()` (a fat-finger encoding mistake, an SDK / CLI argument-construction bug, a JSON deserialization that defaults missing fields to zero) or with any address whose key the team cannot produce on a later signature, the whitelist state PDA becomes administratively bricked. `pause` and `unpause` can no longer be called, so the only operational kill-switch protecting the permissionless `whitelist` instruction is lost. A subsequent `change_admin` to recover from the mistake is also blocked, since the current `admin` field is unsignable. The only remaining recovery is a program redeploy by the upgrade authority that rewrites `change_admin_handler` (or that re-initializes the state PDA through a migration). The harm requires admin error or key compromise to manifest, which caps severity at Low, but recovery is non-trivial and operationally disruptive.

**Recommended Mitigation:** Add a zero-key filter and adopt a two-step rotation in both `change_admin` handlers. Concretely, in `programs/spl-token-whitelist/src/instructions/admin/change_admin.rs` (and apply the same change symmetrically to the `dstoken-whitelist` `change_admin` handler, which is out of formal audit scope):

1. Reject the default pubkey at the top of the handler:

```rust
require_keys_neq!(
    new_admin,
    Pubkey::default(),
    SplWhitelistErrorCode::InvalidAdmin
);
```

2. Split the rotation into a propose step (the current admin writes the proposed admin key into a new pending-admin field on the state PDA) and an accept step that requires the new admin to sign the second transaction and clears the pending-admin field upon acceptance. This guarantees that the destination key is controlled by a live signer before it replaces the active admin. If the propose/accept refactor is out of scope for this release, at minimum require the `new_admin` to sign the same `change_admin` transaction by adding a second `Signer<'info>` account to the `ChangeAdmin` struct and constraining it so that the signer's key equals `new_admin`.

**Securitize:** Acknowledged.

\clearpage
## Informational


### Hardcoded `MINT_CONFIG_DISCRIMINATOR = 1` duplicates upstream TACL state with no compile-time tie-back

**Description:** `programs/spl-token-whitelist/src/constants.rs:7` declares `pub const MINT_CONFIG_DISCRIMINATOR: u8 = 1` as a hardcoded literal. The same byte value is the discriminator field on the upstream `spl_token_access_control` (TACL) program's `MintConfig` state struct (which is out of audit scope and not redistributed as a consumable public constant by the upstream crate). The in-scope code re-declares the byte locally and compares the deserialized struct's discriminator against the local literal at `programs/spl-token-whitelist/src/utils/freeze_authority_type.rs:77`:

```rust
require!(
    mint_config.discriminator == MINT_CONFIG_DISCRIMINATOR,
    SplWhitelistErrorCode::InvalidMintConfig
);
```

The discriminator is sourced from upstream state but is not tied back to upstream at compile time. The two values can desynchronize across releases: if the upstream TACL program ever bumps `MintConfig::DISCRIMINATOR` (e.g. to `2` during a struct-layout migration), the in-scope `AcProgramWithSrfc37` and `SystemAccountWithSrfc37` thaw paths will start returning `InvalidMintConfig` for every legitimately-derived `MintConfig` account, silently DoS'ing the sRFC-37 thaw flows until the in-scope program is rebuilt and redeployed with a refreshed literal. The bug surfaces only after the upstream upgrade lands; the in-scope code compiles fine in isolation because the duplicated constant carries no dependency on the upstream definition.

The recoverability question is non-trivial because the program is upgradeable per the deployment context, but the failure mode is silent until users encounter it. A whitelist instruction that previously thawed accounts will start failing for a class of mints that was working a day earlier, with no signal in the in-scope code that explains why.

**Recommended Mitigation:** Two options, in order of preference:

1. Upstream fix - request that `spl_token_access_control` export `MintConfig::DISCRIMINATOR` (or the `MintConfig` discriminator byte) as a `pub const` consumable downstream, then replace the local literal with the imported constant. The Rust compiler will then enforce equality across the workspace via the dependency pin.

2. If upstream cannot be modified, add a build-time or test-time assertion that bridges the gap - e.g. a unit test that constructs a `MintConfig` via the upstream crate's public constructor (or a zeroed instance with the discriminator field set) and asserts the local `MINT_CONFIG_DISCRIMINATOR` equals what the upstream produces. This converts a silent runtime DoS after an upstream upgrade into a build-time failure during dependency bumping, surfacing the drift before deployment.

**Securitize:** Acknowleged.


### SPL sRFC-37 access-control thaw forwards caller-selected CPI accounts without tying them to the validated authority path

**Description:** For an sRFC-37 mint whose Token ACL `MintConfig.freeze_authority` is the `spl-token-access-control` authority PDA, `FreezeAuthorityType::from_mint_and_freeze_authority` re-derives the access-control authority PDA from the mint, verifies it matches the supplied `srfc37_authority`, and returns `AcProgramWithSrfc37`:

```rust
let ac_program_authority = Pubkey::find_program_address(
    &[
        spl_token_access_control::constants::ACCESS_CONTROL_AUTHORITY_SEED,
        mint.key().as_ref(),
    ],
    &spl_token_access_control::ID,
)
.0;
if ac_program_authority == srfc37_authority.key() {
    require!(
        authority.key() != srfc37_authority.key(),
        SplWhitelistErrorCode::InvalidFreezeAuthorityType
    );
    return Ok(Self::AcProgramWithSrfc37);
}
```

The wrapper has authoritatively established, from the mint alone, the identity of the access-control authority for this thaw.

The `AcProgramWithSrfc37` branch of `thaw_account` then takes the next five entries of `remaining_accounts` and forwards them as the downstream CPI accounts:

```rust
Self::AcProgramWithSrfc37 => {
    require!(
        additional_accounts.len() == self.additional_accounts_len(),
        SplWhitelistErrorCode::InvalidFreezeAuthorityType
    );

    let access_control_authority = &additional_accounts[0];
    let access_control_state = &additional_accounts[1];
    let event_authority = &additional_accounts[2];
    let program = &additional_accounts[3];
    require!(
        *program.key == spl_token_access_control::ID,
        SplWhitelistErrorCode::InvalidFreezeAuthorityType
    );
    let token_acl_program = &additional_accounts[4];
    require!(
        *token_acl_program.key == TOKEN_ACL,
        SplWhitelistErrorCode::InvalidFreezeAuthorityType
    );

    let ac_program_thaw_accounts =
        spl_token_access_control::cpi::accounts::ThawAccount {
            access_control_authority: access_control_authority.to_account_info(),
            access_control_state: access_control_state.to_account_info(),
            authority: authority.to_account_info(),
            event_authority: event_authority.to_account_info(),
            ...
        };
```

The slot-to-CPI mapping is:

| Index | Slot in CPI | Wrapper-side check |
|-------|-------------|--------------------|
| `[0]` | `access_control_authority` | none |
| `[1]` | `access_control_state` | none |
| `[2]` | `event_authority` | none |
| `[3]` | `spl-token-access-control` program | program ID equality |
| `[4]` | Token ACL program | program ID equality |

The first three slots are accepted unconditionally. The wrapper does not require `additional_accounts[0] == srfc37_authority` (which it already derived), does not re-derive `[ACCESS_CONTROL_STATE_SEED, mint]` for slot `[1]`, and does not re-derive the `#[event_cpi]` event authority PDA for slot `[2]`.

This is currently safe only because the pinned `spl-token-access-control` revalidates these accounts through its own Anchor PDA constraints on `ThawAccount`:

```rust
#[account(
    seeds = [ACCESS_CONTROL_STATE, mint.key().as_ref()],
    bump = access_control_state.bump,
)]
pub access_control_state: Account<'info, AccessControlState>,

#[account(
    seeds = [ACCESS_CONTROL_AUTHORITY_SEED, mint.key().as_ref()],
    bump,
)]
pub access_control_authority: AccountInfo<'info>,
```

The wrapper has performed the classification work to know what the correct accounts must be, then discards that knowledge and relies on downstream constraints to catch mismatches.

This is the only freeze-authority mode with the gap: `SystemAccount` and `AcProgram` pass the Anchor-validated `freeze_authority` directly into the CPI rather than reading authority-bearing slots from `remaining_accounts`, and `SystemAccountWithSrfc37` only forwards the Token ACL program account (which is checked against `TOKEN_ACL`).


**Recommended Mitigation:** In the `AcProgramWithSrfc37` branch, derive `access_control_authority`, `access_control_state`, and the `__event_authority` PDA from the mint under `spl_token_access_control::ID`, and require `additional_accounts[0..3]` to equal those derivations before constructing the CPI. Apply the same change to the `AcProgram` branch's `access_control_state` and `event_authority` slots.

**Securitize:** Acknowledged.


### `getWhitelistIxs` is not checking the ownership of the tokenAccounts passed with tx owner

**Description:** When constructing a whitelist transaction, the off-chain `getWhitelistIxs` function is called. The caller can either provide token accounts directly via `params.tokenAccounts`, or omit them — in which case the function automatically derives the owner's Associated Token Accounts (ATAs).

The problem arises when token accounts are provided explicitly. In this case, there is no off-chain validation to verify that the provided token accounts are actually owned by the transaction owner, allowing arbitrary token accounts to be passed without any client-side rejection.

> packages/spl-token-whitelist-sdk/src/instructions/whitelist.ts#getWhitelistIxs
```ts
export async function getWhitelistIxs( ... ): Promise<TransactionInstruction[]> {
  ...
  let tokenAccounts: PublicKey[];

  if (params.tokenAccounts && params.tokenAccounts.length > 0) {
>>  tokenAccounts = params.tokenAccounts;
  } else { ... }

  ...

  return [...preIxs, ix];
}
```

While the on-chain program does enforce that each token account's owner matches the transaction signer, the absence of this check on the client side means that a caller can construct and submit a transaction referencing token accounts they do not own. The transaction will be rejected on-chain, but the SDK silently allows the construction and submission of such invalid transactions without providing any meaningful client-side error, leading to a poor developer experience and potentially unexpected runtime failures.

> programs/spl-token-whitelist/src/instructions/whitelist.rs#whitelist_handler
```rs
pub fn whitelist_handler<'info>(ctx: Context<'_, '_, '_, 'info, Whitelist<'info>>) -> Result<()> {
    ...
    // Thaw the token accounts
    for token_account_info in token_accounts_infos.iter() {
        ...
        require!(
>>          token_account.owner == ctx.accounts.owner.key(),
            SplWhitelistErrorCode::InvalidOwner
        );
        ...
    }
    ...
}
```

**Recommended Mitigation:** The `getWhitelistIxs` function should validate that each explicitly provided token account is owned by the transaction owner before constructing the instruction. This check should be performed by fetching each token account's data and verifying that its `owner` field matches the provided owner address.

**Securitize:** Fixed in [db2c3c2](https://github.com/securitize-io/bc-solana-whitelist-sc/commit/db2c3c21026b66b0f06c5fdf59d3ab158a62d078).

**Cyfrin:** Verified.


### `Whitelisted` event does not record which freeze-authority path was used

**Description:** The `whitelist` instruction resolves a `FreezeAuthorityType` before thawing accounts. That enum drives validation, how many `remaining_accounts` are consumed, and which CPI path runs (`token_2022::thaw_account`, access-control `thaw_account`, or SRFC37 `thaw_account`):

> programs/spl-token-whitelist/src/utils/freeze_authority_type.rs
```rs
pub enum FreezeAuthorityType {
    SystemAccount,
    AcProgram,
    AcProgramWithSrfc37,
    SystemAccountWithSrfc37,
}
```

After processing, the program emits `Whitelisted` with only `owner`, `mint`, and `accounts_count`:

> programs/spl-token-whitelist/src/events.rs
```rs
/// Emitted after thawing a batch of token accounts for an owner.
#[event]
pub struct Whitelisted {
    pub owner: Pubkey,
    pub mint: Pubkey,
    pub accounts_count: u8,
}
```


**Impact:**
- The resolved `freeze_authority_type` is not included in the event, preventing off-chain and monitoring systems from knowing the type of thaw/unfreezing that occurred.

**Recommended Mitigation:** We should include the type of `freeze_authority_type` in the event so that we know by which method we unfreezed tokenAccounts

**Securitize:** Acknowledged.

\clearpage