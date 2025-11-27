**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[Al-Qa-Qa](https://x.com/Al_Qa_qa)

**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## High Risk


### Precision Manipulation Due to Missing Mint Check

**Description:** `deposit_handler` chooses the conversion precision (`conv_decimals`) as:

```rust
let conv_decimals = ctx
    .accounts
    .liquidation_token_mint
    .as_ref()
    .map(|mint| mint.decimals)          // if Some ⇒ use its decimals
    .unwrap_or(ctx.accounts.asset_mint.decimals);
```

The account context *documents* that `liquidation_token_mint` and `liquidation_token_vault` must appear together, but there is **no runtime constraint** enforcing it.
An operator can therefore:

1. Pass **`liquidation_token_mint = Some`** with any mint they control (e.g., 0 decimals).
2. Pass **`liquidation_token_vault = None`**, bypassing the only check that references the vault.

Because `conv_decimals` now equals `0`, the denominator inside `convert_to_shares` becomes `10^0 = 1` instead of (say) `10^6`. All arithmetic that scales by this factor is therefore inflated by `10^decimals`, dramatically increasing the number of shares minted for the same asset deposit.

**Impact:** A privileged operator can mint an arbitrarily large supply of shares at a discount (≈ 10^D × cheaper, where **D** is the asset’s normal decimals). They can later redeem those shares for real assets, draining the vault and diluting all honest shareholders—effectively a direct loss of user funds.

**Proof of Concept:**
1. Create a fake SPL mint with `decimals = 0`.
2. Construct a `deposit` instruction where
   * `liquidation_token_mint` → the fake mint account
   * `liquidation_token_vault` → **omitted** (encode as `None`)
   * All other required accounts are valid.
3. Deposit 1 unit of the underlying asset.
4. Observe that `convert_to_shares` uses a factor of `1` instead of `10^asset_decimals`, minting roughly `10^asset_decimals` more shares than intended.

**Recommended Mitigation:** Enforce account coupling:
  ```rust
  require!(
      liquidation_token_mint.is_some() == liquidation_token_vault.is_some(),
      ScVaultError::InvalidLiquidationAccounts
  );
  ```
  or add an Anchor constraint tying the two options together as the docstring promises.


**Securitize:** Fixed in [b0cabd3](https://github.com/securitize-io/bc-solana-vault-sc/commit/b0cabd3ed8dac07ab78b245d9cbdc53102871937).

**Cyfrin:** Verified

\clearpage
## Medium Risk


### Missing Slippage Check on `liquidation_amount` in Redemption-Enabled Vaults

**Description:** When calling `liquidate_handler()` the liquidator provide the minimum amount of assets he is willing to receive. either assets or liquidation tokens

```rust
/// ## Arguments
...
/// - `min_output_amount`: An optional minimum output amount to ensure sufficient assets or liquidation tokens are received.
```

The slippage check is implemented only for assets before checking the type of the Vault weather it support Redemption or not.

```rust
>>  if let Some(min_output_amount) = min_output_amount {
        require_gt!(
            assets,
            min_output_amount,
            ScVaultError::InsufficientOutputAmount
        );
    }

    ...

    if let Some(ref redemption_program) = ctx.accounts.redemption_program {
        ...
        // Transfer received liquidation tokens to liquidator.
        transfer_from!(
            liquidation_token_vault,                                  // from
            liquidator_liquidation_ata,                        // to
            ctx.accounts.vault_authority,                             // authority
            ctx.accounts.liquidation_token_program.as_ref().unwrap(), // token_program
            liquidation_token_mint,                                   // mint
>>          liquidation_amount,                                       // amount
            liquidation_token_mint.decimals,                          // decimals
            vault_authority_signer                                    // signer
        );
    } else {
        ...
    }
```

As we can see the amount the liquidator receives in case of Redemption is not `assets` value calculated. it is `liquidation_amount` received after redeeming.

This wil result in incorrect slippage, as the liquidator will provide the minimum amount he is willing to receive from `liquidate token`, but the check will be made for `asset` instead.

**Impact:**
- Liquidator receives less than he wants

**Proof of Concept:**
- liquidator made the `min_output_amount` as `1000`
- firing `liquidate_handler`
- assets value is `1100` after calculations
- slippage passed
- firing `redemption_program::redeem()`
- liquidation_amount is `900`
- liquidator receives `900` token, although he mentioned he only accepts `1000` or more

**Recommended Mitigation:**
- Move the liquidation check and transfer it to the `else` block (the Vault that is not supporting Redemption)
- Make another liquidation check aganist `liquidation_amount` for Vaults supporting redemption

**Securitize:** Acknowledged, it’s acceptable from our side since it matches the behavior in the EVM version and we don’t intend to change it. However, the slippage documentation has been clarified in [56c8f9e](https://github.com/securitize-io/bc-solana-vault-sc/commit/56c8f9e8ac6420196ec2df3dddd5a8ee3a7e6965).

\clearpage
## Low Risk


### Off-By-One Error in Liquidator and Operator Capacity Check

**Description:** When adding new liquidators or operators, the check is performed to check that the MAX_LENGTH is greater than or equal the current length. But after this we push the new element.

> - bc-solana-vault-sc/programs/sc-vault/src/instructions/admin/add_liquidator.rs
>- bc-solana-vault-sc/programs/sc-vault/src/instructions/admin/add_operator.rs
```rust
pub fn add_liquidator_handler(
    ctx: &mut Context<AddLiquidator>,
    new_liquidator: Pubkey,
) -> Result<()> {
    let vault_state = &mut ctx.accounts.vault_state;

>>  require_gte!(
        MAX_LIQUIDATORS,
        vault_state.liquidators.len(),
        ScVaultError::MaxLiquidators
    );
    ...
>>  vault_state.liquidators.push(new_liquidator);
    ...
}
// ----------------
pub fn add_operator_handler(ctx: &mut Context<AddOperator>, new_operator: Pubkey) -> Result<()> {
    let vault_state = &mut ctx.accounts.vault_state;

>>  require_gte!(
        MAX_OPERATORS,
        vault_state.operators.len(),
        ScVaultError::MaxOperators
    );
    ...
>>  vault_state.operators.push(new_operator);
    ...
}
```

If the current length is the same as `MAX_LIQUIDATORS/OPERATORS` the check will pass, as it enforces the MAX to be greater than or equal. But this is incorrect. as if the length is the `MAX` we should prevent adding, as this will result in out of bound array access.

**Impact:** Incorrect behavior of the Program and getting incorrect error results.

**Recommended Mitigation:** Consider using `require_gt` instead of `require_gte`.

**Securitize:** Fixed in [179f8f3](https://github.com/securitize-io/bc-solana-vault-sc/commit/179f8f337b886edb1631c31537f62efb7ac8c47a).

**Cyfrin:** Verified


### Unsafe Addition in `convert_to_shares` Causes View Function Inaccuracy

**Description:** When providing `assets` parameter there is no check if the addition of `total_assets` with `asset` will result in a number greater than `u64::MAX` or not.

```rust
pub fn convert_to_shares(
    assets: u64,
    rate: u64,
    decimals: u8,
    total_assets: u64,
    total_supply: u64,
    rounding: Rounding,
) -> Result<u64> {
    let liq_token_decimals_factor = 10u64.pow(decimals.into());
    let total_shares_after_deposit = math::mul_div(
        rate,
>>      total_assets + assets,
        liq_token_decimals_factor,
        rounding,
    )?;
    ...
}
```

When calling `convert_to_assets_handler`, the asset is provided as input. it is like a `view` function to check the corresponding shares the operator will take for this amount. and this `assets` are added to `total_assets`.

So if he provided `assets` with value that makes `total_assets + assets` goes greater than `U64::MAX` this will result in overflow, leading to incorrect shares returned value for that amount.

This only affects the `view` function and `convert_to_assets_handler` as `deposit_handler` transfers the assets from the depositer (operator) before it, and since supply is `u64` it will not reach the max.


**Impact:** Incorrect return values when calling `convert_to_assets_handler` with large asset amount

**Recommended Mitigation:** Use safe additions in `convert_to_shares`, so that the function revert with overflow if the user provided large asset amount.

**Securitize:** Fixed in [9189e4c](https://github.com/securitize-io/bc-solana-vault-sc/commit/9189e4c3b46956861db1e2efe6cc49b5c0111ca9).

**Cyfrin:** Verified


### Strict Comparison in Slippage Check Incorrectly Blocks Valid Redemptions

**Description:** When checking minimum outcome from the liquidate, we are implementing the check to enforce the returned assets to be more than the minimum amount we put.

> bc-solana-vault-sc/programs/sc-vault/src/instructions/liquidator/liquidate.rs#liquidate_handler
```rust
    if let Some(min_output_amount) = min_output_amount {
>>      require_gt!(
            assets,
            min_output_amount,
            ScVaultError::InsufficientOutputAmount
        );
    }
```

This check is incorrect as if the `assets` equals `min_output_amount`. the tx will revert, but in reaility it should success as the user accepts this value is the minimum value he accepts, but it will be treated as less than desired by the user and revert the tx.

**Impact:** Reverting liquidations that are supposed to pass.

**Recommended Mitigation:** Consider adjusting the check to use `require_gt`.

**Securitize:** Fixed in [de507ba](https://github.com/securitize-io/bc-solana-vault-sc/commit/de507ba56f0181c411902cb23493b7a59b8de777).

**Cyfrin:** Verified


### Incorrect Splitting of `remaining_accounts` Causes Misrouting Between NAV and Redemption Accounts

**Description:** When spliting accounts in `liquidate_handler`, we are assuming that `nav_provider_program` will take the MAX value. where we take  the minimum value from the `MAX_NAV_PROVIDER_ACCOUNTS (5)` and the remaining accounts.

> bc-solana-vault-sc/programs/sc-vault/src/instructions/liquidator/liquidate.rs#liquidate_handler
```rust
    let nav_provider_accounts_count = MAX_NAV_PROVIDER_ACCOUNTS.min(ctx.remaining_accounts.len());
    let (nav_provider_accounts, redemption_accounts) =
        ctx.remaining_accounts.split_at(nav_provider_accounts_count);
```

The problem is that in case of `redemption` is activated, it takes at least `4` accounts.

> bc-solana-vault-sc/programs/sc-vault/src/constants.rs
```rust
pub const MIN_REDEMPTION_ACCOUNTS: usize = 4;
```

So if the liquidator is firing in a vault state where it activate the `redemption` and the nav provider only accepts `1` account as rate. this will result in incorrect splitting, and redemption accounts will goes to nav_provider instead.


**Impact:**
- Reverting liquidate function, resulting in inapility to do the liquidation process

**Proof of Concept:**
- Vault state activate `Redemption`, with minimum accounts required (4)
- Vault state has `NAV Provider program` accepting only one account (minimum).
- The liquidator fired liquidate putting remaining accounts as following: first one is `nav_provider_state`, and the other `4` are for redemption. i.e total 5.
- `nav_provider_accounts_count` will be 5.min(5), i.e 5
- All `5` accounts will goes to `nav_provider_accounts` and no account will goes to `redemption_accounts`
- This will lead to revert the tx when checking `redemption_accounts` aganist minimum as they should be at least of 4 length

**Recommended Mitigation:** Provide the split index as input, so that for `nav_providers` that don't need all `5` accounts, you can make them take the accounts they need. and make redemption accounts with correct values

**Securitize:** Fixed in [ab400a8](https://github.com/securitize-io/bc-solana-vault-sc/commit/ab400a819c6e96a317a1aba151101a930c485995#diff-4f93a9d4b557fd37b8c1471b7327157fcb3c08921e5f2226c38d5981651300b0).

**Cyfrin:** Verified


### `Liquidate` Event Emits Shares and Assets in Wrong Order

**Description:** The `Liquidate` event is fired making `shares` as the second parameter and `assets` as the third parameter

> bc-solana-vault-sc/programs/sc-vault/src/instructions/liquidator/liquidate.rs#liquidate_handler
```rust
    emit!(crate::events::Liquidate {
        liquidator: ctx.accounts.liquidator.key(),
2:      shares,
3:      assets,
    });
```

But the event construction is not like this, as `assets` are the second parameter not third. and shares is the third parameter not second.

> bc-solana-vault-sc/programs/sc-vault/src/events.rs
```rust
#[event]
pub struct Liquidate {
    pub liquidator: Pubkey,
2:  pub assets: u64,
3:  pub shares: u64,
}
```

There is also another thing to point out here, which is `assets` themselves. As the `assets` will be transferred to the  liquidator if the vault is not activating `redemption`, but in case of supporting redemption the actual amount transferred to the liquidator is `liquidation_amount`. This may cause confusion at case weather assets are the actual received balance, or what.

**Impact:** Incorrect event emission leads to incorrect tracking, analysis of the liquidation process.


**Recommended Mitigation:**
- Swap assets position with shares position
```diff
    emit!(crate::events::Liquidate {
        liquidator: ctx.accounts.liquidator.key(),
-       shares,
        assets,
+       shares,
    });
```
- And for `liquidation_amount` this can be mitigated by adding another parameter for `liquidation_amount` (default is zero if no Redemption is not supported)

**Securitize:** Fixed in [c766076](https://github.com/securitize-io/bc-solana-vault-sc/commit/c7660762f01943c3d0fe6e6074cf3bea682b7093).

**Cyfrin:** Verified

\clearpage
## Informational


### Invalid Zero Rate Not Rejected During Deposit

**Description:** When despoiting assets, and convert the shares to be minted to the despositer we are not checking the validity of rate value (weather it is greater zero or not)

> bc-solana-vault-sc/programs/sc-vault/src/utils/conversions.rs#convert_to_shares
```rust
pub fn convert_to_shares( ... ) -> Result<u64> {
    let liq_token_decimals_factor = 10u64.pow(decimals.into());
    let total_shares_after_deposit = math::mul_div(
>>      rate,
        total_assets + assets,
        liq_token_decimals_factor,
        rounding,
    )?;

    if total_shares_after_deposit >= total_supply {
        Ok(total_shares_after_deposit - total_supply)
    } else {
        Ok(0)
    }
}
```

This is not the case when redeeming where we check that the rate value is greater than zero

> bc-solana-vault-sc/programs/sc-vault/src/utils/conversions.rs#convert_to_assets
```rust
pub fn convert_to_assets( ... ) -> Result<u64> {
    if total_supply == 0 {
        return Ok(0);
    }
>>  require_gt!(rate, 0, ScVaultError::InvalidRate);
    let liq_token_decimals_factor = 10u64.pow(decimals.into());
    Ok(u64::min(
        math::mul_div(shares, liq_token_decimals_factor, rate, rounding)?,
        math::mul_div(shares, total_assets, total_supply, rounding)?,
    ))
}
```

This will make `total_shares_after_deposit` ends being `0`, results in minting `0` shares to the depositer (operator).

**Impact:**
- In case of incorrect return value from RedStone, the operator will take `0` shares

**Recommended Mitigation:** Check that `rate` is greater than `0`
```diff
pub fn deposit_handler<'info>( ... ) -> Result<()> {
    ...
    // Get rate from nav provider.
    let rate = get_rate!(ctx.remaining_accounts, ctx.accounts.nav_provider_program);
+   require_gt!(rate, 0, ScVaultError::InvalidRate);
    ...
    let shares = conversions::convert_to_shares( ... )?;

    ...
}

```

**Securitize:** Fixed in [2764f90](https://github.com/securitize-io/bc-solana-vault-sc/commit/2764f902d8cf3cfcf202eab1c78d16c48c7ef150).

**Cyfrin:** Verified


### Redundant `vault_authority_signer` passed to `BurnChecked` in `redeem` and `liquidate`

**Description:** Both `redeem_handler` and `liquidate_handler` build their burn CPI like this:

```rust
let burn_ctx = CpiContext::new_with_signer(
    ctx.accounts.share_token_program.to_account_info(),
    BurnChecked {
        mint: ctx.accounts.share_mint.to_account_info(),
        from: ctx.accounts.<share_ata>.to_account_info(),
        authority: ctx.accounts.<operator_or_liquidator>.to_account_info(),
    },
    vault_authority_signer,              // ← unnecessary
);
burn_checked(burn_ctx, shares, ctx.accounts.share_mint.decimals)?;
```

The SPL-Token program requires **only the `authority` account to sign**.
Here the authority is the operator/liquidator, who is already a transaction-signer.
Adding `vault_authority_signer`:

* Produces an extra PDA signature that the token program ignores.
* Consumes compute units each time the instruction runs.


**Recommended Mitigation:** * Build the burn context without extra signers:

  ```rust
  let burn_ctx = CpiContext::new(
      ctx.accounts.share_token_program.to_account_info(),
      BurnChecked {
          mint: ctx.accounts.share_mint.to_account_info(),
          from: ctx.accounts.<share_ata>.to_account_info(),
          authority: ctx.accounts.<operator_or_liquidator>.to_account_info(),
      },
  );
  ```

* Keep `vault_authority_signer` only for calls that truly need the PDA to sign (e.g., vault asset transfers).
This removes superfluous signatures, lowers compute costs, and avoids accidental brittleness.

**Securitize:** Fixed in [3635c15](https://github.com/securitize-io/bc-solana-vault-sc/commit/3635c15d920a3f40f75604e2bff4872f2e3f091e).

**Cyfrin:** Verified


### Lack of `mut` on `liquidation_token_mint` restricts redemption flexibility

**Description:** When firing `liquidate_handler` and the Vault is redepmtion vault. we provide the necessary liquidate account (mint, vault, token_program, ...). `liquidation_token_mint` is not market with `mut` flag.

> bc-solana-vault-sc/programs/sc-vault/src/instructions/liquidator/liquidate.rs#Liquidate
```rust
pub struct Liquidate<'info> {
    ...
    /// The mint account for the liquidation token.
    ///
    /// This account is only required when redemption program is enabled.
    /// It defines the liquidation tokens that will be received after redemption.
    #[account(
        mint::token_program = liquidation_token_program,
    )]
    pub liquidation_token_mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    ...
}
```

This will prevent Redemption program to change the `mint` program. This will prevent the redemption program to mint `liquidation_amount` for example (if the program is the authority of liquidation token), as it will need to write to the account.

If the `redemption program` has the authority of `liquidation_token_mint` and it will work by taking `assets` and mint necessary `liquidation_tokens` it can't be done using the current interface. this affects the flexibility of the redemption programs to be introduced.

**Impact:**
- Preventing redemption program to supporting minting liquidation_token

**Recommended Mitigation:**
- Mark the account with `mut` in both `Liquidate` and `redemption_interface::Redeem`

**Securitize:** Fixed in [61d4f8c](https://github.com/securitize-io/bc-solana-vault-sc/commit/61d4f8c8958ab564a1153375e362b385df575fcf).

**Cyfrin:** Verified

\clearpage