**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[JesJupyter](https://x.com/jesjupyter)

[Ctrus](https://x.com/ctrusonchain)
**Assisting Auditors**



---

# Findings
## Medium Risk


### Escrow ATA Balance Mismatch Enables Fee Bypass, Limit Bypass, and Accounting Inconsistency


**Description:** Background: This behavior stems from the fix for **C-01** (donation-attack DOS on `close_account`). At the time of that fix, fees were not yet implemented, so using `escrow_ata.amount` as the gross and draining the entire balance was fully correct in the previous version of the codebase. The issue only surfaced after fees were introduced, which changed the assumptions under which the original fix was designed: the fee split now relies on a snapshotted `deposit.fee_amount` while the `gross` is dynamic, creating a mismatch.

The `release` instruction uses `ctx.accounts.escrow_ata.amount` (current ATA balance) as `gross` to prevent donation-attack DOS on close_account (C-01 fix in previous audit).

```rust
    // 3. Fee split calculation
    let gross = ctx.accounts.escrow_ata.amount;
    let fee = deposit.fee_amount;

    require!(gross >= fee, ErrorCode::InsufficientEscrowBalanceForFee);

    let net = gross.checked_sub(fee).unwrap();
```
At `deposit` time, the fee is computed and stored in `deposit.fee_amount`:

```rust
let fee_amount = compute_fee(
        amount,
        mint_decimals,
        mint_fee_config.fee_percentage_6,
        mint_fee_config.min_fee_6,
        mint_fee_config.max_fee_6,
    )?;
```

At release time, `gross` is taken from the current escrow ATA balance, while `fee` remains the snapshotted value:

```rust
// 3. Fee split calculation
    let gross = ctx.accounts.escrow_ata.amount;
    let fee = deposit.fee_amount;

    require!(gross >= fee, ErrorCode::InsufficientEscrowBalanceForFee);

    let net = gross.checked_sub(fee).unwrap();
```

However, there is no guarantee that the escrow ATA balance equals the original `deposit.amount`. Because SPL token accounts accept incoming transfers from anyone, the balance can be altered before release.

- Attack Scenario 1: Same User (Depositor) Donation

1. Depositor creates a deposit of 100 tokens. Fee is computed as 5 (5%), stored in `deposit.fee_amount`. `remaining_capacity` and `max_transfer_size` are enforced (e.g., max 100).
2. Before release, the depositor sends 50 additional tokens directly to the escrow ATA via a normal SPL transfer.
3. On release: `gross = 150`, `fee = 5`, `net = 145`.
4. Recipient receives 145; treasury receives 5.

Leading to:

- **Fee bypass:** Effective fee rate = 5/150 ≈ 3.33% instead of 5%. Protocol revenue is diluted.
- **Limit bypass:** `max_transfer_size` and `remaining_capacity` were enforced only at deposit. The effective payment is 150, exceeding the intended limits.
- **Payment flexibility:** The depositor can change the payment amount at any time before release by donating more tokens.

- Attack Scenario 2: Third-Party Donation (Grief / Inconsistency)

1. User A deposits 100 tokens for a recipient. Off-chain payment system expects recipient to receive `net = 95` (100 − 5 fee).
2. User B (or any address) sends 1 token to the escrow ATA.
3. On release: `gross = 101`, `fee = 5`, `net = 96`.
4. Recipient receives 96 instead of the expected 95.

Leading to:

- **Accounting inconsistency:** Off-chain systems that track expected amounts will mismatch on-chain results. Integrations that assume `net == deposit.amount - deposit.fee_amount` will break.

**Impact:**
1. **Protocol revenue loss:** Depositors can reduce effective fee rate by donating extra tokens.
2. **Invariant violation:** `max_transfer_size` and `remaining_capacity` can be circumvented.
3. **Integration risk:** Off-chain systems that assume deterministic `net` from `deposit.amount` and `deposit.fee_amount` will see incorrect amounts.
4. **Unpredictable payments:** Payment amount can be changed by anyone before release, undermining predictability for recipients and integrators.

**Recommended Mitigation:**
- Store the `fee_rate` and apply it during actual release on `gross`.
- And add intended `deposit.amount`  into the `Released` event.

**Atum:** Fixed in [b4c128e](https://github.com/Atum-Labs/solana-escrow/commit/b4c128e78d8b91112a242b652cfb8b8f4ee0e736).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Signatures Lack Cluster and Program Binding, Enabling Cross-Cluster and Cross-Program Replay

**Description:** `compute_deposit_hash` builds the signed message without cluster or program context:

```rust
    // 4. Signature Verification
    let message = compute_deposit_hash(
        payment_id,
        delegate.authority,
        delegate.allowed_mint,
        amount,
        reserver,
        releaser,
        nonce,
        issued_at,
        deadline,
    );
```

The deposit (and derived reserve/release/refund) signatures do not include cluster-specific data or the program ID. This allows:
- Cross-cluster replay: A signature created for Devnet/Testnet to be replayed on Mainnet.

1. User signs a deposit on Devnet for testing.
2. Attacker captures the Ed25519 instruction and signature.
3. Attacker submits the same instruction on Mainnet.
4. Mainnet replay bucket has not seen this nonce, so the replay check passes.
5. If delegate, ATA, and other accounts exist on Mainnet, the deposit succeeds and real funds are moved.

- Cross-program replay: A signature to be replayed on a forked program instance with a different program ID. If the user happens to interact with both programs, the signature could be replyed.


**Impact:** Cross-cluster: Users testing on Devnet/Testnet can have their signatures replayed on Mainnet, leading to unintended deposits and fund movement.
Cross-program: Signatures can be replayed on fork instances

**Recommended Mitigation:**
1. Include `program_id` in the signed message
2. Add a `cluster_id` (or similar) to the signed message.

**Atum:** Fixed in [b4c128e](https://github.com/Atum-Labs/solana-escrow/commit/b4c128e78d8b91112a242b652cfb8b8f4ee0e736).

**Cyfrin:** Verified.


### Missing mint validation in `CreateDelegate`

**Description:** The CreateDelegate instruction creates an `EscrowDelegate` account and approves token delegation without verifying that the mint is on the protocol's allowlist (i.e., that a `MintFeeConfig` PDA exists for the mint).

In contrast, the `deposit` function in `escrow.rs` does validate the mint allowlist:
```rust
// In deposit handler:
let mint_fee_config_info = &ctx.accounts.mint_fee_config;
require!(
    !mint_fee_config_info.data_is_empty(),
    ErrorCode::MintNotAllowed
);
```
This means users can create delegate accounts for mints that are not allowed by the protocol. When they later attempt to deposit using this delegate, the transaction will fail with `MintNotAllowed`, but the rent paid for the `EscrowDelegate` account (128 bytes) has already been spent.

**Impact:** Users pay rent to create accounts that are immediately unusable if the mint is not allowlisted.

**Recommended Mitigation:** Add a `MintFeeConfig` account check to the `CreateDelegate` instruction to ensure the mint is on the allowlist before creating the delegate

**Atum:** Fixed in [b4c128e](https://github.com/Atum-Labs/solana-escrow/commit/b4c128e78d8b91112a242b652cfb8b8f4ee0e736).

**Cyfrin:** Verified.


### `Fulfillment` Proxy Does Not Support Token-2022 TransferHook Extension

**Description:** The escrow program correctly forwards `remaining_accounts` in all token transfer CPI calls:

```rust
    token::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.authority_ata.to_account_info(),
                to: ctx.accounts.escrow_ata.to_account_info(),
                authority: ctx.accounts.escrow_delegate.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
            },
            signer_seeds,
        )
        .with_remaining_accounts(ctx.remaining_accounts.to_vec()),
        amount,
        decimals,
    )?;
```

The same pattern is used in `release`and `refund`.

The `fulfillment_proxy` program performs token transfers **without** forwarding `remaining_accounts`:

```rust
    token::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.from_ata.to_account_info(),
                to: ctx.accounts.to_ata.to_account_info(),
                authority: ctx.accounts.settler.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;
```

The `strict_fulfill` instruction (lines 61–74) has the same omission. Even if the client passes TransferHook accounts as remaining accounts, they are ignored because the program does not call `.with_remaining_accounts(ctx.remaining_accounts.to_vec())`.

**Impact:**
- Users cannot fulfill payments using Token-2022 tokens with TransferHook. The transfer CPI will fail.
- Escrow supports `TransferHook` but `fulfillment_proxy` does not.

**Recommended Mitigation:** Add `.with_remaining_accounts(ctx.remaining_accounts.to_vec())` to `transfer_checked` CPI calls.

**Atum:** Fixed in [b4c128e](https://github.com/Atum-Labs/solana-escrow/commit/b4c128e78d8b91112a242b652cfb8b8f4ee0e736).

**Cyfrin:** Verified.

\clearpage
## Informational


### Unused Error Variants in Escrow Program

**Description:** Several error variants are defined in the escrow program’s `ErrorCode` enum but are never used in the codebase. For example:
```rust
    #[msg("Deposit with this ID already exists")]
    DepositAlreadyExists,
    #[msg("Deposit not found")]
    DepositNotFound,
    #[msg("Deposit has already been released")]
    DepositAlreadyReleased,
    #[msg("Deposit has already been refunded")]
    DepositAlreadyRefunded,
```

The program never reaches a point where it could return these custom errors.


**Impact:** Unused enum variants add noise and can suggest to future readers that explicit checks exist when they do not. Removing them (or wiring them to explicit checks for clearer client errors) would simplify the codebase.

**Recommended Mitigation:** Remove the four unused error variants. If the team wants more descriptive client-facing errors, add explicit `require!` checks that return these errors.

**Atum:** Fixed in [b4c128e](https://github.com/Atum-Labs/solana-escrow/commit/b4c128e78d8b91112a242b652cfb8b8f4ee0e736).

**Cyfrin:** Verified.

\clearpage