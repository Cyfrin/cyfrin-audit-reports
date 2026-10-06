**Lead Auditors**

[0xFlint](https://x.com/0xFlint_)

[Carrotsmuggler](https://x.com/carrotsmuggler)

**Assisting Auditors**



---

# Findings
## Medium Risk


### A deleted Classic trustline blocks controller lock of every wallet for that investor

**Description:** An investor can block their wallets from being locked by deleting the asset trustline from one empty wallet. Its stale registration causes both `lock_investor` and `remove_wallet` to revert, preventing the controller from freezing the investor or removing the blocking wallet.

[`lock_investor_after_auth`](../contracts/asset-controller/src/registry.rs#L91-L123) requires every associated wallet to be included, then updates each wallet's SAC authorization:

```rust
for wallet in wallets.iter() {
    sac.set_authorized(&wallet, &!locked);
}
investor.locked = locked;
storage::set_investor(env, investor_id, &investor);
```

For a Classic wallet with a deleted trustline, `set_authorized` fails with `TrustlineMissingError`. The entire lock rolls back, including any earlier deauthorizations, so the investor's other wallets remain authorized. The completeness check prevents omitting the affected wallet.

[`remove_wallet`](../contracts/asset-controller/src/contract.rs#L178-L195) fails for the same reason: it attempts deauthorization before deleting the stale association.

```rust
StellarAssetClient::new(&env, &storage::sac(&env)).set_authorized(&wallet, &false);
storage::remove_wallet(&env, &wallet);
storage::set_investor(&env, &investor_id, &investor);
```

Without the holder recreating the trustline, operators must work around the failed investor-wide lock by freezing the remaining live trustlines through the Classic issuer.

**Impact:** `FR-7` requires authorization revocation for sanctions, revoked KYC, and court orders—time-sensitive enforcement actions. An investor can prepare an empty wallet and delete its trustline before enforcement, causing the intended freeze to fail while their funded wallets remain usable.

The additional issuer-side coordination can give the investor meaningful time to sell or transfer tokens before the protocol stops them. The impact is delayed enforcement across the investor's wallets, not permanent loss of issuer control.

**Recommended Mitigation:** In `lock_investor` when freezing, and in `remove_wallet`, skip `set_authorized(false)` if the Classic trustline is verifiably absent.

**Securitize:** Fixed in commit [df917](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/df917b9b211b6bf537ace6c5fcd194759ca83b4e)

**Cyfrin:** Verified.

As an informational note, the `Err(Err(invoke_error))` in the code handling of `try_set_authorized` is unreachable since the SAC client uses the generic `soroban_sdk::Error` and conversion into that same error type cannot fail.


### Missing EVM seizure-destination restriction allows transfer operators to seize into self-designated custody

**Description:** The Stellar implementation removes a separation-of-duties control present in the EVM implementation: a transfer agent may execute a seizure, but the custody destination must be independently approved by an issuer or master.

On EVM, `ComplianceService::validateSeize` rejects any destination that is not an issuer-special wallet:

```solidity
require(getWalletManager().isIssuerSpecialWallet(_to), "Target wallet type error");
```

Designating a destination through `WalletManager::addIssuerWallet` requires `onlyIssuerOrAbove`. That guard explicitly permits only `ISSUER` and `MASTER`, excluding `TRANSFER_AGENT`:

```solidity
function addIssuerWallet(address _wallet) public override onlyIssuerOrAbove returns (bool) {
    return setSpecialWallet(_wallet, ISSUER);
}

modifier onlyIssuerOrAbove {
    IDSTrustService trustManager = getTrustService();
    uint8 role = trustManager.getRole(msg.sender);
    require(role == ROLE_ISSUER || role == ROLE_MASTER, "Insufficient trust level");
    _;
}
```

The transfer agent can therefore choose among approved custody destinations, but cannot register an arbitrary wallet and make it eligible for seizure.

In contrast, in the Stellar `AssetController::seize` function, any registered wallet is accepted as the seizure destination.

```rust
if storage::wallet_investor_and_extend_ttl(&env, &from).is_none()
    || storage::wallet_investor_and_extend_ttl(&env, &to).is_none()
{
    panic_with_error!(&env, AssetControllerError::WalletNotRegistered);
}

let sac = StellarAssetClient::new(&env, &storage::sac(&env));
sac.clawback(&from, &amount);
sac.mint(&to, &amount);
```

Since `TRANSFER` can also call `AssetController::register_investor` and `AssetController::add_wallet`, it can register an attacker-controlled wallet and then seize investor holdings into it without separate `ISSUER` or `MASTER` approval.

Section 2.5 of stellar-audit-request.md identifies parity with the EVM implementation as an acceptance criterion. The destination-approval restriction can also be enforced on Stellar, so its omission is an unnecessary deviation that expands the transfer operator’s authority.

**Impact:** A malicious or compromised `TRANSFER` operator can redirect investor holdings into a wallet it controls, rather than being limited to custody destinations approved by `ISSUER` or `MASTER` as in the EVM model.

Administrative clawback does not replace this preventive control: recovery requires intervention, and the attacker may move or burn the received tokens before that occurs.

**Recommended Mitigation:** Restore the EVM separation of authority by maintaining seizure-destination approval independently of investor registration. Restrict this approval to `MASTER` or `ISSUER`, and require it in `AssetController::seize` before clawback and mint. Registering a wallet must not automatically approve it as a seizure destination.

**Securitize:** Fixed in commit [8ea79](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/8ea792a63aa5964b34871c754216b8cfd0d6b446)

**Cyfrin:** Verified.


### remove/add wallet operations allow any registry operator to reassign funded wallets to another investor

**Description:** `AssetController::remove_wallet` and `AssetController::add_wallet` do not require the wallet's token balance to be zero. This allows registry operators to reassign a funded wallet to a different investor without moving its tokens or obtaining holder authorization.

In the EVM implementation, both registry operations require a zero balance, preventing reassignment of funded wallets.

```solidity
require(getToken().balanceOf(_address) == 0, "Wallet with positive balance");
```

Stellar's `AssetController::remove_wallet` deauthorizes the wallet and deletes its investor association without checking its token balance.

```rust
StellarAssetClient::new(&env, &storage::sac(&env)).set_authorized(&wallet, &false);
storage::remove_wallet(&env, &wallet);
storage::set_investor(&env, &investor_id, &investor);
```

Although the tokens remain in the wallet, `AssetController::add_wallet` checks only that the wallet is currently unregistered and the destination investor exists. It does not check the wallet's balance or previous investor association. The registry's `attach_wallet` helper applies the destination investor's lock policy and stores the new association:

```rust
sac.set_authorized(&wallet, &!investor.locked);

storage::set_wallet_investor(env, &wallet, &investor_id);
storage::set_investor(env, &investor_id, investor);
```

Both operations permit `MASTER`, `ISSUER`, `TRANSFER`, and `EXCHANGE` callers without holder authorization. Consequently, an authorized registry operator can remove and reattach a funded wallet under a different investor without moving its tokens.

**Impact:** A compromised operational key, including an `EXCHANGE` key, can reattribute multiple funded wallets to a colluding investor without moving tokens or obtaining their holders' signatures. Systems that rely on these associations for ownership accounting, distributions, redemption, voting, or compliance may recognize the wrong investor and misdirect benefits.


**Recommended Mitigation:** Require a zero token balance before removing or attaching a wallet, consistently across registration and bulk onboarding paths. Use investor lock/unlock functionality for funded wallets that require authorization changes without changing their investor association.

**Securitize:** Fixed in commit [65ec3](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/65ec33c9f5bb120df8626c3967f79aff94476aeb)

**Cyfrin:** Verified.


\clearpage
## Low Risk


### Missing EVM creator checks allow exchange operators to remove other operators' records

**Description:** The Stellar implementation omits the EVM restriction that limits `EXCHANGE` operators to only remove records that they themselves created.

In the EVM implementation, `RegistryService::removeWallet` checks the wallet record's creator:

```solidity
require(getTrustService().getRole(msg.sender) != EXCHANGE || investorsWallets[_address].creator == msg.sender, "Insufficient permissions");
```

`RegistryService::removeInvestor` applies the same restriction to the investor record:

```solidity
require(getTrustService().getRole(msg.sender) != EXCHANGE || investors[_id].creator == msg.sender, "Insufficient permissions");
```

These checks prevent one exchange from removing another operator's records without restricting the broader removal authority of `MASTER`, `ISSUER`, and `TRANSFER_AGENT`.

On Stellar, `AssetController::remove_wallet` and `AssetController::remove_investor` permit `EXCHANGE` callers but do not check who created the record. Wallet removal deauthorizes the wallet and deletes its association:

```rust
StellarAssetClient::new(&env, &storage::sac(&env)).set_authorized(&wallet, &false);
storage::remove_wallet(&env, &wallet);
storage::set_investor(&env, &investor_id, &investor);
```

Consequently, Exchange B can remove wallets registered by Exchange A or by `MASTER`, `ISSUER`, or `TRANSFER` operators. `AssetController::remove_wallet` remains available while paused. Once an investor has no associated wallets, Exchange B can also remove that investor regardless of its creator, but `AssetController::remove_investor` requires the controller to be unpaused.

Section 2.5 of `stellar-audit-request.md` identifies EVM parity as an acceptance criterion. Stellar does not prevent storing record provenance or checking it during removal; omitting these restrictions is an expansion of exchange authority.


**Impact:** A malicious or compromised exchange operator can disrupt another operator's investor registrations and deauthorize its registered wallets. Restoring those associations requires administrative intervention.

**Recommended Mitigation:** Store the creating operator separately for each investor and wallet record. When an `EXCHANGE` caller removes a record, require that caller to match the corresponding creator, preserving the EVM permissions for the other operational roles.

**Securitize:** Fixed in commits [65ec3](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/65ec33c9f5bb120df8626c3967f79aff94476aeb) and [c2471](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/c2471b0ab923c99d7421acd19e2d4e8968e895a6).

**Cyfrin:** Verified.


### Lower-privileged operators can block a MASTER-initiated admin transfer

**Description:** `AssetController::transfer_contract_admin` requires the proposed admin to have no role, and `access::accept_contract_admin` repeats that check before granting `MASTER`:

```rust
require_available_admin(env, &new_admin);
grant_role_with_event(env, &new_admin, &MASTER_ROLE, &new_admin);
revoke_role_with_event(env, &previous_admin, &MASTER_ROLE, &new_admin);
```

The availability check rejects any existing membership:

```rust
if get_role(env, account) != NONE_ROLE {
    panic_with_error!(env, AssetControllerError::RoleAlreadyAssigned);
}
```

However, ordinary role assignment does not exclude the pending recipient. An `ISSUER` can grant it `EXCHANGE`, or a `TRANSFER` can grant it `TRANSFER`, without the recipient's consent. Acceptance then fails with `RoleAlreadyAssigned`, allowing either operator to interfere with a transfer initiated by `MASTER`.

**Impact:** A malicious or compromised issuer or transfer operator can delay admin succession and repeat the interference while role assignment remains available. The old master and pending proposal remain intact, so this does not permit takeover or permanent lockout. Recovery may require pausing the controller, removing the conflicting role, and completing acceptance while paused.

**Recommended Mitigation:** Consider preventing ordinary role assignments to the recipient of an active admin-transfer proposal. Retain the acceptance-time exclusivity check so the new admin cannot acquire `MASTER` alongside an operational role.

**Securitize:** Fixed in commit [2522431]( https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/2522431632c4cca5c18a0c7ffdd3d64a33336795).

**Cyfrin:** Verified.


### Selling-liability minimums prevent reliable full-balance burn and seizure

**Description:** The controller's administrative `burn` and `seize` functions cannot be relied upon to recover a Classic account's full holding under normal operating conditions. Both use Stellar Asset Contract (SAC) clawback, which cannot reduce a G-address trustline balance below its outstanding selling liabilities. Consequently, **any positive selling liability prevents a full-balance burn or seizure**, even when the operator is authorized, the wallet is registered and clawback-enabled, and its nominal balance covers the requested amount.

The protocol controls the Classic issuer and can clear liabilities through a hard freeze, so the obstruction is not inherently unresolvable.

- Native clawback path

[`AssetController::burn`](../contracts/asset-controller/src/contract.rs#L249-L255) reaches `sac.clawback` through [`token::burn_after_auth`](../contracts/asset-controller/src/token.rs#L34-L49). [`AssetController::seize`](../contracts/asset-controller/src/contract.rs#L271-L304) uses the same debit before minting to the destination:

```rust
let sac = StellarAssetClient::new(&env, &storage::sac(&env));
sac.clawback(&from, &amount);
sac.mint(&to, &amount);
```

`StellarAssetClient` is only the SDK invocation interface. The actual implementation is built into the Soroban host. For a non-issuer G-address, the issued-asset balance is stored in its Classic trustline, so clawback must update that trustline rather than a separate contract balance:

```text
AssetController::burn / AssetController::seize
  -> native SAC::clawback
  -> spend_balance_no_authorization_check
  -> transfer_classic_balance(account, -clawback_amount)
  -> transfer_trustline_balance
  -> get_min_max_trustline_balance
  -> reject if the resulting balance is below selling liabilities
```

The native [`clawback` implementation](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs#L297-L314) authenticates the SAC administrator and then invokes the debit helper:

```rust
pub(crate) fn clawback(e: &Host, from: Address, amount: i128) -> Result<(), HostError> {
    let _span = tracy_span!("SAC clawback");
    check_nonnegative_amount(e, amount)?;
    check_clawbackable(e, from.metered_clone(e)?)?;
    check_not_issuer(e, &from)?;

    let admin = read_administrator(e)?;
    admin.require_auth()?;

    e.extend_current_contract_instance_and_code_ttl(
        INSTANCE_TTL_THRESHOLD.into(),
        INSTANCE_EXTEND_AMOUNT.into(),
    )?;

    spend_balance_no_authorization_check(e, from.metered_clone(e)?, amount)?;
    event::clawback(e, from, amount)?;
    Ok(())
}
```

The call to `spend_balance_no_authorization_check` above reaches the following [G-address branch](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs#L156-L171). It converts the requested amount to `i64` and explicitly calls `transfer_classic_balance` with a negative amount:

```rust
ScAddress::Account(acc_id) => {
    let i64_amount = i64::try_from(amount).map_err(|_| {
        e.error(
            ContractError::OverflowError.into(),
            "spent amount is too large for an i64",
            &[],
        )
    })?;
    transfer_classic_balance(e, acc_id, -i64_amount, &addr)
}
```

[`transfer_classic_balance`](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs#L376-L404) then selects the asset type. Both issued-asset branches call the local `transfer_trustline_balance_unless_issuer` closure, which forwards a non-issuer account's debit to `transfer_trustline_balance`:

```rust
pub(crate) fn transfer_classic_balance(
    e: &Host,
    to_key: AccountId,
    amount: i64,
    addr: &Address,
) -> Result<(), HostError> {
    let transfer_trustline_balance_unless_issuer =
        |asset: TrustLineAsset, issuer: AccountId, to: AccountId| -> Result<(), HostError> {
            if issuer == to {
                return Ok(());
            }

            transfer_trustline_balance(e, to, asset, amount)
        };

    match read_asset(e)? {
        Asset::Native => transfer_account_balance(e, to_key, amount, addr),
        Asset::CreditAlphanum4(asset) => {
            let issuer = asset.issuer.metered_clone(e)?;
            let tlasset = TrustLineAsset::CreditAlphanum4(asset);
            transfer_trustline_balance_unless_issuer(tlasset, issuer, to_key)
        }
        Asset::CreditAlphanum12(asset) => {
            let issuer = asset.issuer.metered_clone(e)?;
            let tlasset = TrustLineAsset::CreditAlphanum12(asset);
            transfer_trustline_balance_unless_issuer(tlasset, issuer, to_key)
        }
    }
}
```

This is the same clawback debit throughout, not a separate holder transfer. Skipping the holder's spending-authorization check does **not** skip the trustline balance constraints reached below.

- The selling-liability minimum

[`transfer_trustline_balance`](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs#L584-L628) obtains the permitted balance range and rejects a debit outside it:

```rust
let (min_balance, max_balance) = get_min_max_trustline_balance(host, &tl)?;

let Some(new_balance) = tl.balance.checked_add(amount) else {
    return Err(host.error(
        ContractError::BalanceError.into(),
        "resulting balance overflow",
        &[],
    ));
};
if new_balance >= min_balance && new_balance <= max_balance {
    tl.balance = new_balance;
    le = Host::modify_ledger_entry_data(host, &le, LedgerEntryData::Trustline(tl))?;
    storage.put(&lk, &le, None, &host, None)
} else {
    Err(err!(
        host,
        ContractError::BalanceError,
        "resulting balance is not within the allowed range",
        min_balance,
        new_balance,
        max_balance
    ))
}
```

The pivotal check is in [`get_min_max_trustline_balance`](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs#L756-L783). For a trustline with liability data, the function explicitly sets the minimum balance to its selling liabilities:

```rust
if let TrustLineEntryExt::V1(ext1) = &tl.ext {
    let min_balance = ext1.liabilities.selling;
    if tl.limit < ext1.liabilities.buying {
        return Err(e.err(
            ScErrorType::Storage,
            ScErrorCode::InternalError,
            "limit is lower than liabilities",
            &[],
        ));
    }
    let max_balance = tl.limit - ext1.liabilities.buying;
    Ok((min_balance, max_balance))
} else {
    let min_balance = 0;
    let max_balance = tl.limit;
    Ok((min_balance, max_balance))
}
```

For example, a holder with balance **100** and selling liabilities of only **1** cannot have all **100** burned or seized: the resulting balance would be zero, below the required minimum of one. If all 100 are reserved by offers, even a debit of one fails. Thus, ordinary offer placement can prevent complete recovery; the holder need not reserve its entire balance.

- Soft deauthorization does not resolve the obstruction

SAC [`set_authorized(false)`](https://github.com/stellar/rs-soroban-env/blob/57d7cfbf597dd3a6889748b1b5704a9a46796e74/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs#L878-L915) preserves existing offers and liabilities by setting the maintain-liabilities flag:

```rust
tl.flags &= !(TrustLineFlags::AuthorizedFlag as u32);
tl.flags |= TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;
```

Clearing the obstruction instead requires an issuer-authorized Classic hard freeze that clears **both** authorization flags. [`remove_wallet`](../contracts/asset-controller/src/contract.rs#L150-L175) is not a substitute: it uses soft deauthorization and also deletes the registration required by controller burn/seizure. The recovery flow must preserve registration and keep the source frozen while liabilities are cleared and the controller operation is retried.

**Impact:** Ordinary selling liabilities can prevent full-position burn or seizure, making a core recovery function dependent on additional issuer intervention. This may impose significant coordination and delays, particularly if issuer authority is separately governed.

**Recommended Mitigation:** Implement and document an operating flow for recovering holdings from every supported investor wallet with outstanding liabilities. The flow must coordinate issuer-side hard freeze and liability clearing, preserve controller registration and clawback eligibility, then execute burn or seizure without reauthorizing the source.

**Securitize:** Acknowledged. Documentation was expanded to clarify the operating procedures for the issuer path in commit [0cb8e](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/0cb8ebfac8a822cfc88066d9a255e7dc83f82c7b).

**Cyfrin:** Acknowledged.


### Unbounded investor wallet counts can exceed atomic lock and unlock transaction limits


**Description:** `AssetController::lock_investor` requires every wallet associated with an investor to be processed in one transaction. However, `add_wallet_after_auth` does not enforce a transaction-safe wallet-count limit. Repeated, individually valid onboarding calls can therefore create an investor whose complete wallet set exceeds transaction resource limits.

Splitting the list across successive calls is not supported: each invocation requires `wallets.len() == investor.wallet_count`, with every wallet unique and belonging to that investor. A resource-limit failure rolls back the entire invocation without changing the lock policy or wallet authorizations.

The queried mainnet configuration on **2026-09-16** differed from the SDK's bundled test preset:

| Per-transaction resource | Mainnet | SDK 26.1.0 test preset |
| --- | ---: | ---: |
| Footprint entries | `400` | `100` |
| Read-write entries | `200` | `50` |
| Event bytes | `16,384` | `16,384` |

If an investor has 83 wallets, the total event bytes is 16,400, exceeded the cap and causing a revert.

**Impact:** An unusually large investor wallet set can prevent normal investor-wide locking or unlocking. Creating this condition requires authorized onboarding, whether through legitimate enrollment, operator error, or collusion with an operator.

Operators can recover by removing and deauthorizing wallets individually until the remaining set fits. However, removed wallets lose their registration and eligibility for registration-dependent controller recovery.

**Recommended Mitigation:** Enforce a conservative per-investor wallet-count limit.

**Securitize:** Fixed in commit [5cb65](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/5cb65340d2d5ce111c771a88fbeb86baba4666ba)

**Cyfrin:** Verified.


### Classic claimable balances fall outside controller burn and seizure


**Description:** `AssetController::burn` and `AssetController::seize` recover tokens from wallet balances through SAC clawback. Neither function can recover tokens held in native Stellar claimable balances, leaving an issuer-side dependency in the administrative recovery workflow.

A native Stellar claimable balance is a separate ledger entry, not a wallet or trustline. For a non-issuer holder, it inherits the source trustline's clawback-enabled status when [created](https://github.com/stellar/stellar-core/blob/v27.0.0/src/transactions/CreateClaimableBalanceOpFrame.cpp#L178-L225).

Both controller recovery functions use address-based clawback. `burn` delegates to `token::burn_after_auth`, while `seize` claws back before minting to its destination:

```rust
let sac = StellarAssetClient::new(&env, &storage::sac(&env));
sac.clawback(&from, &amount);
sac.mint(&to, &amount);
```

Once tokens are held in a claimable entry, they are no longer part of the originating wallet's balance. Controller burn or seizure against that wallet therefore cannot recover them; insufficient-balance failures are correct at the SAC level but leave the intended recovery incomplete.


For entries created from clawback-enabled trustlines, recovery remains available through native [`ClawbackClaimableBalance`](https://github.com/stellar/stellar-core/blob/v27.0.0/src/transactions/ClawbackClaimableBalanceOpFrame.cpp#L37-L83). This operation requires authorization from the Classic asset issuer under its signer configuration; controller roles and SAC administrator status alone are insufficient. It destroys the **entire entry** and does not support partial recovery or transfer to a seizure destination.

**Impact:** Controller-only recovery cannot guarantee complete destruction or confiscation of affected holdings. Recovery additionally depends on identifying relevant claimable balances and obtaining Classic issuer authorization.

**Recommended Mitigation:** Maintain an issuer-authorized procedure to identify and claw back eligible claimable balances before declaring recovery complete or restoring wallet authorization.

**Securitize:** Acknowledged. Documentation was expanded to clarify the operating procedures for the issuer path in commit [0cb8e](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/0cb8ebfac8a822cfc88066d9a255e7dc83f82c7b).


**Cyfrin:** Acknowledged.

\clearpage
## Informational


### Overlapping SAC error codes can misreport controller failures

**Description:** The controller propagates native Stellar Asset Contract (SAC) errors without translating them. Some native error codes overlap with `AssetControllerError` values that describe different failure conditions:

| Code | Controller interpretation | Actual native failure |
|---|---|---|
| 10 | `WalletAlreadyRegistered` | `BalanceError` |
| 11 | `WalletNotRegistered` | `BalanceDeauthorizedError` |
| 13 | `WalletCountOverflow` | `TrustlineMissingError` |

Insufficient balance reported as duplicate registration. In `AssetController::burn`, a positive amount and a registered source pass controller validation. If the requested clawback exceeds the source's available balance, the SAC rejects it with `BalanceError`, code `10`. A client decoding this through `AssetControllerError` reports `WalletAlreadyRegistered`, incorrectly suggesting a duplicate-registration problem instead of insufficient balance.

Deauthorization reported as missing registration. In `AssetController::issue_tokens`, a registered wallet passes the registration check. If its native trustline has been independently deauthorized, SAC mint rejects it with `BalanceDeauthorizedError`, code `11`. Decoding this as `WalletNotRegistered` incorrectly reports that the association is missing, when the actual problem is native authorization.

Missing trustline reported as wallet-count overflow. In `AssetController::add_wallet`, an existing investor and an unregistered G-address can pass the registry checks and checked count increment. If that address lacks the asset's trustline, the subsequent SAC authorization call fails with `TrustlineMissingError`, code `13`. Decoding this as `WalletCountOverflow` incorrectly reports that the investor's wallet counter overflowed, even though the count check passed and the actual problem is the missing trustline.

**Impact:** Clients interpreting these native failures as controller errors can report an incorrect cause and direct operators toward unrelated recovery actions, such as registering an already-registered wallet or investigating a counter overflow when a trustline is missing. No authorization bypass or partial state change results from the ambiguity.

**Recommended Mitigation:** Translate these native failures into distinct, appropriately named controller errors at SAC call boundaries. Preserve existing public error codes and update client decoding for the translated errors.

**Securitize:** Fixed in commit [f34cc](https://github.com/securitize-io/bc-stellar-dstoken-sc/commit/f34cc80b8e7f1163a74f07f01c67c9a215b1e509)

**Cyfrin:** Verified.


### TTL renewal does not keep related controller state live


**Description:** Controller instance/code, investor records, and wallet mappings have independent lifetimes. Operations renew only selected entries, so activity involving an investor does not necessarily keep all related state live.

| Operation | Instance/code | Investor record | Wallet mappings |
|------------------------------|---------------|--------------------|-----------------------------------|
| Extend TTL | Renewed | Not renewed | Not renewed |
| Register investor / add wallet | Renewed | Renewed | New mapping only; existing siblings untouched |
| Remove wallet | Renewed | Renewed | Selected mapping deleted; siblings untouched |
| Issue / burn / seize, including batches | Renewed | Not renewed | Touched mappings renewed |
| Combined registration and issuance | Renewed | When onboarding writes it | Touched mappings renewed |
| Lock / unlock investor | Renewed | Renewed | All supplied mappings renewed; complete wallet set required |
| Registry queries / direct native transfers | Not renewed | Not renewed | Not renewed |

Consequently, a parent record can remain live while an older wallet mapping archives, or token activity can maintain a wallet mapping while its parent archives. OpenZeppelin role entries and native SAC state have separate renewal policies; controller maintenance does not cover them.

Renewal is bounded: each eligible helper call adds at most 30 ledger-days toward a 120-ledger-day target, subject to network limits. One call need not reach the target, while repeated references to a wallet can renew it more than once per transaction. Simulations and failed transactions do not commit renewal.

**Impact:** **No material security impact has been demonstrated.** Archived persistent records are recoverable, not deleted; archival does not reset registration, lock state, or authority. Properly prepared transactions can restore the required entries.

**Recommended Mitigation:** Consider renewing the parent investor alongside touched wallet mappings. Provide bounded, permissionless renewal for explicitly supplied investor/wallet keys, driven by an off-chain index, to cover inactive sibling mappings.


**Securitize:** Acknowledged.

**Cyfrin:** Acknowledged.

\clearpage