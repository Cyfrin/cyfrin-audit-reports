**Lead Auditors**

[DadeKuma](https://x.com/DadeKuma)

[Naman](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## Informational


### Unnecessary use of `emit_cpi!` increases CU cost

**Description:** The `whitelist` instruction uses [`emit_cpi!`](https://github.com/securitize-io/bc-solana-whitelist-sc/blob/main/programs/dstoken-whitelist/src/instructions/whitelist.rs#L247) and the `#[event_cpi]` attribute to emit the `Whitelisted` event.

The `emit_cpi!` macro is designed for programs that are called via CPI and need their events to propagate to calling programs.

However, the `dstoken-whitelist` program is intended to be called directly by end users, not invoked via CPI by other programs.

**Impact:** Using `emit_cpi!` when unnecessary adds complexity without providing any benefit:
- Increases transaction size and CU cost
- It's currently [not possible](https://www.anchor-lang.com/docs/features/events#:~:text=Currently%2C%20event%20data%20emitted%20through%20CPIs%20cannot%20be%20directly%20subscribed%20to.%20To%20access%20this%20data%2C%20you%20must%20fetch%20the%20complete%20transaction%20data%20and%20manually%20decode%20the%20event%20information%20from%20the%20instruction%20data%20of%20the%20CPI.) to directly subscribe to these events
- Requires additional event authority accounts to be passed in the instruction

**Recommended Mitigation:** Consider replacing `emit_cpi!` with `emit!`, and removing the `#[event_cpi]` attribute.

**Securitize:** Here is the fix: https://github.com/securitize-io/bc-solana-whitelist-sc/commit/2a83f4e3f518c9d0801b24d900be56240bd7da31

**Cyfrin:** Verified.


### Transaction size limit could be exceeded with non-empty hashes

**Description:** The `whitelist` instruction accepts variable-length strings (`investor_id`, `collision_hash`, `proof_hash`) that are encoded in CPI data buffers.

Solana enforces a 1,232-byte transaction size limit, which might limit the whitelisting feature in some edge cases.

**Impact:** The production configuration uses empty strings for `collision_hash` and `proof_hash`, which keeps transaction sizes below the 1,232-byte limit.

However, if non-empty hashes are used in the future, the transaction size could exceed the limit when adding 5 or more levels in a single transaction, causing the transaction to fail.

**Proof of Concept:** With the configuration using empty hashes, the `whitelist` instruction maintains a safety margin below the 1,232-byte transaction limit:

| Levels | Transaction Size | Margin | Status |
|--------|------------------|--------|--------|
| 2 | 994 bytes | 238 bytes | Safe |
| 3 | 1,016 bytes | 216 bytes | Safe |
| 5 | 1,060 bytes | 172 bytes | Safe |

For comparison, if non-empty 32-character hashes were used, the transaction would revert with 5 or more levels:

| Levels | Transaction Size | Margin | Status |
|--------|------------------|--------|--------|
| 2 | 1,098 bytes | 134 bytes | Safe |
| 3 | 1,143 bytes | 89 bytes | Safe |
| 5 | 1,233 bytes | -1 byte | Exceeds limit |

The development team confirmed that production will use empty strings for `collision_hash` and all `proof_hash` values. The validation `rbac_utils::is_valid_hash` accepts empty strings as valid:

```rust
pub fn is_valid_hash(hash: &str) -> bool {
     hash.is_ascii() && hash.len() <= 32
}
```

**Recommended Mitigation:** No mitigation required for the current configuration, but consider documenting this behavior.

If future requirements change to use non-empty hashes with 5 or more levels, the function would need to be split into separate transactions to avoid reverting.

**Securitize:** Acknowledged.

\clearpage