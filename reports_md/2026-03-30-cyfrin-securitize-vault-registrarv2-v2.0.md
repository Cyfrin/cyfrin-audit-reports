**Lead Auditors**

[Stalin](https://x.com/0xStalin)

[Alix40](https://x.com/AliX__40)

**Assisting Auditors**



---

# Findings
## Low Risk


### `VaultRegistrar::registerVault` uses `>=` for deadline check instead of `>`, deviating from EIP-2612 convention and design spec

**Description:** [`VaultRegistrar::registerVault`](https://github.com/securitize-io/bc-vault-registrar/blob/0867ad37a9f3479dc7c26d18e757fdb07d8620c5/VaultRegistrar/contracts/VaultRegistrar.sol#L83) checks `if (block.timestamp >= deadline)`, treating `block.timestamp == deadline` as expired. Both the EIP-2612 standard and OpenZeppelin's `ERC20Permit` use a strict `>` comparison. The project's own [design spec](https://github.com/securitize-io/bc-vault-registrar/blob/0867ad37a9f3479dc7c26d18e757fdb07d8620c5/VaultRegistrar/docs/phase1-design.md#L145) also specifies `if (block.timestamp > deadline)`.

**Impact:** The valid authorization window is one second shorter than intended. A transaction landing at exactly `block.timestamp == deadline` will revert unexpectedly. No funds at risk — only a failed transaction and minor operational inconvenience.

**Recommended Mitigation:**
```diff
- if (block.timestamp >= deadline) revert SignatureExpired();
+ if (block.timestamp > deadline) revert SignatureExpired();
```

**Securitize:** Fixed in commit [0cd08a3](https://github.com/securitize-io/bc-vault-registrar/commit/0cd08a3febe0f1905524306253ebb9715e69a9e6).

**Cyfrin:** Verified. Fixed by following the recommended mitigation.


\clearpage
## Informational


### Investor Cannot Revoke Standing Permission for a Removed Operator

**Description:** `VaultRegistrar::invalidateOperatorPermission` guards the revocation call with a check that requires the target `operator` to currently hold `OPERATOR_ROLE`:

```solidity
// VaultRegistrar.sol:162
function invalidateOperatorPermission(address operator) external notZeroAddress(operator) {
    if (!hasRole(OPERATOR_ROLE, operator)) revert NotAnOperator(operator);   // ← blocks revocation
    uint256 newNonce = ++_operatorNonces[_msgSender()][operator];
    emit OperatorPermissionInvalidated(_msgSender(), operator, newNonce);
}
```

When admin calls `removeOperator(operatorA)`, the operator loses `OPERATOR_ROLE`. Any investor who previously signed a long-lived standing permission for that operator can no longer increment their per-operator nonce, because the call reverts with `NotAnOperator`.

**Impact:** An investor's standing permission for a removed operator is permanently unrevocable until the deadline passes. If `OPERATOR_ROLE` is later re-granted to the same address (routine re-onboarding, key rotation, admin key compromise), the old, investor-unrevocable signature becomes immediately usable again — allowing the re-granted operator to register arbitrary vaults under the investor's identity within the original deadline window.

The code comment justifies the check as: *"a non-operator cannot call registerVault regardless, so revoking them has no effect."* This reasoning breaks down when the operator's role is restored: the old signature becomes valid again, and the investor has lost the ability to pre-emptively revoke consent during the intervening period.

**Proof of Concept:**
1. Admin grants `OPERATOR_ROLE` to `operatorA`
2. Alice signs a 90-day standing permission for `operatorA`
3. Day 10: `operatorA` is compromised; admin calls `removeOperator(operatorA)`
4. Day 10: Alice calls `invalidateOperatorPermission(operatorA)` → **reverts** with `NotAnOperator`
5. Day 20: Admin re-grants `OPERATOR_ROLE` to `operatorA` (after believing the situation is resolved)
6. Day 20–90: `operatorA` uses Alice's original signature to register vaults under her identity


**Recommended Mitigation:** Remove the `hasRole` check from `invalidateOperatorPermission`. An investor should always be able to increment their own nonce for any address, regardless of whether the operator holds a role:

```solidity
function invalidateOperatorPermission(address operator) external notZeroAddress(operator) {
    uint256 newNonce = ++_operatorNonces[_msgSender()][operator];
    emit OperatorPermissionInvalidated(_msgSender(), operator, newNonce);
}
```

**Securitize:** Fixed in commit [58a5856](https://github.com/securitize-io/bc-vault-registrar/commit/58a585655478b80752a58a4e2c0b2f510409aed0)

**Cyfrin:** Verified. Investor can now revoke standing permission for a removed Operator


### `VaultRegistrar::isRegistered` reverts instead of returning `false` when vault belongs to a different investor

**Description:** [`VaultRegistrar::isRegistered`](https://github.com/securitize-io/bc-vault-registrar/blob/0867ad37a9f3479dc7c26d18e757fdb07d8620c5/VaultRegistrar/contracts/VaultRegistrar.sol#L111-L129) is a view function that returns `bool`. It correctly returns `false` when the vault or investor is unregistered (empty ID), but when both have non-empty IDs that don't match, it delegates to [`_validateVaultBelongsToInvestor`](https://github.com/securitize-io/bc-vault-registrar/blob/0867ad37a9f3479dc7c26d18e757fdb07d8620c5/VaultRegistrar/contracts/VaultRegistrar.sol#L170-L178), which reverts with `VaultBelongsToDifferentInvestor` instead of returning `false`.

**Impact:** Any contract calling `isRegistered` as a boolean query will revert instead of receiving `false` when the vault is registered under a different investor. This breaks composability and can DoS downstream contracts that rely on it as a safe view check.

**Recommended Mitigation:** Replace the revert path with a `false` return:

```diff
-     _validateVaultBelongsToInvestor(vaultAddress, vaultInvestorId, investorId);
+     if (keccak256(bytes(vaultInvestorId)) != keccak256(bytes(investorId))) {
+         return false;
+     }

      return true;
```

**Securitize:** Fixed in commit [6b4a9e5](https://github.com/securitize-io/bc-vault-registrar/commit/6b4a9e5185290c4cf1ab8b5bb049a9074594f984).

**Cyfrin:** Verified. `VaultRegistrar::isRegistered` now returns false when the vault belongs to a different investor.

\clearpage