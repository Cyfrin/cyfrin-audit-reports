**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[Chinmay](https://x.com/dev_chinmayf)


---

# Findings
## Informational


### Mismatched total supply cap between L1 and L2 tokens

**Description:** OpenZeppelin’s [`ERC20VotesUpgradeable`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.4/contracts/token/ERC20/extensions/ERC20VotesUpgradeable.sol#L45-L47) enforces:

```solidity
function _maxSupply() internal view virtual returns (uint256) {
    return type(uint208).max;
}
```
to keep vote‑checkpoint values within 208 bits. As a result, any L1 total supply above `2^208 − 1` would be valid on L1, as the standard ERC20 implementation uses `type(uint256).max`, but invalid on L2. However, since `type(uint208).max` is astronomically larger than any realistic token issuance, this is extremely unlikely in practice.

If strict symmetry is preferred, consider enforcing the same `uint208` cap on L1, via [`ERC20CappedUpgradeable`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.4/contracts/token/ERC20/extensions/ERC20CappedUpgradeable.sol) or a manual `require(totalSupply() + mintAmount <= type(uint208).max)` in `mint()`, so both chains’ supply limits are aligned.

**Linea:** Acknowledged.


### Parameter name mismatch between L2LineaToken interface and implementation

**Description:** There is a discrepancy in parameter naming between the [`IL2LineaToken::syncTotalSupplyFromL1`](https://github.com/Consensys/audit-2025-07-linea-tokens/blob/44640f0965a5c7465b99769a5d241a9a1cb3a2ef/src/L2/interfaces/IL2LineaToken.sol#L38) interface and its implementation, [`L2LineaToken::syncTotalSupplyFromL1`](https://github.com/Consensys/audit-2025-07-linea-tokens/blob/44640f0965a5c7465b99769a5d241a9a1cb3a2ef/src/L2/L2LineaToken.sol#L104). The interface uses the names (`_l1BlockTimestamp`, `_l1TotalSupply`), whereas the implementation employs more verbose names (`_l1LineaTokenTotalSupplySyncTime`, `_l1LineaTokenSupply`) that mirror the contract’s state variables. This mismatch in wording can lead to confusion when reading documentation or generating bindings, even though the ABI remains compatible.

Consider using `_l1LineaTokenTotalSupplySyncTime` and `_l1LineaTokenSupply` in both the interface and its NatSpec comments so they align with the implementation’s state fields and maintain clear, consistent documentation.


**Linea:** Fixed in [PR#17](https://github.com/Consensys/linea-tokens/pull/17), commit [`1296069`](https://github.com/Consensys/linea-tokens/pull/17/commits/1296069ed398e72d9a57f71a02b2ee93fbbc5e47)

**Cyfrin:** Verified. Parameters now renamed in interface and corresponding nat-spec.


### Prevent accidental ownership and admin renouncement

**Description:** The inherited `renounceOwnership()` and `AccessControlUpgradeable`’s `renounceRole(DEFAULT_ADMIN_ROLE, msg.sender)` both allow the last authority to remove themselves, potentially leaving the contract permanently ownerless or admin‑less—blocking critical functions like `withdraw()` or role‑protected operations.

Consider override `renounceOwnership()` in `TokenAirdrop` to always revert, and similarly override `renounceRole` to prevent `DEFAULT_ADMIN_ROLE` from being renounced.

**Linea:** Fixed in [PR#19](https://github.com/Consensys/linea-tokens/pull/19), commits [`babc8ca`](https://github.com/Consensys/linea-tokens/pull/19/commits/babc8ca99fe0ee7b69e53cbc0b48a3e31b9778e6) and [`a302e77`](https://github.com/Consensys/linea-tokens/pull/19/commits/a302e77baee0061f4d44b9805c751aea5fcd9098)

**Cyfrin:** Verified. `renounceOwnership` overriden and reverts.


### Consider implementing emergency pause mechanism for user facing calls

**Description:** Both `TokenAirdrop` and `LineaToken` expose critical operations that, once live, cannot be halted in the event of an unforeseen bug or exploit:

* `TokenAirdrop::claim`
  Without a pausable guard, any mis‑calculation or malicious behavior in the “factor” tokens (e.g. a faulty `balanceOf` or overflow/rounding exploit) could irreversibly drain or lock the airdrop pool.


* `LineaToken::syncTotalSupplyToL2`
  This function bridges on‑chain state to L2. If an L2 upgrade introduces a bug, or the message service changes fee semantics, repeated calls could fail or corrupt cross‑chain state without any ability to stop them.

Consider integrating OpenZeppelin’s `Pausable` (`Upgradeable`) so that the owner/admin can halt pause the contracts in case of any critical issues.

**Linea:** Acknowledged. This is intentional to provide users access to their tokens at all times.


### Unused AccessControl in `L2LineaToken`

**Description:** `L2LineaToken` inherits `AccessControlUpgradeable` and grants `DEFAULT_ADMIN_ROLE` on initialization, but none of its functions (`mint`, `burn`, `syncTotalSupplyFromL1`) are protected by role checks. As a result, the AccessControl machinery isn’t actually enforcing any permissions. Consider removing `AccessControlUpgradeable`.

**Linea:** Acknowledged. Intentionally left in so that it is not forgotten in the future.

\clearpage