**Lead Auditors**

[Hans](https://twitter.com/hansfriese)
**Assisting Auditors**




---

# Findings

## Medium Risk

### A signer can't cancel his signature before a deadline.

**Severity:** Medium

**Description:** After signing a signature, a signer might want to cancel it for some reason. While checking other protocols, a signer can cancel by increasing his nonce.
In this protocol, we inherit from OpenZeppelin's [Nonces](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Nonces.sol) contract and there are no ways to cancel the signature before a deadline.

**Impact:** Signers can't invalidate their signatures when they want.

**Recommended Mitigation:** Recommend adding a function like `increaseNonce()` to invalidate the past signatures.

**Client:**
Fixed by adding a base `Nonces` contract that exposes an external `useNonce()` function, enabling the caller to increment
their nonce. Commit: [`0189a1f`](https://github.com/farcasterxyz/farcaster-contracts-private/commit/0189a1fd308a5976ecdfbce2765b6d7a953eb80f)

**Cyfrin:** Verified.

### In `IdRegistry`, a recovery address might be updated unexpectedly.

**Severity:** Medium

**Description:** There are 2 functions to update a recovery address, `changeRecoveryAddress()` and `changeRecoveryAddressFor()`.
As `changeRecoveryAddress()` doesn't reset a pending signature that would be used in `changeRecoveryAddressFor()`, the below scenario would be possible.

- Alice decided to set a recovery as Bob and created a signature for that.
- But before calling `changeRecoveryAddressFor()`, Alice noticed Bob was not a perfect fit and changed the recovery address to another one by calling `changeRecoveryAddress()` directly.
- But Bob or anyone calls `changeRecoveryAddressFor()` after that and Bob can change the owner as well.

Of course, Alice could delete the signature by increasing her nonce but it's not a good approach for users to be allowed to use the previous signature.

**Impact:** A recovery address might be updated unexpectedly.

**Recommended Mitigation:** We should include the current recovery address in the recovery signature.
Then the previous signature will be invalidated automatically after changing the recovery.

**Client:**
Fixed by adding the current recovery address to `CHANGE_RECOVERY_ADDRESS_TYPEHASH`. Commit: [`7826446`](https://github.com/farcasterxyz/farcaster-contracts-private/commit/7826446c172d2038ab7b3eeb3073c3a7233061df)

**Cyfrin:** Verified.

### `IdRegistry.transfer/transferFor()` might be revoked by a recovery address.

**Severity:** Medium

**Description:** In every `fid`, there exists an owner and a recovery address, each possessing identical authority, enabling either one to modify the other.
But while transferring the `fid`, it just changes the owner and this scenario might be possible.

- Consider Bob with a `fid(owner, recovery)` intending to sell it.
- After receiving some funds, he transfers his `fid` to an honest user using `transfer()`.
- When the honest user is going to update the recovery address, Bob calls `recover()` by front running and seizes the account.
- In contrast to ERC721, a recovery address acts like an approved user for the NFT, empowered to change ownership at any moment. Notably, this authority is cleared during the [transfer](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L252) to prevent subsequent updates by any prior approvals.

**Impact:** `IdRegistry.transfer/transferFor()` might be revoked by a recovery address.

**Recommended Mitigation:** Recommend adding a function like `transferAll()` to update both `owner/recovery`.

**Client:**
Fixed by adding `transferAndChangeRecovery` and `transferAndChangeRecoveryFor` to `IdRegistry`. Commit: [`d389f9f`](https://github.com/farcasterxyz/farcaster-contracts-private/commit/d389f9f9e102ea1706f115b0aba2c7e429ba3e9a)

**Cyfrin:** Verified.

### A removal signature might be applied to the wrong `fid`.

**Severity:** Medium

**Description:** A remove signature is used to remove a key from `fidOwner` using `KeyRegistry.removeFor()`. And the signature is verified in `_verifyRemoveSig()`.

```solidity
    function _verifyRemoveSig(address fidOwner, bytes memory key, uint256 deadline, bytes memory sig) internal {
        _verifySig(
            _hashTypedDataV4(
                keccak256(abi.encode(REMOVE_TYPEHASH, fidOwner, keccak256(key), _useNonce(fidOwner), deadline))
            ),
            fidOwner,
            deadline,
            sig
        );
    }
```

But the signature doesn't specify a `fid` to remove and the below scenario would be possible.

- Alice is an owner of `fid1` and she created a removal signature to remove a `key` but it's not used yet.
- For various reasons, she became an owner of `fid2`.
- `fid2` has a `key` also but she doesn't want to remove it.
- But if anyone calls `removeFor()` with her previous signature, the `key` will be removed from `fid2` unexpectedly.

Once a key is removed, `KeyState` will be changed to `REMOVED` and anyone including the owner can't retrieve it.

**Impact:** A key remove signature might be used for an unexpected `fid`.

**Recommended Mitigation:** The removal signature should contain `fid` also to be invalidated for another `fid`.

**Client:**
Acknowledged. This is an intentional design tradeoff that makes it possible to register a fid and add a key in a single transaction, without knowing the caller's assigned fid in advance. We accept that this has the consequence described in the finding, and users should interpret key registry actions as “add key to currently owned fid.”

Nonces provide some protection against this scenario: if Alice wants to revoke her previous signature intended for `fid1`, she can increment her nonce to invalidate the signature.

**Cyfrin:** Acknowledged.

## Low Risk

### Inconsistent validation of `vaultAddr`

In `KeyManager.setVault()` and `StorageRegistry.setVault()`, there is a validation for address(0) but we don't check in the constructors.

```solidity
File: audit-farcaster\src\KeyManager.sol
123:         vault = _initialVault;
124:         emit SetVault(address(0), _initialVault);
...
211:     function setVault(address vaultAddr) external onlyOwner {
212:         if (vaultAddr == address(0)) revert InvalidAddress();
213:         emit SetVault(vault, vaultAddr);
214:         vault = vaultAddr;
215:     }
216:
```

**Client:**
After internal discussion, we’ve decided to remove payments from the `KeyGateway` altogether and rely on per-fid limits in the `KeyRegistry` for now. We’re keeping the gateway pattern in place, which gives us the ability to introduce a payment in the future if it becomes necessary.

We don't intend to redeploy the StorageRegistry with this deployment, but we will add this validation in the next version of the storage contract.

Commit: [`11e2722`](https://github.com/farcasterxyz/farcaster-contracts-private/commit/11e27223625e4c6b5f929398e015ccda740c1593)

**Cyfrin:** Acknowledged.

### Lack of validations for some admin functions

In `KeyManager.setUsdFee()` and `StorageRegistry.setPrice()`, there are no upper limits.

While the protocol owner is regarded as a trusted party, it's still kind of an inconsistent implementation because there are min/max limits for `fixedEthUsdPrice` in `StorageRegistry.setFixedEthUsdPrice()`.

```solidity
File: audit-farcaster\src\KeyManager.sol
203:     function setUsdFee(uint256 _usdFee) external onlyOwner {
204:         emit SetUsdFee(usdFee, _usdFee);
205:         usdFee = _usdFee;
206:     }

File: audit-farcaster\src\StorageRegistry.sol
716:     function setPrice(uint256 usdPrice) external onlyOwner {
717:         emit SetPrice(usdUnitPrice, usdPrice);
718:         usdUnitPrice = usdPrice;
719:     }
```

**Client:**
After internal discussion, we’ve decided to remove payments from the `KeyGateway` altogether. (See the response to 7.2.1 for more details).

We don't intend to redeploy the StorageRegistry with this deployment, but we will add this validation in the next version of the storage contract.

Commit: [`11e2722`](https://github.com/farcasterxyz/farcaster-contracts-private/commit/11e27223625e4c6b5f929398e015ccda740c1593)

**Cyfrin:** Acknowledged.