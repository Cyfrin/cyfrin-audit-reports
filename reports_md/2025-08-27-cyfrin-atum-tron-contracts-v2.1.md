**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Al-qaqa](https://x.com/Al_Qa_qa)

**Assisting Auditors**

 

---

# Findings
## Critical Risk


### `USDT` tokens on TRON used as deposits will be permanently stuck in `Escrow` contract as `Escrow::release, refund` revert due to critical bug inside USDT's `transfer` function

**Description:** The official TRON USDT token address is [given](https://tron.network/usdt) as [TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t](https://tronscan.org/#/contract/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t/code).

The relevant inheritance heirarchy is `TetherToken -> StandardTokenWithFees -> StandardToken -> BasicToken`.

There appears to be one significant bug inside `StandardTokenWithFees::transfer` which does this:
```solidity
  function transfer(address _to, uint _value) public returns (bool) {
    uint fee = calcFee(_value);
    uint sendAmount = _value.sub(fee);

    super.transfer(_to, sendAmount);
    if (fee > 0) {
      super.transfer(owner, fee);
    }
  }
```

The bug here is there is no `return` statement so this will return `false` even for successful transfers.

`TetherToken::transfer` will call this function if `deprecated == false` which is [currently the case](https://tronscan.org/#/contract/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t/code?func=Tab-read-F2). The `transferFrom` function is fine as that has the return, it is only transfer which is the problem.

**Impact:** In Atum's codebase `Escrow::release, refund` call `safeTransfer` which under-the-hood calls `IERC20::transfer`. When `token == USDT` even using `safeTransfer` this bad bug causes the successful transfer to revert due to `StandardTokenWithFees::transfer` returning `false`. This results in escrowed USDT tokens being permanently stuck inside the `Escrow` contract.

**Recommended Mitigation:** In `Escrow::release, refund` when `token == USDT` just call `usdt.transfer` and ignore the return value - this is safe as it will always revert if the transfer failed.

**Atum:**
Fixed in commit [12fb91a](https://github.com/Atum-Labs/tvm-contracts/commit/12fb91a270e3b48639bd06fdd27d56e95893c898).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### `Fulfillment::requestHash` should reference `depositId` generated inside `Escrow::deposit`

**Description:** Currently `Fulfillment::requestHash` (emitted in the `Fulfilled` event on the destination chain) references `DepositWitness::requestId`.

However this is not very useful and potentially dangerous when reconciling fulfillments to requests off-chain, since the input `DepositWitness::requestId`:
* is never stored anywhere on-chain
* may not be unique as it is an arbitrary input supplied by the `Originator`

**Recommended Mitigation:** The `Fulfilled` event should instead reference the `depositId` which is created inside `Escrow::deposit`, is always unique and is also stored on-chain.

**Atum:**
Fixed in commit [7049c6c](https://github.com/Atum-Labs/tvm-contracts/commit/7049c6cbd71c3e9b5984fa9e9da520869a09f732) for `tvm-contracts` and [3dc4563](https://github.com/Atum-Labs/evm-contracts/commit/3dc45631509cc39a8242484ecb53396c4d412293) for `evm-contracts`.

**Cyfrin:** Verified.


### Smart contract wallets using Approved Hashes are limited to one active deposit at a time

**Description:** `Escrow::deposit` generates the unique `depositId` based on the depositor's address and their signature:
```solidity
depositId = keccak256(abi.encode(depositor, signature));
```

The problem in this is that the signature is always `65/64` length for EOA wallets, but it can be with different values in case of Smart Contract Wallets.

Some Smart Contract Wallets like Safe Wallet have a concept of `Approved Hashes` where the owners of the wallet can approve a given hash, then after signing the hash it is moved to `Approved hashes` mapping or it can be approved before that.

The problem is that in order to use the Approved Hashes feature you should pass signature of zero length, so as to let the verification go through Approved Hash:
[SafeWallet::SignatureVerifierMuxer.sol#L154-L156](https://github.com/safe-global/safe-smart-account/blob/024f544092f0a9635781617a35d8c3342a76f01a/contracts/handler/extensible/SignatureVerifierMuxer.sol#L154-L156)
```solidity
    function defaultIsValidSignature(ISafe safe, bytes32 _hash, bytes memory signature) internal view returns (bytes4 magic) {
        bytes memory messageData = EIP712.encodeMessageData(
            safe.domainSeparator(),
            SAFE_MSG_TYPEHASH,
            abi.encode(keccak256(abi.encode(_hash)))
        );
        bytes32 messageHash = keccak256(messageData);
>>      if (signature.length == 0) {
            // approved hashes
>>          require(safe.signedMessages(messageHash) != 0, "Hash not approved");
        } else {
            // threshold signatures
            safe.checkSignatures(address(0), messageHash, signature);
        }
>>      magic = ERC1271.isValidSignature.selector;
    }
```

So in order for Smart Contract wallets relying on Approved Hashes, they will provide signature of zero length. In the case they have an active deposit, they will be prevented from making another deposit unless the old one gets completed (released/refunded), limited users to one active deposit.

**Impact:** Users of Smart Contract wallets using approved hashes are limited to one active deposit.

**Recommended Mitigation:** In `Escrow::deposit` also use `permit.nonce` when generating `depositId`.

**Atum:**
Acknowledged; will be fixed in a future version.

\clearpage
## Informational


### Use TRON `isContract` to determine whether an address is a contract

**Description:** TRON has a special opcode `ISCONTRACT` added in [TIP-44](https://github.com/tronprotocol/tips/blob/master/tip-44.md) for determining whether an address is a contract or not.

Use this in the permit2 fork at https://github.com/alexroan/permit2-tron/blob/main/contracts/libraries/SignatureVerification.sol#L26 doing something like:
```diff
-       if (claimedSigner.code.length == 0) {
+       if (!claimedSigner.isContract) {
```

However the existing code appears to function correctly as well so there is no significant reason to change this. `SignatureChecker::isValidSignatureNow` used by the `Escrow` contract also uses the [same code length](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol#L33).

**Atum:**
Acknowledged.


### TIP-712 requires addresses to be cast to `uint160` but `address` in TRON Solidity doesn't store the prefix so casting is unnecessary

**Description:** [TIP-712](https://github.com/tronprotocol/tips/blob/master/tip-712.md) requires addresses used in TIP-712 to be cast to `uint160`:

> * address: need to remove TRON unique prefix(0x41) and encoded as uint160
>
> The encoding of a struct instance is enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ), i.e. the concatenation of the encoded member values in the order that they appear in the type. Each encoded member value is exactly 32-byte long.
>
> It's totaly compatible with EIP-712.
>
> The only difference between TRON address and Ethereum address is that TRON address starts with a byte prefix 0x41 and uses base58 encoding, so prefix needs to be removed when the address type is processed.

However `address` in TRON Solidity is already 20 bytes without any prefix, therefore casting `address` to `uint160` wouldn't _"remove TRON unique prefix"_ - it wouldn't do anything except increase transaction costs.

**Recommended Mitigation:** * In `tvm-contracts`, the following `uint160(address)` casts can be safely removed:
```solidity
TIP712.sol
45:        return keccak256(abi.encode(typeHash, nameHash, versionHash, chainId, uint160(address(this))));
```

* In `permit2-tron`, the following `uint160(address)` casts can be safely removed:
```solidity
TIP712.sol
38:        return keccak256(abi.encode(typeHash, nameHash, chainId, uint160(address(this))));

libraries/PermitHash.sol
40:            abi.encode(_PERMIT_SINGLE_TYPEHASH, permitHash, uint160(permitSingle.spender), permitSingle.sigDeadline)
54:                uint160(permitBatch.spender),
64:                _PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissionsHash, uint160(msg.sender), permit.nonce, permit.deadline
81:                uint160(msg.sender),
97:            abi.encode(typeHash, tokenPermissionsHash, uint160(msg.sender), permit.nonce, permit.deadline, witness)
120:                uint160(msg.sender),
132:                _PERMIT_DETAILS_TYPEHASH, uint160(details.token), details.amount, details.expiration, details.nonce
143:        return keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, uint160(permitted.token), permitted.amount));
```

The only time a `uint160` cast makes sense is if an address is passed as external input using `bytes` or `uint256` and it also contains the `TRON` prefix.

**Atum:**
Fixed in commit [e0b9ce3](https://github.com/alexroan/permit2-tron/commit/e0b9ce3163443013cf83027ca58457c80e8dc86c) for `permit2-tron` and commit [0772f28](https://github.com/Atum-Labs/tvm-contracts/commit/0772f285435f65900b74cd8b9cbc6cddec079dbd) for `tvm-contracts`.

**Cyfrin:** Verified.


### Incorrect description of `depositId` generation in `IEscrow`

**Description:** In `IEscrow.sol` file, it is mentioned that `depositId` is generated as the keccak256(signature), and this is incorrect. the depositId is generated using both `depositor` address and the `signature`

[IEscrow.sol#L207](https://github.com/Atum-Labs/tvm-contracts/blob/main/1-tvm-contracts/contracts/IEscrow.sol#L207)
```solidity
    /// @notice Deposit tokens into the escrow using Permit2 signature
>>  /// @dev The returned depositId is generated as keccak256(signature) and must be used for all subsequent operations
    /// @param permit Permit2 permit structure containing token, amount, nonce, and deadline
    /// @param depositor Address that owns the tokens and signed the permit
    /// @param witness Contains requestId (user reference) and authorized reserver/releaser addresses
    /// @param signature EIP-712 signature from depositor authorizing the transfer
    /// @return depositId Unique identifier for this deposit (keccak256(signature)) - use for reserve/release/refund
    function deposit( ... )
```


[Escrow.sol#L100-L102](https://github.com/Atum-Labs/tvm-contracts/blob/main/1-tvm-contracts/contracts/Escrow.sol#L100-L102)
```solidity
    function deposit( ... ) external whenNotPaused returns (bytes32 depositId) {
        ...

        // Generate a deposit ID from the depositor and signature
        // This prevents griefing attacks where a malicious depositor can use the signature of a legitimate deposit
>>      depositId = keccak256(abi.encode(depositor, signature));
        ...
    }
```

**Impact:**
- Incorrect docs leading to error in description of how the contract works

**Proof of Concept:** **Recommended Mitigation:**
correct the mistake by making it `generated as keccak256(depositor, signature)`

```diff
diff --git a/1-tvm-contracts/contracts/IEscrow.sol b/1-tvm-contracts/contracts/IEscrow.sol
index 914559a..9d21d99 100644
--- a/1-tvm-contracts/contracts/IEscrow.sol
+++ b/1-tvm-contracts/contracts/IEscrow.sol
@@ -204,7 +204,7 @@ interface IEscrow {
     // Core Functions

     /// @notice Deposit tokens into the escrow using Permit2 signature
-    /// @dev The returned depositId is generated as keccak256(signature) and must be used for all subsequent operations
+    /// @dev The returned depositId is generated as keccak256(depositor, signature) and must be used for all subsequent operations
     /// @param permit Permit2 permit structure containing token, amount, nonce, and deadline
     /// @param depositor Address that owns the tokens and signed the permit
     /// @param witness Contains requestId (user reference) and authorized reserver/releaser addresses
```

**Atum:**
Fixed in commit [0772f28](https://github.com/Atum-Labs/tvm-contracts/commit/0772f285435f65900b74cd8b9cbc6cddec079dbd) for `tvm-contracts` and [f668872](https://github.com/Atum-Labs/evm-contracts/commit/f668872b0aa6b8724eff0c03af5a45bc66788067) for `evm-contracts`.

**Cyfrin:** Verified.

\clearpage