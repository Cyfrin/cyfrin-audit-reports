**Lead Auditors**

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## Informational


### Missing zero address checks in DelegationMetaSwapAdapter

**Description:** Missing zero address checks in the `constructor` and `setSwapApiSigner` functions of `DelegationMetaSwapAdapter`.

```solidity

  constructor(
        address _owner,
        address _swapApiSigner,
        IDelegationManager _delegationManager,
        IMetaSwap _metaSwap,
        address _argsEqualityCheckEnforcer
    )
        Ownable(_owner)
    {
        swapApiSigner = _swapApiSigner; //@audit missing address(0) check
        delegationManager = _delegationManager; //@audit missing address(0) check
        metaSwap = _metaSwap; //@audit missing address(0) check
        argsEqualityCheckEnforcer = _argsEqualityCheckEnforcer; //@audit missing address(0) check
        emit SwapApiSignerUpdated(_swapApiSigner);
        emit SetDelegationManager(_delegationManager);
        emit SetMetaSwap(_metaSwap);
        emit SetArgsEqualityCheckEnforcer(_argsEqualityCheckEnforcer);
    }
  function setSwapApiSigner(address _newSigner) external onlyOwner {
        swapApiSigner = _newSigner; //@audit missing address(0) check
        emit SwapApiSignerUpdated(_newSigner);
    }
```



**Recommended Mitigation:** Consider adding zero address checks.

**Metamask:** Resolved in commit [6912e73](https://github.com/MetaMask/delegation-framework/commit/6912e732e2ed65699152c6bfdb46a0ed433f1263).

**Cyfrin:** Resolved.


### Ambiguous expiration timestamp validation in `DelegationMetaSwapAdapter`

**Description:** In the DelegationMetaSwapAdapter.sol contract, the _validateSignature() method uses a "greater than" (>) comparison instead of a "greater than or equal to" (>=) comparison when validating signature expiration:

```solidity
function _validateSignature(SignatureData memory _signatureData) private view {
    if (block.timestamp > _signatureData.expiration) revert SignatureExpired();

    bytes32 messageHash_ = keccak256(abi.encodePacked(_signatureData.apiData, _signatureData.expiration));
    bytes32 ethSignedMessageHash_ = MessageHashUtils.toEthSignedMessageHash(messageHash_);

    address recoveredSigner_ = ECDSA.recover(ethSignedMessageHash_, _signatureData.signature);
    if (recoveredSigner_ != swapApiSigner) revert InvalidApiSignature();
}
```

This implementation allows signatures to remain valid at the exact moment of their expiration timestamp, which creates ambiguity in the intended security model.

**Impact:** A signature marked as expired (with an expiration timestamp equal to the current block timestamp) is still considered valid, which may be counter-intuitive and could lead to confusion.

**Recommended Mitigation:** If the current behavior is intentional, consider renaming the `expiration` field to `validUpto`. Alternatively, to make it semantically clear with the term `expiration`, consider replacing `>` with `>=`.

**Metamask:** Resolved in commit [6912e73](https://github.com/MetaMask/delegation-framework/commit/6912e732e2ed65699152c6bfdb46a0ed433f1263).

**Cyfrin:** Resolved.

\clearpage