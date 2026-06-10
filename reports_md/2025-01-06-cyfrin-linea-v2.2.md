**Lead Auditors**

[Dacian](https://x.com/DevDacian)

**Assisting Auditors**

 


---

# Findings
## Medium Risk


### Operator can finalize for non-existent `finalShnarf`

**Description:** In the previous version of `LineaRollup::_finalizeBlocks` there was this check which ensured that the final shnarf was associated with a block number:
```solidity
if (
  shnarfFinalBlockNumbers[_finalizationData.finalSubmissionData.shnarf] !=
  _finalizationData.finalSubmissionData.finalBlockInData
) {
  revert FinalBlockDoesNotMatchShnarfFinalBlock(
    _finalizationData.finalSubmissionData.finalBlockInData,
    shnarfFinalBlockNumbers[_finalizationData.finalSubmissionData.shnarf]
  );
}
```

In the new version `shnarfFinalBlockNumbers` was changed to `blobShnarfExists` which links a shnarf to an effective boolean flag (though as an uint due to previous definition), and the above check was removed but no similar check was implemented.

**Impact:** An operator can finalize for non-existent `finalShnarf`.

**Recommended Mitigation:** Add an equivalent check in `LineaRollup::_finalizeBlocks` to verify that the computed `finalShnarf` exists:
```solidity
finalShnarf = _computeShnarf(
  _finalizationData.shnarfData.parentShnarf,
  _finalizationData.shnarfData.snarkHash,
  _finalizationData.shnarfData.finalStateRootHash,
  _finalizationData.shnarfData.dataEvaluationPoint,
  _finalizationData.shnarfData.dataEvaluationClaim
);

// @audit prevent finalization for non-existent final shnarf
if(blobShnarfExists[finalShnarf] == 0) revert FinalBlobNotSubmitted();
```

**Linea:** Fixed in [PR226](https://github.com/Consensys/linea-monorepo/pull/226) commit [4286bdb](https://github.com/Consensys/linea-monorepo/pull/226/commits/4286bdbd03a0d447adf60dba6d26680503c2a14f).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Operator can submit data via `LineaRollup::submitDataAsCalldata` for invalid parent shnarf

**Description:** `LineaRollup::submitBlobs` has this check to validate the parent shnarf exists:
```solidity
    if (blobShnarfExists[_parentShnarf] == 0) {
      revert ParentBlobNotSubmitted(_parentShnarf);
    }
```

But `LineaRollup::submitDataAsCalldata` has no similar check, meaning that an operator can submit data for an invalid parent shnarf by calling `submitDataAsCalldata`.

**Linea:** Fixed in [PR223](https://github.com/Consensys/linea-monorepo/pull/223) commit [8800eaa](https://github.com/Consensys/linea-monorepo/pull/223/commits/8800eaa2fd9f45b9048b29caaeee939ade01e317).

**Cyfrin:** Verified.

\clearpage
## Informational


### Use SafeCast or document assumption that unsafe downcast in `SparkeMerkleTreeVerifier::_verifyMerkleProof` can't overflow

**Description:** `SparkeMerkleTreeVerifier::_verifyMerkleProof` has added the following sanity check:
```solidity
uint32 maxAllowedIndex = uint32((2 ** _proof.length) - 1);
if (_leafIndex > maxAllowedIndex) {
  revert LeafIndexOutOfBounds(_leafIndex, maxAllowedIndex);
}
```

If `_proof.length` > 32 this would overflow as in Solidity casts don't revert but overflow.

The team has stated that _"it is based on the Merkle tree depth coming from the finalization where the length is checked against the depth. That currently is set at 5 and is unlikely to change"._

So the overflow appears to be impossible in practice, however we recommend either:

* using [SafeCast](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeCast.sol#L509-L514) to revert if an overflow did occur
* explicitly documenting the assumption that an overflow can't occur in the code

The risk with the comment approach is that in the future the related code in finalization can be changed without the dev realizing that would trigger an overflow in this place.

**Linea:** Fixed in [PR222](https://github.com/Consensys/linea-monorepo/pull/222) commits [c20b938](https://github.com/Consensys/linea-monorepo/pull/222/commits/c20b9380dd55237a6cbc65826d17c85cb68afe5b) & [77a6e99](https://github.com/Consensys/linea-monorepo/pull/222/commits/77a6e99bc4413c8e445f795a35ff8b4cddbcadb9).

**Cyfrin:** Verified.


### Mark `L1MessageManagerV1::outboxL1L2MessageStatus` as deprecated

**Description:** `L1MessageManagerV1::outboxL1L2MessageStatus` is never read or written to anymore apart from the test suite:
```
$ rg "outboxL1L2MessageStatus"
test-contracts/TestL1MessageManager.sol
31:    outboxL1L2MessageStatus[_messageHash] = OUTBOX_STATUS_SENT;
39:      uint256 existingStatus = outboxL1L2MessageStatus[messageHash];
46:        outboxL1L2MessageStatus[messageHash] = OUTBOX_STATUS_RECEIVED;

messageService/l1/v1/L1MessageManagerV1.sol
22:  mapping(bytes32 messageHash => uint256 messageStatus) public outboxL1L2MessageStatus;

test-contracts/LineaRollupV5.sol
1944:  mapping(bytes32 messageHash => uint256 messageStatus) public outboxL1L2MessageStatus;

test-contracts/LineaRollupAlphaV3.sol
2011:  mapping(bytes32 messageHash => uint256 messageStatus) public outboxL1L2MessageStatus;

tokenBridge/mocks/MessageBridgeV2/MockMessageServiceV2.sol
40:    outboxL1L2MessageStatus[messageHash] = OUTBOX_STATUS_SENT;
```

Therefore it should be marked as deprecated with a comment similar to how `LineaRollup` handles its deprecated mappings.

Similarly `L1MessageManagerV1::inboxL2L1MessageStatus` is only ever deleted from but no new mappings are inserted; ideally a comment should also indicate this.

**Linea:** Fixed in [PR256](https://github.com/Consensys/linea-monorepo/pull/256) commit [ac51e9e](https://github.com/Consensys/linea-monorepo/pull/256/commits/ac51e9e57050f1fae13f6446a890250403e74b10#diff-231d964c3a2bc0ac9159b40fa3ab1196ee50417232c63df839d83cec34250d49L19-R26).

**Cyfrin:** Verified.


### Remove comments which no longer apply

**Description:** Comments which no longer apply should be removed as they are now misleading.

File: `L1MessageServiceV1.sol`
```solidity
// @audit `claimMessage` no longer uses `_messageSender` so these comments are incorrect
   * @dev _messageSender is set temporarily when claiming and reset post. Used in sender().
   * @dev _messageSender is reset to DEFAULT_SENDER_ADDRESS to be more gas efficient.
```

File: `L1MessageService.sol`
```solidity
// @audit `_messageSender` no longer initialized as it is not used anymore by L1 Messaging
   * @dev _messageSender is initialised to a non-zero value for gas efficiency on claiming.
```

**Linea:** Fixed in [PR256](https://github.com/Consensys/linea-monorepo/pull/256) commits [ac51e9e](https://github.com/Consensys/linea-monorepo/pull/256/commits/ac51e9e57050f1fae13f6446a890250403e74b10#diff-e9f6a0c3577321e5aa88a9d7e12499c2c4819146062e33a99576971682396bb5L101-R102) & [b875723](https://github.com/Consensys/linea-monorepo/commit/b875723765ceeeccbbdf1a0a747884ad7589001e).

**Cyfrin:** Verified.


### Use named mappings in `TokenBridge` and remove obsolete comments

**Description:** `TokenBridge` should use named mappings and remove obsolete comments:
```diff
-   /// @notice mapping (chainId => nativeTokenAddress => brigedTokenAddress)
-   mapping(uint256 => mapping(address => address)) public nativeToBridgedToken;
-   /// @notice mapping (brigedTokenAddress => nativeTokenAddress)
-   mapping(address => address) public bridgedToNativeToken;

+   mapping(uint256 chainId => mapping(address native => address bridged)) public nativeToBridgedToken;
+   mapping(address bridged => address native) public bridgedToNativeToken;
```

**Linea:** Fixed in [PR256](https://github.com/Consensys/linea-monorepo/pull/256) commit [ac51e9e](https://github.com/Consensys/linea-monorepo/pull/256/commits/ac51e9e57050f1fae13f6446a890250403e74b10#diff-e5dcf44cdbba69f5a1f8fc58700577ce57caac0c15a5d5fb63e0620aeced62d4L62-R74).

**Cyfrin:** Verified.


### `L2MessageService::reinitializePauseTypesAndPermissions` should use `reinitializer(2)`

**Description:** `TokenBridge::reinitializePauseTypesAndPermissions` uses `reinitializer(2)` because:
```
export ETH_RPC_URL=mainnet_rpc
cast storage 0x051F1D88f0aF5763fB888eC4378b4D8B29ea3319 0
0x0000000000000000000000000000000000000000000000000000000000000001
export ETH_RPC_URL=linea_rpc
cast storage 0x353012dc4a9A6cF55c941bADC267f82004A8ceB9 0
0x0000000000000000000000000000000000000000000000000000000000000001
```

`LineaRollup::reinitializeLineaRollupV6` uses `reinitializer(6)` because:
```
export ETH_RPC_URL=mainnet_rpc
cast storage 0xd19d4B5d358258f05D7B411E21A1460D11B0876F 0
0x0000000000000000000000000000000000000000000000000000000000000005
```

But `L2MessageService::reinitializePauseTypesAndPermissions` uses `reinitializer(6)` even though:
```
export ETH_RPC_URL=linea_rpc
cast storage 0x508Ca82Df566dCD1B0DE8296e70a96332cD644ec 0
0x0000000000000000000000000000000000000000000000000000000000000001
```

For consistency `L2MessageService::reinitializePauseTypesAndPermissions` should use `reinitializer(2)`.

**Linea:** Fixed in [PR271](https://github.com/Consensys/linea-monorepo/pull/271) commit [53f43d3](https://github.com/Consensys/linea-monorepo/pull/271/commits/53f43d3d6f6c49556e4da49af53e5db3aa2bfa24).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Remove redundant `L2MessageManagerV1::__L2MessageManager_init` and associated constant

**Description:** `L2MessageManagerV1::__L2MessageManager_init` is no longer called by `L2MessageService::initialize` which uses the new `PermissionsManager` contract.

Hence it should be removed along with its associated constant `L1_L2_MESSAGE_SETTER_ROLE`. This constant is referenced in comments throughout the code so those should also be updated.

The test suite still contains calls to `L2MessageManagerV1::__L2MessageManager_init`; the test suite should also be updated use only the new method for initialisation.
```solidity
// output of: rg "__L2MessageManager_init"
messageService/l2/v1/L2MessageManagerV1.sol
39:  function __L2MessageManager_init(address _l1l2MessageSetter) internal onlyInitializing {

test-contracts/TestL2MessageManager.sol
32:    __L2MessageManager_init(_l1l2MessageSetter);
41:    __L2MessageManager_init(_l1l2MessageSetter);

test-contracts/L2MessageServiceLineaMainnet.sol
1620:  function __L2MessageManager_init(address _l1l2MessageSetter) internal onlyInitializing {
1992:    __L2MessageManager_init(_l1l2MessageSetter);

// output of: rg "L1_L2_MESSAGE_SETTER_ROLE"
messageService/l2/L2MessageManager.sol
26:   * @dev Only address that has the role 'L1_L2_MESSAGE_SETTER_ROLE' are allowed to call this function.
40:  ) external whenTypeNotPaused(PauseType.GENERAL) onlyRole(L1_L2_MESSAGE_SETTER_ROLE) {

messageService/l2/v1/L2MessageManagerV1.sol
18:  bytes32 public constant L1_L2_MESSAGE_SETTER_ROLE = keccak256("L1_L2_MESSAGE_SETTER_ROLE");
37:   * @param _l1l2MessageSetter The address owning the L1_L2_MESSAGE_SETTER_ROLE role.
40:    _grantRole(L1_L2_MESSAGE_SETTER_ROLE, _l1l2MessageSetter);

interfaces/l2/IL2MessageManager.sol
48:   * @dev Only address that has the role 'L1_L2_MESSAGE_SETTER_ROLE' are allowed to call this function.

test-contracts/L2MessageServiceLineaMainnet.sol
1601:  bytes32 public constant L1_L2_MESSAGE_SETTER_ROLE = keccak256("L1_L2_MESSAGE_SETTER_ROLE");
1618:   * @param _l1l2MessageSetter The address owning the L1_L2_MESSAGE_SETTER_ROLE role.
1621:    _grantRole(L1_L2_MESSAGE_SETTER_ROLE, _l1l2MessageSetter);
1626:   * @dev Only address that has the role 'L1_L2_MESSAGE_SETTER_ROLE' are allowed to call this function.
1629:  function addL1L2MessageHashes(bytes32[] calldata _messageHashes) external onlyRole(L1_L2_MESSAGE_SETTER_ROLE) {
```

**Linea:** Fixed in [PR212](https://github.com/Consensys/linea-monorepo/pull/212) commit [3b30a8a](https://github.com/Consensys/linea-monorepo/pull/212/commits/3b30a8aa083bfe77fa6e73ca3950343f250f482b).

**Cyfrin:** Verified.


### Cheaper to not cache `calldata` array length

**Description:** When an array is passed as `calldata` it is [cheaper not to cache the length](https://x.com/DevDacian/status/1791490921881903468):
```diff
// PermissionsManager::__Permissions_init
  function __Permissions_init(RoleAddress[] calldata _roleAddresses) internal onlyInitializing {
-    uint256 roleAddressesLength = _roleAddresses.length;

-    for (uint256 i; i < roleAddressesLength; i++) {
+    for (uint256 i; i < _roleAddresses.length; i++) {
```

The same applies to:
* `PauseManager::__PauseManager_init`
* `LineaRollup::submitBlobs`
* `L2MessageManager::anchorL1L2MessageHashes`

**Linea:** Fixed in [PR247](https://github.com/Consensys/linea-monorepo/pull/247) commits [8bf9d86](https://github.com/Consensys/linea-monorepo/pull/247/commits/8bf9d867bb0fa3f9f5956efa3d8e90f4e21cf4ee), [0ffc752](https://github.com/Consensys/linea-monorepo/pull/247/commits/0ffc752c126c419d67d70260065996d4ad2545b5) & commit [968b257](https://github.com/Consensys/linea-monorepo/pull/247/commits/968b25795d1323d83360cbc3be3480a861b12aac).

**Cyfrin:** Verified.


### Use named return variables to save at least 9 gas per variable

**Description:** Using [named return variables](https://x.com/DevDacian/status/1796396988659093968) saves at least 9 gas per variable; named returns are already used in some functions of the protocol but not in others:
```solidity
PauseManager.sol
136:  function isPaused(PauseType _pauseType) public view returns (bool)

l1/L1MessageManager.sol
98:  function isMessageClaimed(uint256 _messageNumber) external view returns (bool) {

l1/L1MessageService.sol
150:  function sender() external view returns (address addr) {

l2/v1/L2MessageServiceV1.sol
165:  function sender() external view returns (address) {

lib/SparseMerkleTreeVerifier.sol
32:  ) internal pure returns (bool) {

TokenBridge.sol
 function _safeName(address _token) internal view returns (string memory) {
  function _safeSymbol(address _token) internal view returns (string memory) {
  function _safeDecimals(address _token) internal view returns (uint8) {
  function _returnDataToString(bytes memory _data) internal pure returns (string memory) {
```

**Linea:** Fixed in [PR247](https://github.com/Consensys/linea-monorepo/pull/247) commit [968b257](https://github.com/Consensys/linea-monorepo/pull/247/commits/968b25795d1323d83360cbc3be3480a861b12aac).

**Cyfrin:** Verified.


### Cache storage variables to avoid multiple identical storage reads

**Description:** Cache storage variables to avoid multiple identical storage reads:

File: `TokenBridge.sol`
```solidity
// @audit use `_initializationData.sourceChainId` instead of `sourceChainId`
147:        nativeToBridgedToken[sourceChainId][_initializationData.reservedTokens[i]] = RESERVED_STATUS;

// @audit cache 'sourceChainId' from storage and use cached copy
371:        nativeToBridgedToken[sourceChainId][_nativeTokens[i]] = DEPLOYED_STATUS;
```

**Linea:** Fixed in [PR247](https://github.com/Consensys/linea-monorepo/pull/247) commit [968b257](https://github.com/Consensys/linea-monorepo/pull/247/commits/968b25795d1323d83360cbc3be3480a861b12aac#diff-e5dcf44cdbba69f5a1f8fc58700577ce57caac0c15a5d5fb63e0620aeced62d4L147-R374).

**Cyfrin:** Verified.


### Fail fast in `LineaRollup::submitBlobs` and `submitDataAsCalldata`

**Description:** `LineaRollup::submitBlobs` does a lot of processing then after the `for` loop there is this first check which ensures the computed shnarf matches the provided expected input:
```solidity
if (_finalBlobShnarf != computedShnarf) {
  revert FinalShnarfWrong(_finalBlobShnarf, computedShnarf);
}
```

If the first check did not revert, this means that `_finalBlobShnarf == computedShnarf`.

Then a second check reverts if this schnarf already exists:
```solidity
if (blobShnarfExists[computedShnarf] != 0) {
  revert DataAlreadySubmitted(computedShnarf);
}
```

But since the second check can only execute if `_finalBlobShnarf == computedShnarf`, it is much more efficient to delete the second check and put a new check at the beginning of the function like this:
```solidity
if (blobShnarfExists[_finalBlobShnarf] != 0) {
  revert DataAlreadySubmitted(_finalBlobShnarf);
}
```

Ideally the beginning of the function would have these 4 checks before doing or declaring anything else:
```solidity
  function submitBlobs(
    BlobSubmission[] calldata _blobSubmissions,
    bytes32 _parentShnarf,
    bytes32 _finalBlobShnarf
  ) external whenTypeAndGeneralNotPaused(PauseType.BLOB_SUBMISSION) onlyRole(OPERATOR_ROLE) {
    uint256 blobSubmissionLength = _blobSubmissions.length;

    if (blobSubmissionLength == 0) {
      revert BlobSubmissionDataIsMissing();
    }

    if (blobhash(blobSubmissionLength) != EMPTY_HASH) {
      revert BlobSubmissionDataEmpty(blobSubmissionLength);
    }

    if (blobShnarfExists[_parentShnarf] == 0) {
      revert ParentBlobNotSubmitted(_parentShnarf);
    }

    if (blobShnarfExists[_finalBlobShnarf] != 0) {
      revert DataAlreadySubmitted(_finalBlobShnarf);
    }

    // variable declarations and processing follow
```

The same applies in `submitDataAsCalldata`:
```solidity
  function submitDataAsCalldata(
    CompressedCalldataSubmission calldata _submission,
    bytes32 _parentShnarf,
    bytes32 _expectedShnarf
  ) external whenTypeAndGeneralNotPaused(PauseType.CALLDATA_SUBMISSION) onlyRole(OPERATOR_ROLE) {
    if (_submission.compressedData.length == 0) {
      revert EmptySubmissionData();
    }

    if (blobShnarfExists[_expectedShnarf] != 0) {
      revert DataAlreadySubmitted(_expectedShnarf);
    }

    // ...
```

**Linea:** Fixed in [PR247](https://github.com/Consensys/linea-monorepo/pull/247) commit [968b257](https://github.com/Consensys/linea-monorepo/pull/247/commits/968b25795d1323d83360cbc3be3480a861b12aac).

**Cyfrin:** Verified.

\clearpage