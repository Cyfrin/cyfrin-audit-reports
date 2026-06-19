**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Stalin](https://x.com/0xStalin)

**Assisting Auditors**



---

# Findings
## Low Risk


### Inconsistent `blockNumberDeadline` for forced transactions can lead to DoS newer forced transactions requests

**Description:** When submitting a forced transaction on L1, the contract calculates `blockNumberDeadline` using the next formula:
```solidity
    uint256 blockNumberDeadline;
    unchecked {
      /// @dev The computation uses 1s block time making block number and seconds interchangeable,
      ///      while the chain might currently differ at >1s, this gives additional inclusion time.
      blockNumberDeadline =
        currentFinalizedL2BlockNumber +
        block.timestamp -
        _lastFinalizedState.timestamp +
        L2_BLOCK_BUFFER;
    }
```

The problem is that the delta between `block.timestamp` & `_lastFinalizedState.timestamp` varies significantly depending on when the forced transaction is submitted relative to the most recent finalization.
This creates inconsistent deadlines for users:
- Just before a new block is finalized - **Longer deadline**:
`_lastFinalizedState.timestamp` is very close to `block.timestamp` → small delta → higherblockNumberDeadline (longer deadline)
- Just after a new block was finalized - **Shorter deadline**:
`_lastFinalizedState.timestamp` is significantly older than `block.timestamp` → large delta → lowerblockNumberDeadline (shorter deadline)

This means two users submitting a forced transaction at almost the same real-world time can receive very different deadlines, purely based on finalization timing luck.

The root cause of the problem stems from the fact that the formula is meant to treat block numbers and seconds interchangeably, which means, as if the block's production rate would be 1 per second, but this is not the case [in Linea, the current block rate is](https://lineascan.build/chart/blocktime) ~1 block every 2 seconds.

**Impact:** Deadline varies significantly depending on how recently a block was finalized:
- Forced tx sent right after finalization → shorter deadline
- Forced tx sent right before next finalization → longer deadline



**Proof of Concept:** The next example demonstrates the discrepancy in the deadlines. Assume the blocks are finalized every 10k seconds at a rate of 1 block every 2 seconds. (That means, during each finalization, 5k blocks will be finalized).

Current state on the rollup is as:
- `currentFinalizedL2BlockNumber` = 50_000
- `_lastFinalizedState.timestamp` = 90_000

The next finalization would update values to:
- `currentFinalizedL2BlockNumber` = 55_000
- `_lastFinalizedState.timestamp` = 100_000

Here is what happens to the deadline when a forced tx is submitted right before the next finalization occurs:

| forced tx | Approx. real time | Time since last finalized state | Finalized L2 block # | blockNumberDeadline |
|------|-------------------|---------------------------------|----------------------|---------------------|
| 1    | t ≈ 99,999 s      | ~9,999 s                        | 50,000               | **59,999**          |
| 2    | t ≈ 100,001 s     | ~1 s                            | 55,000               | **55,001**          |


This discrepancy can lead to a DoS from subsequent forced transaction requests, as the newest transaction would have a lower `blockNumberDeadline` than the last stored forced transaction; `Rollup::storeForcedTransaction` explicitly reverts execution.
```solidity
  function storeForcedTransaction(
    ...
  ) external payable virtual onlyRole(FORCED_TRANSACTION_SENDER_ROLE) {
    unchecked {
      ...

      uint256 forcedTransactionNumber = nextForcedTransactionNumber++;

    //@audit-info => deadline for previous forced tx must be beyond the block number deadline assigned for the newest forced transaction
      require(
        forcedTransactionL2BlockNumbers[forcedTransactionNumber - 1] < _blockNumberDeadline,
        ForcedTransactionExistsForBlockOrIsTooLow(_blockNumberDeadline)
      );

      forcedTransactionRollingHashes[forcedTransactionNumber] = _forcedTransactionRollingHash;
      forcedTransactionL2BlockNumbers[forcedTransactionNumber] = _blockNumberDeadline;

      ...
    }
  }

```

The table below shows the outcome of requesting forced transactions using the original example of this issue:
| Tx | Submitted `blockNumberDeadline` | Assigned `forcedTransactionNumber` | Previous deadline (index n-1) | Check (prev < new)     | Outcome  |
|----|----------------------------------|-------------------------------------|-------------------------------|------------------------|----------|
| 1  | **59,999**                       | 1                                   | 0 (default/not set)           | 0 < 59,999 → **yes**   | **Success** |
| 2  | **55,001**                       | 2                                   | 59,999                        | 59,999 < 55,001 → **no** | **Revert**  |


**Recommended Mitigation:** Consider refactoring the `blockNumberDeadline` formula to account for the actual L2 block rate.

**Linea:** Fixed in commit [8d9b0f](https://github.com/Consensys/linea-monorepo/pull/2298/changes/8d9b0f94afc0bbb7f498b068319a2f2844340544) && [05309](https://github.com/Consensys/linea-monorepo/pull/2298/changes/053093da2e7a86b99909fcbf096eb96bd8815f0a).

**Cyfrin:** Verified. The formula for calculating `blockNumberDeadline` now adjusts the elapsed time for the finalization period based on the L2 block rate. Now, the `blockNumberDeadline` is adjusted in the `ForcedTransactionGateway` to add a buffer in the edge case where the calculated `blockNumberDeadline` is lower than the last recorded deadline on the Rollup; This buffer mitigates the case when the L2 block rate production deviates from the `L2_BLOCK_DURATION_SECONDS`.

\clearpage
## Informational


### Use named mappings to explicitly denote the purpose of keys and values

**Description:** Use named mappings to explicitly denote the purpose of keys and values:
```solidity
AddressFilter.sol
15:  mapping(address => bool) internal filteredAddresses;
```

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-3eee1a32db90dd3af5aaa4b7c9cb7699d317f11a62132ac86294675e970c58f1L13-R13).

**Cyfrin:** Verified.


### Missing code to track and withdraw forced transaction fees

**Description:** When users call `ForcedTransactionGateway::submitForcedTransaction` they send the required fee as `msg.value`. This function passes the fee (`msg.value`) to `LineaRollupBase::storeForcedTransaction` but `LineaRollupBase` doesn't:
* track the total amount of received forced transaction fees
* contain a function to withdraw the fees

Consider at least tracking the total amount of received forced transaction fees and potentially adding a function to withdraw them.

**Linea:** Acknowledged; adding a withdraw function by Linea for any value (tracked or untracked) introduces questions and undue suspicion. Creating a function for this would cause more community concern than needed, so this is not really an option.

Any fees paid are ok to be "donated" to the ecosystem and provide extra cushioning or staking value. We don't expect this to be uses regularly and the amounts are mostly negligible.

The amounts can be calculated easily by using the `ForcedTransactionAdded` type events and getting the transaction value send as this is a 1:1 for the fees paid - no more, no less.

If there was ever a withdraw of this specific amount, it would go through a security council upgrade with a fixed call with the amount that can be publicly traceable.


### Remove TODO comments

**Description:** Remove TODO comments:
```solidity
rollup/LineaRollupBase.sol
124:  // TODO check the layout of these variables
```

Comparing this audit's `LineaRollup` storage layout to the previous "mixed upgrade" version using `forge inspect -R "@openzeppelin/=contracts/node_modules/@openzeppelin/" --hardhat --evm-version cancun LineaRollup storageLayout` shows that the new storage slots are appended after the previously existing `shnarfProvider` slot which is correct:
```shell
  Name                            | Type                        | Slot | Offset | Bytes
=======================================================================================
# identical
  shnarfProvider                  | contract IProvideShnarf     | 449  | 0      | 20

# new, over-write previous gap
  nextForcedTransactionNumber     | uint256                     | 450  | 0      | 32
  forcedTransactionL2BlockNumbers | mapping(uint256 => uint256) | 451  | 0      | 32
  forcedTransactionRollingHashes  | mapping(uint256 => bytes32) | 452  | 0      | 32
  forcedTransactionFeeInWei       | uint256                     | 453  | 0      | 32
  addressFilter                   | contract IAddressFilter     | 454  | 0      | 20

# pushed down 5 slots
  __gap_LineaRollup               | uint256[50]                 | 455  | 0      | 1600
  __gap_LivenessRecoveryOperator  | uint256[50]                 | 505  | 0      | 1600
```

The storage gap `LineaRollupBase::__gap_LineaRollup` has not been reduced but this appears to be safe since it is still at the end of the storage layout.

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-99ffaedf2a0a7fba64bba5cb2ae2ad8c1587960f6cf5104f3e12f67a5c7d38d8L124).

**Cyfrin:** Verified.


### Inline call to `ForcedTransactionGateway::_buildAccessList` since variable `accessList` used only once in `submitForcedTransaction`

**Description:** Inline call to `ForcedTransactionGateway::_buildAccessList` since variable `accessList` used only once in `submitForcedTransaction`:
```diff
-   LibRLP.List memory accessList = _buildAccessList(_forcedTransaction.accessList);
    LibRLP.List memory transactionFieldList = LibRLP.p();
    transactionFieldList = LibRLP.p(transactionFieldList, DESTINATION_CHAIN_ID);
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.nonce);
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.maxPriorityFeePerGas);
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.maxFeePerGas);
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.gasLimit);

    if (_forcedTransaction.to == address(0)) {
      transactionFieldList = LibRLP.p(transactionFieldList, bytes(""));
    } else {
      transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.to);
    }
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.value);
    transactionFieldList = LibRLP.p(transactionFieldList, _forcedTransaction.input);
-   transactionFieldList = LibRLP.p(transactionFieldList, accessList);
+   transactionFieldList = LibRLP.p(transactionFieldList, _buildAccessList(_forcedTransaction.accessList));
```

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-8d8766008f6ce77c606b66562a607209e5227fa45ae395a762f75d474ef17670L128-R141).

**Cyfrin:** Verified.


### In Solidity don't initialize to default values

**Description:** In Solidity don't initialize to default values:
```solidity
rollup/LineaRollupBase.sol
534:      for (uint256 i = 0; i < _filteredAddresses.length; i++) {
```

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-99ffaedf2a0a7fba64bba5cb2ae2ad8c1587960f6cf5104f3e12f67a5c7d38d8L534-R533).

**Cyfrin:** Verified.


### Incorrect natspec above `LineaRollupBase::_computePublicInput`

**Description:** Incorrect natspec above `LineaRollupBase::_computePublicInput`:
```diff
   * 0x220   l2MerkleRootsLengthLocation
-  * 0x240   l2MessagingBlocksOffsetsLengthLocation
+  * 0x240   filteredAddressesLengthLocation
+  * 0x260   l2MessagingBlocksOffsetsLengthLocation
```

Also consider changing the name convention from "...LengthLocation" to "...OffsetPointer". The values stored at those offsets are not length locations, they're offset pointers. The offset pointer indicates where in the tail to find the length-prefixed array data:
* `calldataload(add(_finalizationData, 0x240))` returns a relative byte offset (e.g., 0x2a0)
* adding that offset to `_finalizationData` gives the length location: `add(_finalizationData, 0x2a0)` → where the array length lives
* the actual array elements start at `add(_finalizationData, 0x2c0)`

So they're offset pointers that resolve to length locations, but they aren't the length locations themselves.

**Proof of Concept:** The Foundry tests are broken; to get the PoC working first remove old evm versions from `foundry.toml`:
```solidity
[profile.default]
src = 'src'
out = 'out'
libs = ['node_modules', 'lib']
cache_path  = 'cache_forge'
foundry_version = "stable"

# Test settings
match-path = 'test/foundry/*'

# Default solc compiler settings
evm_version = "osaka"
optimizer = true
optimizer_runs = 10_000
```

Then comment out the code in `contracts/test/foundry/LineaRollup.t.sol` since it no longer compiles.

Afterwards add new PoC file `contracts/test/foundry/CalldataLayoutProof.t.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";

/**
 * @title Proof that FinalizationDataV4 NatSpec comments have wrong calldata offsets.
 * @dev The NatSpec in _computePublicInput claims:
 *        0x220   l2MerkleRootsLengthLocation
 *        0x240   l2MessagingBlocksOffsetsLengthLocation
 *
 *      But the actual ABI-encoded layout is:
 *        0x220   l2MerkleRoots offset pointer
 *        0x240   filteredAddresses offset pointer        ← MISSING from NatSpec
 *        0x260   l2MessagingBlocksOffsets offset pointer  ← NatSpec says 0x240
 *
 *      This test proves it by encoding a FinalizationDataV4 struct and inspecting
 *      the raw calldata bytes at each offset.
 */

// Minimal reproduction of the struct types
struct ShnarfData {
    bytes32 parentShnarf;
    bytes32 snarkHash;
    bytes32 finalStateRootHash;
    bytes32 dataEvaluationPoint;
    bytes32 dataEvaluationClaim;
}

struct FinalizationDataV4 {
    bytes32 parentStateRootHash;                        // 0x00
    uint256 endBlockNumber;                             // 0x20
    ShnarfData shnarfData;                              // 0x40-0xc0 (5 slots inline)
    uint256 lastFinalizedTimestamp;                     // 0xe0
    uint256 finalTimestamp;                             // 0x100
    bytes32 lastFinalizedL1RollingHash;                 // 0x120
    bytes32 l1RollingHash;                              // 0x140
    uint256 lastFinalizedL1RollingHashMessageNumber;    // 0x160
    uint256 l1RollingHashMessageNumber;                 // 0x180
    uint256 l2MerkleTreesDepth;                         // 0x1a0
    uint256 lastFinalizedForcedTransactionNumber;       // 0x1c0
    uint256 finalForcedTransactionNumber;               // 0x1e0
    bytes32 lastFinalizedForcedTransactionRollingHash;  // 0x200
    bytes32[] l2MerkleRoots;                            // 0x220 offset pointer
    address[] filteredAddresses;                        // 0x240 offset pointer
    bytes l2MessagingBlocksOffsets;                     // 0x260 offset pointer
}

contract CalldataInspector {
    /// @dev We use calldata to get the exact ABI-encoded layout that
    ///      LineaRollupBase._computePublicInput operates on.
    ///
    ///      Returns the raw 32-byte words at offsets 0x220, 0x240, 0x260
    ///      within the struct's calldata encoding.
    function inspect(
        FinalizationDataV4 calldata _data
    )
        external
        pure
        returns (
            uint256 wordAt0x220,
            uint256 wordAt0x240,
            uint256 wordAt0x260,
            // Also return the actual dynamic data to prove the offset pointers
            // resolve to the correct arrays
            uint256 merkleRootsLength,
            bytes32 merkleRootsFirstElement,
            uint256 filteredAddressesLength,
            address filteredAddressesFirstElement,
            uint256 messagingOffsetsLength
        )
    {
        assembly {
            // Read the raw 32-byte words at each offset relative to _data
            wordAt0x220 := calldataload(add(_data, 0x220))
            wordAt0x240 := calldataload(add(_data, 0x240))
            wordAt0x260 := calldataload(add(_data, 0x260))

            // Dereference offset at 0x220 → should point to l2MerkleRoots
            let merkleRootsLoc := add(_data, wordAt0x220)
            merkleRootsLength := calldataload(merkleRootsLoc)
            merkleRootsFirstElement := calldataload(add(merkleRootsLoc, 0x20))

            // Dereference offset at 0x240 → should point to filteredAddresses
            let filteredLoc := add(_data, wordAt0x240)
            filteredAddressesLength := calldataload(filteredLoc)
            filteredAddressesFirstElement := calldataload(add(filteredLoc, 0x20))

            // Dereference offset at 0x260 → should point to l2MessagingBlocksOffsets
            let messagingLoc := add(_data, wordAt0x260)
            messagingOffsetsLength := calldataload(messagingLoc)
        }
    }
}

contract CalldataLayoutProofTest is Test {
    CalldataInspector inspector;

    function setUp() public {
        inspector = new CalldataInspector();
    }

    function test_finalizationDataV4_calldata_layout() public view {
        // Build a FinalizationDataV4 with recognizable sentinel values
        // in the dynamic arrays so we can verify correct dereferencing.

        bytes32[] memory merkleRoots = new bytes32[](2);
        merkleRoots[0] = bytes32(uint256(0xAAAA));
        merkleRoots[1] = bytes32(uint256(0xBBBB));

        address[] memory filtered = new address[](1);
        filtered[0] = address(0xDEAD);

        bytes memory messagingOffsets = hex"CCDD";

        FinalizationDataV4 memory data = FinalizationDataV4({
            parentStateRootHash: bytes32(uint256(1)),
            endBlockNumber: 1000,
            shnarfData: ShnarfData({
                parentShnarf: bytes32(uint256(2)),
                snarkHash: bytes32(uint256(3)),
                finalStateRootHash: bytes32(uint256(4)),
                dataEvaluationPoint: bytes32(uint256(5)),
                dataEvaluationClaim: bytes32(uint256(6))
            }),
            lastFinalizedTimestamp: 7,
            finalTimestamp: 8,
            lastFinalizedL1RollingHash: bytes32(uint256(9)),
            l1RollingHash: bytes32(uint256(10)),
            lastFinalizedL1RollingHashMessageNumber: 11,
            l1RollingHashMessageNumber: 12,
            l2MerkleTreesDepth: 5,
            lastFinalizedForcedTransactionNumber: 13,
            finalForcedTransactionNumber: 14,
            lastFinalizedForcedTransactionRollingHash: bytes32(uint256(15)),
            l2MerkleRoots: merkleRoots,
            filteredAddresses: filtered,
            l2MessagingBlocksOffsets: messagingOffsets
        });

        (
            uint256 wordAt0x220,
            uint256 wordAt0x240,
            uint256 wordAt0x260,
            uint256 merkleRootsLength,
            bytes32 merkleRootsFirstElement,
            uint256 filteredAddressesLength,
            address filteredAddressesFirstElement,
            uint256 messagingOffsetsLength
        ) = inspector.inspect(data);

        // ──────────────────────────────────────────────────────────────────
        // PROOF 1: All three offsets at 0x220, 0x240, 0x260 are DISTINCT
        //          offset pointers (not zero, not the same value).
        //
        //          If the NatSpec were correct (only 2 dynamic fields with
        //          offsets at 0x220 and 0x240), then 0x260 would be the
        //          start of the tail data, not an offset pointer.
        // ──────────────────────────────────────────────────────────────────

        assertTrue(wordAt0x220 != wordAt0x240, "0x220 and 0x240 should be different offset pointers");
        assertTrue(wordAt0x240 != wordAt0x260, "0x240 and 0x260 should be different offset pointers");
        assertTrue(wordAt0x220 != wordAt0x260, "0x220 and 0x260 should be different offset pointers");

        // Offsets should be strictly increasing (arrays laid out in order in tail)
        assertTrue(wordAt0x220 < wordAt0x240, "l2MerkleRoots offset < filteredAddresses offset");
        assertTrue(wordAt0x240 < wordAt0x260, "filteredAddresses offset < l2MessagingBlocksOffsets offset");

        // ──────────────────────────────────────────────────────────────────
        // PROOF 2: Dereferencing offset at 0x220 yields l2MerkleRoots
        // ──────────────────────────────────────────────────────────────────

        assertEq(merkleRootsLength, 2, "0x220 -> l2MerkleRoots: length should be 2");
        assertEq(merkleRootsFirstElement, bytes32(uint256(0xAAAA)), "0x220 -> l2MerkleRoots[0] should be 0xAAAA");

        // ──────────────────────────────────────────────────────────────────
        // PROOF 3: Dereferencing offset at 0x240 yields filteredAddresses
        //          THIS IS THE FIELD MISSING FROM THE NATSPEC COMMENT.
        //          The NatSpec claims 0x240 is l2MessagingBlocksOffsets.
        // ──────────────────────────────────────────────────────────────────

        assertEq(filteredAddressesLength, 1, "0x240 -> filteredAddresses: length should be 1");
        assertEq(
            filteredAddressesFirstElement,
            address(0xDEAD),
            "0x240 -> filteredAddresses[0] should be 0xDEAD (NOT messaging offsets data)"
        );

        // ──────────────────────────────────────────────────────────────────
        // PROOF 4: Dereferencing offset at 0x260 yields l2MessagingBlocksOffsets
        //          The NatSpec says this is at 0x240, but it's actually at 0x260.
        // ──────────────────────────────────────────────────────────────────

        assertEq(messagingOffsetsLength, 2, "0x260 -> l2MessagingBlocksOffsets: length should be 2 bytes");

        // ──────────────────────────────────────────────────────────────────
        // SUMMARY:
        //   NatSpec claims:  0x220 = l2MerkleRoots, 0x240 = l2MessagingBlocksOffsets
        //   Reality:         0x220 = l2MerkleRoots, 0x240 = filteredAddresses, 0x260 = l2MessagingBlocksOffsets
        //
        //   The NatSpec is missing filteredAddresses and has l2MessagingBlocksOffsets
        //   at the wrong offset.
        // ──────────────────────────────────────────────────────────────────
    }
}
```

Run with: `forge test --match-test test_finalizationDataV4_calldata_layout`

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-99ffaedf2a0a7fba64bba5cb2ae2ad8c1587960f6cf5104f3e12f67a5c7d38d8L611-R611).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Remove unused storage slots in new contracts

**Description:** Remove unused storage slots in new contracts:
```solidity
AddressFilter.sol
13:  bool public useAddressFilter = true;
```

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-3eee1a32db90dd3af5aaa4b7c9cb7699d317f11a62132ac86294675e970c58f1L13).

**Cyfrin:** Verified.


### More efficient usage of `LibRLP` in `ForcedTransactionGateway::_buildAccessList, submitForcedTransaction `

**Description:** A more efficient implementation of `ForcedTransactionGateway::_buildAccessList` avoids:
* empty initialization of `acct` (see this [comment](https://github.com/Vectorized/solady/blob/main/src/utils/LibRLP.sol#L108))
* calling `LibRLP.p()` since it does [nothing](https://github.com/Vectorized/solady/blob/main/src/utils/LibRLP.sol#L101)
```solidity
   function _buildAccessList(AccessList[] memory _accessList) internal pure returns (LibRLP.List memory list) {
    unchecked {
      // list is already zero-initialized (empty list)
      for (uint256 i; i < _accessList.length; ++i) {
        LibRLP.List memory keys;  // Empty list, no p() needed
        bytes32[] memory ks = _accessList[i].storageKeys;
        for (uint256 j; j < ks.length; ++j) {
          bytes memory b = new bytes(32);
          assembly {
            mstore(add(b, 0x20), mload(add(ks, add(0x20, shl(5, j)))))
          }
          keys = LibRLP.p(keys, b);
        }
        LibRLP.List memory acct = LibRLP.p(_accessList[i].contractAddress);  // single-arg overload
        acct = LibRLP.p(acct, keys);
        list = LibRLP.p(list, acct);
      }
    }
  }
```

The same techniques can be used in `ForcedTransactionGateway::submitForcedTransaction`:
```diff
-   LibRLP.List memory transactionFieldList = LibRLP.p();
-   transactionFieldList = LibRLP.p(transactionFieldList, DESTINATION_CHAIN_ID);
+   LibRLP.List memory transactionFieldList = LibRLP.p(DESTINATION_CHAIN_ID);
```

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-8d8766008f6ce77c606b66562a607209e5227fa45ae395a762f75d474ef17670L128-R230).

**Cyfrin:** Verified.


### Refactor to avoid two calls to `AddressFilter::addressIsFiltered`

**Description:** The intention is that the address filter will be enabled and hence every call to `ForcedTransactionGateway::submitForcedTransaction` will make two external calls to `AddressFilter::addressIsFiltered`:
```solidity
    if (useAddressFilter) {
      require(!ADDRESS_FILTER.addressIsFiltered(signer), AddressIsFiltered());
      require(!ADDRESS_FILTER.addressIsFiltered(_forcedTransaction.to), AddressIsFiltered());
    }
```

The most common case will likely be that `signer == _forcedTransaction.to` which also results in duplicate identical storage reads. This can be refactored more efficiently by:

1) Creating a function `AddressFilter::addressesAreFiltered` which takes two inputs:
```solidity
function addressesAreFiltered(address _addr1, address _addr2) external view returns (bool) {
    if (_addr1 == _addr2) {
        return filteredAddresses[_addr1];
    }
    return filteredAddresses[_addr1] || filteredAddresses[_addr2];
}
```

2) Calling this function once in `ForcedTransactionGateway::submitForcedTransaction`:
```solidity
    if (useAddressFilter)
        require(!ADDRESS_FILTER.addressesAreFiltered(signer, _forcedTransaction.to), AddressIsFiltered());
```

This solution results in only 1 external and optimizes away the duplicate identical storage read that would occur in the most common case where `signer == _forcedTransaction.to`.

**Linea:** Fixed in commit [857c4b7](https://github.com/Consensys/linea-monorepo/pull/2297/changes/857c4b76c90244bf8c5c8bd66c0f74726ce0cd6b#diff-8d8766008f6ce77c606b66562a607209e5227fa45ae395a762f75d474ef17670L161-R161) by only making the second call if `signer != _forcedTransaction.to`.

**Cyfrin:** Verified.

\clearpage