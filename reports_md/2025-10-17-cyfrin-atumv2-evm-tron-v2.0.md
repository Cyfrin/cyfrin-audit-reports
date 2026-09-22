**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Jorge](https://x.com/TamayoNft)

**Assisting Auditors**



---

# Findings
## Informational


### Batch functions should revert on empty arrays

**Description:** The newly added batch functions `Escrow::depositMany, releaseMany, refundMany` and `FulfillmentProxy::fulfillMany` should revert when their input arrays are empty; the current implementations will emit empty non-sensical events.

**Atum:**
Acknowledged; prefer lower gas costs by not including empty array checks.


### Don't initialize to default values in Solidity

**Description:** Don't initialize to default values in Solidity:
```solidity
FulfillmentProxy.sol
23:        for (uint256 i = 0; i < params.length; i++) {
```

**Atum:**
Fixed in commit [f899054](https://github.com/Atum-Labs/evm-contracts/commit/f899054ef1b970cac20ff068f5bda2b15aca3e69) for EVM and [ee83857](https://github.com/Atum-Labs/tvm-contracts/commit/ee83857255f982c019f996b3b5b8b08d6e733ada) for TRON.

**Cyfrin:** Verified.


### Events emitted using `indexed` structs can be harder to query than using simple types

**Description:** In Atum V1 events were emitted using `indexed` simple types eg:
```solidity
    event Deposited(
        bytes32 indexed requestId,
        bytes32 indexed depositId,
        address indexed depositor,
        address reserver,
        address releaser,
        IERC20 token,
        uint256 amount
    );
```

This made is very easy to query for all deposits belonging to a given `depositor` address.

But in Atum V2 events are now emitted using `indexed` structs:
```solidity
    event Deposited(
        bytes32 indexed depositId, DepositWitness indexed depositWitness, ReserveWitness indexed reserveWitness
    );
```

Now it is much harder to query for all deposits belonging to a given `depositor` address, since when a struct is marked as indexed, it is treated as a complex type. The topic (used for filtering) stores the Keccak-256 hash of a special in-place encoding of the entire struct (concatenation of its members' encodings, padded to multiples of 32 bytes).

To query, you must know the exact values of all fields in the struct to compute the matching hash and filter by it. Partial matches (e.g., filtering by just one field) are impossible using the topic alone—you'd need to fetch broader logs and filter off-chain, which is less efficient.

Consider "unpacking" structs when emitting events and indexing the most important individual basic fields used in queries.

**Atum:**
Acknowledged.

\clearpage