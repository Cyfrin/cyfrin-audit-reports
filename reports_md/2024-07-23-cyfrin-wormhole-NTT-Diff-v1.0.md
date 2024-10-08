**Lead Auditors**

[0kage](https://x.com/0kage_eth)

[Giovanni Di Siena](https://x.com/giovannidisiena)



**Assisting Auditors**

[Hans](https://x.com/hansfriese)

---

# Findings
## Informational


###  Incorrectly documented error selector

**Description:** The `bytes4` error selector for the `IWormholeTransceiver::TransferAlreadyCompletedError` is incorrectly documented as `0x406e719e`. The correct selector is `0xb4c3b00c`.

```solidity
    /// @notice Error when the VAA has already been consumed.
    /// @dev Selector: 0x406e719e.
    /// @param vaaHash The hash of the VAA.
    error TransferAlreadyCompleted(bytes32 vaaHash);
```

**Recommended Mitigation:** Consider updating the selector to `0xb4c3b00c`.


### Inconsistent inline documentation for errors and events

**Description:** The current codebase follows an inline documentation standard for events and errors, including parameter descriptions and `topic[0]` for events and `bytes4` selectors for errors. However, some events and errors lack either parameter descriptions, selectors, or both. This inconsistency can reduce code readability and maintainability.

Here are a few examples from `INttManager.sol`

```solidity
    /// @notice The caller is not the deployer.
    error UnexpectedDeployer(address expectedOwner, address owner);

    /// @notice Peer for the chain does not match the configuration.
    /// @param chainId ChainId of the source chain.
    /// @param peerAddress Address of the peer nttManager contract.
    error InvalidPeer(uint16 chainId, bytes32 peerAddress);

   /// @notice Peer chain ID cannot be zero.
    error InvalidPeerChainIdZero();

    /// @notice Peer cannot be the zero address.
    error InvalidPeerZeroAddress();

    /// @notice Peer cannot have zero decimals.
    error InvalidPeerDecimals();

```

**Recommended Mitigation:** Ensure consistent documentation across all event and error definitions by including parameter descriptions, `topic[0]` and `bytes4` selectors where applicable.



### Lack of events for setting inbound and outbound limits

**Description:** The `NttManager::setPeer` function sets a peer `NttManager` contract address on a foreign chain. The `inboundLimit` is now passed as an input when setting a peer contract. In the earlier implementation, inboundLimit was set to `type(uint64).max`. However, this input is missing from the `PeerUpdated` event, which does not reflect the change in the `setPeer` input parameters.

**Recommended Mitigation:** Consider including the `inboundLimit` as part of the `PeerUpdated` event to accurately reflect the parameters set by the `setPeer` function. Additionally, in the context of third party integrations, since the inbound and outbound limits might be updated multiple times for different destination chains, it is recommended to add an event emission whenever the `NttManager` owner sets the inbound or outbound limit. This will improve transparency and traceability of these parameter changes.



### Lack of indexing in `TransferSent` event

**Description:** The `INttManager::TransferSent` event is emitted when a message is sent from the `NttManager` of the source chain. The current event signature does not index the `recipient` and `refundAddress` parameters. When transfers are performed at scale, this lack of indexing might impede the searchability of transfers across chains.

**Recommended Mitigation:** Consider indexing the `recipient` and `refundAddress` parameters in the `TransferSent` event for improved searchability.


\clearpage