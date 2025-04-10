**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Hans](https://x.com/hansfriese)

**Assisting Auditors**



---

# Findings
## Low Risk


### Forcing CCIP native fee payment results in 10 percent higher costs for `LINK` holders

**Description:** CCIP allows users to pay using either `LINK` or native gas token. By hard-coding `EVM2AnyMessage::feeToken = address(0)` the protocol forces all users to pay using the native gas token.

This results in [higher costs](https://docs.chain.link/ccip/billing#network-fee-table) for `LINK` holders as CCIP offers a 10% discount for paying using `LINK`, though this does simplify the protocol implementation.

**Matrixdock:** Acknowledged.


### Users can use transfer and bridging to evade having their tokens frozen via the blocklist

**Description:** One unconventional application of regular transfers or cross-chain transfers via CCIP / LayerZero bridging is to evade the blocklist:
* user sees operator call to `MToken::addToBlockedList` in mempool which would block their address
* user front-runs this transaction by a normal transfer or a CCIP / LayerZero cross-chain transfer to bridge their tokens to a new `receiver` address on another chain
* if the operator attempts to call `MToken::addToBlockedList` on the other chain for the new `receiver` address, the user can bridge back to another new address again

To prevent this the operator can:
* pause bridging (pausing has been implemented for LayerZero but not CCIP) prior to calling `MToken::addToBlockedList`
* use a service such as [flashbots](https://www.flashbots.net/) when calling `MToken::addToBlockedList` so the transaction is not exposed in a public mempool

**Matrixdock:** Acknowledged.


### Missing `receive` function to reject direct ETH transfers in messager contracts

**Description:** The messager contracts (`MTokenMessager`, `MTokenMessagerLZ`, `MTokenMessagerV2`) are designed to receive the bridging fee in native token but none of them implemented a `receive()` function to handle direct ETH transfers. Without this function, users can accidentally send ETH to the contract address where it will be permanently locked since there's no mechanism to withdraw it.

**Recommended Mitigation:** Add a `receive()` function that reverts to explicitly reject any direct ETH transfers to the contract:

```diff
3 contract MTokenMessagerBase {
4
5     address public ccipClient;//@audit-info MToken
6
7     constructor(address _ccipClient){
8         ccipClient = _ccipClient;
9     }
+
+     receive() external payable {
+         revert("ETH transfers not accepted");
+     }
10 }
```

**Matrixdock:** Acknowledged.



### Cross-chain blocked recipients aren't properly handled

**Description:** The `MToken` contract implements a blocking mechanism to prevent certain addresses from interacting with the token. However, the cross-chain functionality doesn't properly handle blocked addresses.

There are two key issues:

1. In `MToken::msgOfCcSendToken`, the contract checks if the `receiver` is blocked on the source chain, but this check is invalid since the receiver exists on the destination chain.
```solidity
369:    function msgOfCcSendToken(
370:        address sender,
371:        address receiver,
372:        uint256 value
373:    ) public view returns (bytes memory message) {
374:        _checkBlocked(sender);
375:        _checkBlocked(receiver);//@audit-issue receiver is not on the same chain, so this check does not make sense
376:        return abi.encode(TagSendToken, abi.encode(sender, receiver, value));
377:    }
```

2. In `MToken::ccReceiveToken`, there's no check to verify if the `receiver` is blocked on the current (destination) chain before minting tokens to them.
```solidity
415:    function ccReceiveToken(bytes memory message) internal {
416:        (address sender, address receiver, uint value) = abi.decode(
417:            message,
418:            (address, address, uint)
419:        );
420:        _mint(receiver, value);//@audit-issue should check if receiver is blocked, might need to manage the funds sent to the blocked address
421:        emit CCReceiveToken(sender, receiver, value);
422:    }
```
These issues could allow blocked addresses to receive tokens via cross-chain transfers, bypassing the security controls intended by the protocol.

**Impact:** The blocking mechanism can be bypassed using cross-chain transfers. Malicious or sanctioned addresses that are blocked on one chain can still receive tokens through cross-chain transfers, undermining the security feature of the protocol.

**Proof Of Concept:**
```solidity
    // Test cross-chain sending to a blocked address
    function testCrossChainSendToken_ToBlockedAddress() public {
        // Mint some tokens to user1
        uint256 amount = 100 * 10**18;
        mintTokens(user1, amount);

        // Block user2 on the destination chain
        vm.prank(operator);
        remoteChainMToken.addToBlockedList(user2);

        // User1 tries to send tokens cross-chain to blocked user2
        vm.startPrank(user1);
        mtoken.approve(address(mockMessager), amount);

        // When sending to a blocked address, the send may succeed but the tokens should never reach the destination
        mockMessager.sendTokenToChain{value: 0.01 ether}(
            CHAIN_SELECTOR_2,
            address(remoteChainMToken),
            user2,
            amount,
            ""
        );
        vm.stopPrank();

        // Check that user1's tokens are gone (burned in the sending process)
        assertEq(mtoken.balanceOf(user1), 0, "Tokens should be burned on source chain");

        // The blocked user should NOT receive any tokens
        // assertEq(remoteChainMToken.balanceOf(user2), 0, "Blocked user should not receive tokens");
    }
```

**Recommended Mitigation:**
1. Remove the receiver check in `msgOfCcSendToken` as it's not relevant to the source chain:

```diff
function msgOfCcSendToken(
    address sender,
    address receiver,
    uint256 value
) public view returns (bytes memory message) {
    _checkBlocked(sender);
-   _checkBlocked(receiver);
    return abi.encode(TagSendToken, abi.encode(sender, receiver, value));
}
```

2. Add a blocked address check in `ccReceiveToken` and implement a mechanism to handle tokens sent to blocked addresses:

```diff
function ccReceiveToken(bytes memory message) internal {
    (address sender, address receiver, uint value) = abi.decode(
        message,
        (address, address, uint)
    );
+   if (isBlocked[receiver]) {
+       // Option 1: Send to a recovery address
+       _mint(operator, value);
+       emit CCReceiveBlockedAddress(sender, receiver, value);
+   } else {
        _mint(receiver, value);
+   }
    emit CCReceiveToken(sender, receiver, value);
}
```

**Matrixdock:** Acknowledged.


\clearpage
## Informational


### Only emit events when state actually changes

**Description:** Only emit events when state actually changes, for example in `MTokenMessager::setAllowedPeer`:
```diff
    function setAllowedPeer(
        uint64 chainSelector,
        address messager,
        bool allowed
    ) external onlyOwner {
+      require(chainSelector][messager] != allowed, "No state change");
       allowedPeer[chainSelector][messager] = allowed;
       emit AllowedPeer(chainSelector, messager, allowed);
    }
```

Also affects:
* `MTokenMessagerV2::setAllowedPeer`

**Matrixdock:** Acknowledged.


### Use named mappings

**Description:** Use named mappings to explicity indicate purpose of index => value:
```solidity
MTokenMessager.sol
16:    mapping(uint64 => mapping(address => bool)) public allowedPeer;
//     mapping(uint64 chainSelector => mapping(address messager => bool allowed)) public allowedPeer;

MTokenMessagerV2.sol
28:    mapping(uint64 => mapping(address => bool)) public allowedPeer;
//     mapping(uint64 chainSelector => mapping(address messager => bool allowed)) public allowedPeer;
```

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-f1dbc2c2c340ac285844595cba6f20040bb8b33c2ae726867955370039433c6aR11-R28) for `MTokenMessagerV2`.

**Cyfrin:** Resolved.


### Emit missing events for important state changes

**Description:** Emit missing events for important state changes:
* `MTokenMessagerLZ::setLZPaused`

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-591d4d35e5121caa982af913bb68ff10a5555b9462a19650bfd5b844ecedee43R31).

**Cyfrin:** Verified.


### LayerZero integration can be paused but CCIP integration can't be paused

**Description:** `MTokenMessagerLZ` has a `bool lzPaused` storage slot and uses `onlyLZNotPaused` modifier to make LayerZero send/receive revert when paused.

In contrast `MTokenMessager` and `MTokenMessagerV2` have no similar pausing functionality for CCIP send/receive.

Consider whether this asymmetry is intentional or whether the CCIP send/receive should similarly be able to be paused.

**Matrixdock:** Acknowledged.


### Don't allow pausing for LayerZero receive, only send

**Description:** `MTokenMessagerLZ` has the `onlyLZNotPaused` modifier on both the receiving function `_lzReceive` and the two sending functions `lzSendTokenToChain` / `lzSendMintBudgetToChain`.

Consider removing the `onlyLZNotPaused` modifier from `_lzReceive`  as the sender has already burned their tokens when sending, so don't want receiving to revert in this case.

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-591d4d35e5121caa982af913bb68ff10a5555b9462a19650bfd5b844ecedee43L46).

**Cyfrin:** Verified.


### Use consistent prefix for `internal` function names

**Description:** Some of the `internal` functions use a `_` prefix character but others don't. Use `_` as a consistent prefix for all `internal` function names:

* `MTokenMessager::sendDataToChain`
* `MTokenMessagerLZ::sendThroughLZ`
* `MTokenMessagerV2::sendDataToChain`

**Matrixdock:** Acknowledged.


### Use named imports

**Description:** The contracts mostly use named imports but strangely some import statements don't; use named imports everywhere:

`MTokenMessager`:
```solidity
import "./interfaces/ICCIPClient.sol";
```

`MTokenMessagerLZ`:
```solidity
import "./MTokenMessagerBase.sol";
import "./interfaces/ICCIPClient.sol";
```

`MTokenMessagerV2`:
```solidity
import "./interfaces/ICCIPClient.sol";
import "./MTokenMessagerLZ.sol";
```

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b) for `MTokenMessagerLZ` and `MTokenMessagerV2`.

**Cyfrin:** Verified.


### Consider renaming `MTokenMessagerBase::ccipClient` as it is used by LayerZero integration and actually refers to `MToken`

**Description:** `MTokenMessager::ccipClient` and `MTokenMessagerBase::ccipClient` are used by both LayerZero (`MTokenMessagerLZ`) and CCIP (MTokenMessagerV2`).

But they actually simply reference the `MToken` contract. Calling them `ccipClient` is initially confusing especially when reading the LayerZero integration and wondering why it is calling `ccipClient`.

Consider renaming `MTokenMessager::ccipClient` and `MTokenMessagerBase::ccipClient` to `mToken` and simply adding the additional functions to `IMToken` then deleting `ICCIPClient`.

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-dab651c3b43b10cc975bd594f600387ed27d1bffd16250f576c85820925fab9aR6-R9) for `MTokenMessagerBase`.

**Cyfrin:** Verified.


### Unused event `OwnershipTransferRequested` in `MTokenMessagerLZ`

**Description:** The `MTokenMessagerLZ` contract declares an `OwnershipTransferRequested` event but never emits it anywhere in the contract. This suggests there might have been plans to implement a timelock mechanism for ownership transfer, but it was not completed. The event is defined but remains unused, which could indicate incomplete functionality.

```solidity
18:     event OwnershipTransferRequested(address indexed from, address indexed to);
```

**Matrixdock:** Removed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-591d4d35e5121caa982af913bb68ff10a5555b9462a19650bfd5b844ecedee43L18-R30).

**Cyfrin:** Verified.



### Unnecessary code duplication in `MTokenMessager::sendDataToChain`

**Description:** The `sendDataToChain` function creates a message object and calculates fees, duplicating logic that already exists in the `getFeeAndMessage` function. This creates redundancy in the codebase, which can lead to inconsistencies during future updates and increases gas costs.

**Recommended Mitigation:** Refactor the `sendDataToChain` function to use the existing `getFeeAndMessage` function:

```diff
    function sendDataToChain(
        uint64 destinationChainSelector,
        address messageReceiver,
        bytes calldata extraArgs,
        bytes memory data
    ) internal returns (bytes32 messageId) {
-        Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
-            receiver: abi.encode(messageReceiver),
-            data: data,
-            tokenAmounts: new Client.EVMTokenAmount[](0),
-            extraArgs: extraArgs,
-            feeToken: address(0)
-        });
-        uint256 fee = IRouterClient(getRouter()).getFee(
-            destinationChainSelector,
-            evm2AnyMessage
-        );
+        (uint256 fee, Client.EVM2AnyMessage memory evm2AnyMessage) = getFeeAndMessage(
+            destinationChainSelector,
+            messageReceiver,
+            extraArgs,
+            data
+        );
        if (msg.value < fee) {
            revert InsufficientFee(fee, msg.value);
        }
        messageId = IRouterClient(getRouter()).ccipSend{value: fee}(
            destinationChainSelector,
            evm2AnyMessage
        );
        if (msg.value - fee > 0) {
            payable(msg.sender).sendValue(msg.value - fee);
        }
        return messageId;
    }
```

The same issue is also present in `MTokenMessagerV2::sendDataToChain`.

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-f1dbc2c2c340ac285844595cba6f20040bb8b33c2ae726867955370039433c6aR183) for `MTokenMessagerV2`.

**Cyfrin:** Verified.



\clearpage
## Gas Optimization


### Use `immutable` for storage slots only set once in the constructor of non-upgradeable contracts

**Description:** Use `immutable` for storage slots only set once in the constructor:
* `MTokenMessager::ccipClient`
* `MTokenMessagerBase::ccipClient`

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-dab651c3b43b10cc975bd594f600387ed27d1bffd16250f576c85820925fab9aR6-L8) for `MTokenMessagerBase`.

**Cyfrin:** Verified.


### Use named returns especially for `memory` outputs

**Description:** Use named returns especially for `memory` outputs, eg in `MTokenMessager::calculateCCSendTokenFeeAndMessage`:
```diff
    function calculateCCSendTokenFeeAndMessage(
        uint64 destinationChainSelector,
        address messageReceiver,
        address sender,
        address recipient,
        uint value,
        bytes calldata extraArgs
    )
        public
        view
        returns (uint256 fee, Client.EVM2AnyMessage memory evm2AnyMessage)
    {
        bytes memory data = ccipClient.msgOfCcSendToken(
            sender,
            recipient,
            value
        );
-       return
+       (fee, evm2AnyMessage) =
            getFeeAndMessage(
                destinationChainSelector,
                messageReceiver,
                extraArgs,
                data
            );
    }
```

Also applies to:
* `MTokenMessager::calculateCcSendMintBudgetFeeAndMessage`
* `MTokenMessager::sendDataToChain` where obsolete `return` can be removed
* the same functions in `MTokenMessagerV2`

**Matrixdock:** Fixed in commit [f3fbe97](https://github.com/Matrixdock-RWA/RWA-Contracts/commit/f3fbe97bd20ad514b76aa422a7dfc1f8a66cd66b#diff-f1dbc2c2c340ac285844595cba6f20040bb8b33c2ae726867955370039433c6aR82-R102) for `MTokenMessagerV2`.

**Cyfrin:** Verified.


### Cache amount and use Solady `SafeTransferLib::safeTransferETH` when refunding excess fee

**Description:** In `MTokenMessager::sendDataToChain` and `MTokenMessagerV2::sendDataToChain`, cache the amount and [use Solady](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#10-use-safetransferlibsafetransfereth-instead-of-solidity-call-effective-035-cheaper) `SafeTransferLib::safeTransferETH` when refunding excess fee:
```diff
+ import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";

-       if (msg.value - fee > 0) {
-           payable(msg.sender).sendValue(msg.value - fee);
-       }
+       uint256 excessFee = msg.value - fee;
+       if(excessFee > 0) {
+           SafeTransferLib.safeTransferETH(msg.sender, excessFee);
+       }
```

**Matrixdock:** Acknowledged.

\clearpage