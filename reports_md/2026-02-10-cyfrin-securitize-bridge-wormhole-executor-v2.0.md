**Lead Auditors**

[Kage](https://x.com/0kage_eth)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

**Assisting Auditors**



---

# Findings
## Medium Risk


### Unconfigured CCTP domain mapping defaults to zero, potentially routing USDC to Ethereum instead of intended destination

**Description:** The `USDCBridgeV2` contract maintains a mapping from Wormhole chain IDs to Circle CCTP domain IDs via `chainIdToCCTPDomain`.

When a bridge operation is initiated, the contract retrieves the CCTP domain using `USDCBridgeV2::getCCTPDomain`:

```solidity
  function getCCTPDomain(uint16 _chain) internal view returns (uint32) {
      return chainIdToCCTPDomain[_chain];  // Returns 0 if not configured
  }
```

Solidity mappings return the default value (0) for uninitialized keys. The function does not validate whether the returned domain was explicitly configured or is simply the default zero value. Note that CCTP assigns [domain 0 to Ethereum](https://developers.circle.com/cctp/references/contract-addresses#tokenmessengerv2).

Consider the following scenario:

```text
- Admin deploys USDCBridgeV2 and configures CCTP domains for some chains but forgets to configure a specific chain (e.g. Arbitrum)
- BRIDGE_CALLER invokes sendUSDCCrossChainDeposit() with _targetChain set to the arbitrum's Wormhole ID
- getCCTPDomain() returns 0 (default mapping value)
- _transferUSDC() calls circleTokenMessenger.depositForBurn() with destinationDomain = 0
-  In Circle's CCTP, domain 0 corresponds to Ethereum mainnet
- If the source chain's TokenMessenger has Ethereum configured as a valid remote, the transaction succeeds
- USDC is burned on source chain and minted on Ethereum instead of the intended destination

```

**Impact:** USDC intended for a recipient on Chain X can be minted on Ethereum instead.

**Recommended Mitigation:** Consider adding an explicit validation to ensure the CCTP domain has been configured before proceeding with the transfer:

```diff
function getCCTPDomain(uint16 _chain) internal view returns (uint32) {
      uint32 domain = chainIdToCCTPDomain[_chain];

++      if (domain == 0 && _chain != 2) {
          revert CCTPDomainNotConfigured();
      }

      return domain;
  }
```


**Securitize:** Fixed in [65369a1](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/65369a1f98d6367090cfaa416ef318e98779fac6) and [f92422b](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/f92422b9e72fd8475c3f44eb9a46ede8beea7371).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Guardian sets can expire when SecuritizeBridge is paused

**Description:** Any arbitrary caller can call function `executeVAAv1` to execute pending cross-chain messages. When `SecuritizeBridge` is paused, messages cannot be executed.

```solidity
    function executeVAAv1(bytes calldata _encodedVM) external payable whenNotPaused {
        IWormhole _wormholeCore = wormholeCore;
        (IWormhole.VM memory vm, bool valid, ) = _wormholeCore.parseAndVerifyVM(_encodedVM);
        if (!valid) revert InvalidWormholeMessage();
```

In this paused state, inflight `encodedVM`(s) can expire since guardian sets have an expiry time as observed in the [Wormhole Core](https://etherscan.io/address/0x3c3d457f1522d3540ab3325aa5f1864e34cba9d0#code) contract.

```solidity
/// @dev Checks if VM guardian set index matches the current index (unless the current set is expired).
        if(vm.guardianSetIndex != getCurrentGuardianSetIndex() && guardianSet.expirationTime < block.timestamp){
            return (false, "guardian set has expired");
        }
```

**Impact:** This can lead to a scenario where investors have their DS tokens burned on the source chain but never issued on the destination chain. While DS tokens could be manually issued, this could create significant overhead if there are numerous messages in-flight.

**Recommended Mitigation:** If this is an accepted risk, consider acknowledging the issue and ensure pending in-flight messages (in expired guardian sets) are issued DS tokens manually.

Alternatively, to avoid such a scenario, it is recommended to:
 - Remove the bridge address from all source chains
 - Allow pending in-flight messages to be fulfilled/executed on the target chain
 - Pause the target chain to prevent pending messages from expiring.

**Securitize:** Acknowledged.

\clearpage
## Informational


### `USDCBridgeV2::quoteBridge` returns inflated cost estimate by including wormhole core fee that Is never paid in CCTP v2 flow

**Description:** `USDCBridgeV2::quoteBridge` estimates the cost of a cross-chain USDC transfer. However, this function returns an inflated estimate
  that includes a Wormhole Core message fee (`coreFee`) which is never actually paid during the bridge operation.

```solidity
function quoteBridge(uint16 _targetChain) public override view returns (uint256 cost) {
      (uint256 coreFee, uint256 execFee) = _quoteBridge(_targetChain);
      cost = execFee + coreFee;  // @audit coreFee added but is not used in _quoteBridge
  }
```

`USDCBridgeV2::_quoteBridge` calculates both `coreFee` (Wormhole message fee) and `execFee` (Executor fee), but the CCTP v2 flow does not publish a Wormhole VAA and therefore does not require `coreFee`.

```solidity
function _quoteBridge(uint16 _targetChain) private view returns (uint256 coreFee, uint256 execFee) {
      IWormhole _wormholeCore = wormholeCore;

      coreFee = _wormholeCore.messageFee();  // @audit calculated but never used in CCTP v2
      bytes memory request = ExecutorMessages.makeCCTPv2Request();
      bytes memory relayInstructions = RelayInstructions.encodeGas(gasLimit, 0);
      execFee = executorQuoterRouter.quoteExecution(
          _targetChain,
          bytes32(0),
          _msgSender(),
          quoterAddr,
          request,
          relayInstructions
      );
  }
```

In the `USDCBridgeV2::sendUSDCCrossChainDeposit`, we can see that `coreFee` is calculated but never used.

```solidity
function sendUSDCCrossChainDeposit(...) external ... {
      (, uint256 execFee) = _quoteBridge(_targetChain);  // coreFee discarded
      if (address(this).balance < execFee) revert InsufficientContractBalance();
      // ...
      executorQuoterRouter.requestExecution{value: execFee}(...);  // @audit only execFee paid
  }
```

The CCTP v2 flow uses Circle's native messaging infrastructure rather than Wormhole VAAs. No call to `wormholeCore::publishMessage` is made in this flow, so the Wormhole Core message fee is not required.


**Impact:** External integrations (frontends, other contracts, off-chain systems) querying `USDCBridgeV2::quoteBridge` receive an inflated cost estimate

**Recommended Mitigation:** Consider removing `coreFee` from `quoteBridge` calculation.

**Securitize:** Fixed in [73a0a3c](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/73a0a3ccd5554c49a62f374c8e44c2696d309f85).

**Cyfrin:** Verified.


### Missing nonReentrant modifier on function executeVAAv1

**Description:** `SecuritizeBridge::executeVAAv1` is missing a `nonReentrant` modifier, while this modifier exists in `SecuritizeBridge::bridgeDSTokens`. While this does not pose a risk currently, it is recommended to implement the modifier to maintain consistency.

```solidity
function executeVAAv1(bytes calldata _encodedVM) external payable whenNotPaused {
```

**Recommended Mitigation:** Consider adding the nonReentrant modifier on function `executeVAAv1`

**Securitize:** Fixed in [a6b287c](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/a6b287c23d901d6d0f6c02b6802158a529b1ec26).

**Cyfrin:** Verified.


### Incorrect use of _msgSender() instead of address(this) on quote request

**Description:** In the `USDCBridgeV2` contract, function `_quoteBridge` uses the refund address as the `_msgSender()` on the `quoteExecution` call. However in function `sendUSDCCrossChainDeposit`, the refund address is used as `address(this)` on the `requestExecution` external call.

Function `requestExecution`:
```solidity
executorQuoterRouter.requestExecution{value: execFee}(
            _targetChain,
            bytes32(0),
            address(this), // << refund address
            quoterAddr,
            ExecutorMessages.makeCCTPv2Request(),
            RelayInstructions.encodeGas(gasLimit, 0)
        );
```

Function `_quoteBridge`:

```solidity
function _quoteBridge(uint16 _targetChain) private view returns (uint256 coreFee, uint256 execFee) {
        IWormhole _wormholeCore = wormholeCore; // cache storage

        coreFee = _wormholeCore.messageFee();
        bytes memory request = ExecutorMessages.makeCCTPv2Request();
        bytes memory relayInstructions = RelayInstructions.encodeGas(gasLimit, 0);
        execFee = executorQuoterRouter.quoteExecution(
            _targetChain,
            bytes32(0),
            _msgSender(), // << refund address used as msg.sender
            quoterAddr,
            request,
            relayInstructions
        );
    }
```

While this does not affect the quote calculations in the [ExecutorQuoterRouter](https://github.com/wormholelabs-xyz/example-messaging-executor/blob/14ecd59e2e9774a0e6a3b38f28896bc2d4369cd0/evm/src/ExecutorQuoterRouter.sol#L95C4-L107C31) currently, it is recommended to use the accurate refund address to maintain consistency.

**Recommended Mitigation:** Since the actual refund address is expected to be the `USDCBridgeV2` contract, use `address(this)` instead of `_msgSender()` in function `_quoteBridge`.

**Securitize:** Fixed in [c618dee](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/c618deec81d657ff63c8c975281b160f8f3f4c0c).

**Cyfrin:** Verified.


### Use SafeERC20 approval instead of standard IERC20 approve function

**Description:** Use SafeERC20::forceApprove function instead of the standard IERC20 approve function in `USDCBridgeV2._transferUSDC`

```solidity
IERC20(_USDC).approve(address(circleTokenMessenger), _amount);
```

**Recommended Mitigation:** Consider following the above recommendation.

**Securitize:** Fixed in [d138209](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/d13820907c4bad24ab03273b03c7a55b11a69037).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Unnecessary sequence lookup and request construction in `SecuritizeBridge::_quoteBridge`

**Description:** `SecuritizeBridge::_quoteBridge` performs several unnecessary operations to construct the request parameter, which is subsequently ignored by the `ExecutorQuoter` contract:

```solidity
 function _quoteBridge(uint16 _targetChain) private view returns (uint256 coreFee, uint256 execFee) {
        address targetAddress = bridgeAddresses[_targetChain];
        if (targetAddress == address(0)) revert BridgeAddressNotConfigured();

        IWormhole _wormholeCore = wormholeCore; // cache storage
        uint64 sequence = _wormholeCore.nextSequence(address(this)); //@audit sequence generated

        coreFee = _wormholeCore.messageFee();
        bytes memory request = ExecutorMessages.makeVAAv1Request(_wormholeCore.chainId(), _addressToBytes32(address(this)), sequence);
         //@audit request is computed but this is not used while
        bytes memory relayInstructions = RelayInstructions.encodeGas(gasLimit, 0);
        execFee = executorQuoterRouter.quoteExecution(
            _targetChain,
            _addressToBytes32(targetAddress),
            _msgSender(),
            quoterAddr,
            request,
            relayInstructions
        );
    }
```

The [`ExecuteQuoteRouter::quoteExecution`](https://github.com/wormholelabs-xyz/example-messaging-executor/blob/14ecd59e2e9774a0e6a3b38f28896bc2d4369cd0/evm/src/ExecutorQuoterRouter.sol#L95) calls the [`ExecuteQuote::requestQuote`](https://github.com/wormholelabs-xyz/example-messaging-executor/blob/14ecd59e2e9774a0e6a3b38f28896bc2d4369cd0/evm/src/ExecutorQuoter.sol#L191) function that doesn't use the `request` parameter.

```solidity
   //ExecuteQuoteRouter.sol
    function quoteExecution(
        uint16 dstChain,
        bytes32 dstAddr,
        address refundAddr,
        address quoterAddr,
        bytes calldata requestBytes,
        bytes calldata relayInstructions
    ) external view returns (uint256 requiredPayment) {
        requiredPayment =
            quoterContract[quoterAddr].requestQuote(dstChain, dstAddr, refundAddr, requestBytes, relayInstructions);
    }
```

```solidity
    //ExecutorQuoter.sol
    function requestQuote(
        uint16 dstChain,
        bytes32, //dstAddr,
        address, //refundAddr,
        bytes calldata, //requestBytes, //@audit request bytes are unused
        bytes calldata relayInstructions
    ) external view returns (uint256 requiredPayment) {
        ChainInfo storage dstChainInfo = chainInfos[dstChain];
        if (!dstChainInfo.enabled) {
            revert ChainDisabled(dstChain);
        }
        (uint256 gasLimit, uint256 msgValue) = totalGasLimitAndMsgValue(relayInstructions);
        // NOTE: this does not include any maxGasLimit or maxMsgValue checks
        requiredPayment = estimateQuote(quoteByDstChain[dstChain], dstChainInfo, gasLimit, msgValue);

        return requiredPayment;
    }
```

**Recommended Mitigation:** Consider removing the unnecessary sequence lookup and request construction, and replace request with empty bytes.

**Securitize:** Acknowledged.


### Addition and removal functions can be combined into one function

**Description:** Functions `addBridgeCaller` and `removeBridgeCaller` in `USDCBridgeV2` can be combined into one function to save deployment gas.

```solidity
function addBridgeCaller(address _account) external override addressNotZero(_account) onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(BRIDGE_CALLER, _account);
        emit BridgeCallerAdded(_account);
    }

    function removeBridgeCaller(address _account) external override addressNotZero(_account) onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(BRIDGE_CALLER, _account);
        emit BridgeCallerRemoved(_account);
    }
```


Similarly functions `setBridgeAddress` and `removeBridgeAddress` in `SecuritizeBridge` can be combined as well.
```solidity
function setBridgeAddress(uint16 _chainId, address _bridgeAddress) external override onlyOwner addressNotZero(_bridgeAddress) {
        bridgeAddresses[_chainId] = _bridgeAddress;
        emit BridgeAddressAdded(_chainId, _bridgeAddress);
    }


    function removeBridgeAddress(uint16 _chainId) external override onlyOwner {
        delete bridgeAddresses[_chainId];
        emit BridgeAddressRemoved(_chainId);
    }
```

**Recommended Mitigation:** Consider combining the functions in the following manner with updated event names:

```solidity
function addBridgeCaller(address _account, bool _status) external override addressNotZero(_account) onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_status) grantRole(BRIDGE_CALLER, _account);
        else revokeRole(BRIDGE_CALLER, _account);
        emit BridgeCallerUpdated(_account);
    }
```

```solidity
function setBridgeAddress(uint16 _chainId, address _bridgeAddress) external override onlyOwner {
        bridgeAddresses[_chainId] = _bridgeAddress;
        emit BridgeAddressUpdated(_chainId, _bridgeAddress);
    }
```

**Securitize:** Acknowledged.

\clearpage