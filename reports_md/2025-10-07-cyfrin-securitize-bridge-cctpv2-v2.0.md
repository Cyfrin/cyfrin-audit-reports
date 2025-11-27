**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

**Assisting Auditors**



---

# Findings
## Medium Risk


### Uninitialized CCTP domain mapping can send USDC to the incorrect blockchain

**Description:** `USDCBridgeV2::chainIdToCCTPDomain` maps Wormhole chain IDs to Circle's CCTP domain IDs:
```solidity
mapping(uint16 => uint32) public chainIdToCCTPDomain;

function getCCTPDomain(uint16 _chain) internal view returns (uint32) {
    return chainIdToCCTPDomain[_chain];  // @audit returns 0 if not set!
}
```

**Impact:** When this mapping isn't initialized for a wormhole chain id, it returns 0 by default (Solidity's default value for `uint32`). However [Circle's CCTP domain 0 is Ethereum mainnet](https://developers.circle.com/cctp/cctp-supported-blockchains#cctp-v2-supported-domains). So if a mapping has not been configured for a given [wormhole chain id](https://wormhole.com/docs/products/reference/chain-ids/) eg (6 for Avalanche),`USDCBridgeV2::_transferUSDC` will happily send USDC to Ethereum instead of Avalanche:
```solidity
        circleTokenMessenger.depositForBurn(
            _amount,
            getCCTPDomain(_targetChain), // @audit 0 by default = Ethereum mainnet
            targetAddressBytes32,        // mintRecipient on destination
            USDC,          // burnToken
            destinationCallerBytes32,        // destinationCaller (restrict who can mint)
            0,
            1000
        );
```

**Recommended Mitigation:** The simplest option is to change `USDCBridgeV2::getCCTPDomain` to only allow domain 0 for wormhole's Ethereum chain id:
```solidity
function getCCTPDomain(uint16 _chain) internal view returns (uint32 domain) {
    domain = chainIdToCCTPDomain[_chain];
    // Wormhole ChainID 2 = Ethereum https://wormhole.com/docs/products/reference/chain-ids/
    // Only allow CCTP Domain 0 for Ethereum https://developers.circle.com/cctp/cctp-supported-blockchains#cctp-v2-supported-domains
    require(domain != 0 || _chain == 2, "CCTP domain not configured");
}
```

Another potential solution is to change `setBridgeAddress` such that it always sets the CCTP domain as well eg:
```solidity
    function setBridgeAddress(uint16 _chainId, address _bridgeAddress, uint32 _cctpDomain) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        bridgeAddresses[_chainId] = _bridgeAddress;
        chainIdToCCTPDomain[_chain] = _cctpDomain;
        emit BridgeAddressAdd(_chainId, _bridgeAddress, _cctpDomain);
    }
```

Also consider changing `removeBridgeAddress` to delete from `chainIdToCCTPDomain` eg:
```solidity
    function removeBridgeAddress(uint16 _chainId) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        delete bridgeAddresses[_chainId];
        delete chainIdToCCTPDomain[_chainId];
        emit BridgeAddressRemove(_chainId);
    }
```

**Securitize:** Fixed in commit [d750854](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/d750854aadd6873ad2be3aa95fd5abe80fa01bd3) by removing `setBridgeAddress` and adding a new function `setCCTPBridgeAddress` which enforces that CCTP Domain is configured at the same time as target bridge address for the same wormhole chain id. Also changed `removeBridgeAddress` to clear both mappings together as well.

**Cyfrin:** Verified.


### Hard-coding 0 max fee with fast finality is incompatible as this combination commonly has minimum fees of 1

**Description:** Circle's [CCTPv2 Technical Guide](https://developers.circle.com/cctp/technical-guide) provides the following relevant information:
* Messages with `minFinalityThreshold` of 1000 or lower are considered Fast messages
* Messages with `minFinalityThreshold` of 2000 are considered Standard messages (in practice everything > 1000 is considered Standard)
* The applicable fee should be retrieved every time before executing a transaction using this [API](https://developers.circle.com/api-reference/cctp/all/get-burn-usdc-fees)

The provided API requires specifying the CCTP input and output [domains](https://developers.circle.com/cctp/cctp-supported-blockchains#cctp-v2-supported-domains). Using the `wget` form of the API, the minimum fees for fast finality (1000) are typically 1:

* Ethereum -> Avalanche
```console
$ wget --quiet \
  --method GET \
  --header 'Content-Type: application/json' \
  --output-document \
  - https://iris-api-sandbox.circle.com/v2/burn/USDC/fees/0/1
[{"finalityThreshold":1000,"minimumFee":1},{"finalityThreshold":2000,"minimumFee":0}]%
```

* Ethereum -> Solana
```console
$ wget --quiet \
  --method GET \
  --header 'Content-Type: application/json' \
  --output-document \
  - https://iris-api-sandbox.circle.com/v2/burn/USDC/fees/0/5
[{"finalityThreshold":1000,"minimumFee":1},{"finalityThreshold":2000,"minimumFee":0}]%
```

**Impact:** Many CCTP cross-domain transfers have a minimum fee of 1 for fast finality, but `USDCBridgeV2::_transferUSDC` hard-codes a maximum fee of 0 with fast finality 1000:
```solidity
circleTokenMessenger.depositForBurn(
    _amount,
    getCCTPDomain(_targetChain),
    targetAddressBytes32,        // mintRecipient on destination
    USDC,          // burnToken
    destinationCallerBytes32,        // destinationCaller (restrict who can mint)
    0,   // @audit maximum fee
    1000 // @audit fast finality
);
```

This combination is incompatible and will result in many cross-domain transfers unable to use fast finality, reverting to standard finality. If the minimum fee for standard finality ever becomes > 0, this would cause all attempted cross-domain transfers to revert since the automatic downgrade to standard finality would no longer be possible.

**Recommended Mitigation:** Ideally the maximum fee and finality should be provided as inputs:
* current fee bps should be retrieved off-chain using the provided API for the desired domain combination
* multiply fee bps by the amount to be transferred to calculate the maximum fee
* pass maximum fee and desired finality as inputs when calling `circleTokenMessenger.depositForBurn`

At least there should be a way to change the maximum fee, it shouldn't be hard-coded to zero as this causes the protocol to become unusable if standard finality fees become non-zero.

**Securitize:** Fixed in commit [0d3e50d](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/0d3e50daadb37b29266a86d76a9c060eeed5805d) by:
* always using standard finality
* max fee is now a variable so we can change it if Circle increases standard finality fees in the future

**Cyfrin:** Verified.


### Investors using smart contract wallets may have their destination chain tokens issued to an address they don't control

**Description:** `SecuritizeBridge::bridgeDSTokens` encodes `_msgSender()` in the payload message to be destination address for bridged tokens delivered on the destination chain; this is expected to represent the investor's wallet address:
```solidity
 // Send Relayer message
        wormholeRelayer.sendPayloadToEvm{value: msg.value} (
            targetChain,
            targetAddress,
            abi.encode(
                investorDetail.investorId,
                value,
                _msgSender(), // @audit destination address of bridged tokens
                investorDetail.country,
                investorDetail.attributeValues,
                investorDetail.attributeExpirations
            ), // payload
            0, // no receiver value needed since we"re just passing a message
            gasLimit,
            whChainId,
            _msgSender()
        );
```

`SecuritizeBridge::receiveWormholeMessages` executed on the destination chain adds the address to the investor's account and issues tokens to it:
```solidity
        address[] memory investorWallets = new address[](1);
        investorWallets[0] = investorWallet;

        // @audit assumes investor controls same wallet address
        // on destination chain - not necessarily true for smart contract wallets
        registryService.updateInvestor(investorId, investorId, country, investorWallets, attributeIds, attributeValues, attributeExpirations);
        dsToken.issueTokens(investorWallet, value);
```

**Impact:** If the investor's wallet is a smart contract wallet (multisig/AA wallets - which can have different addresses on different chains), there is no guarantee that the investor will have their smart wallet contract deployed at the same address on the destination chain.

In an unlikely worst-case scenario, the address on the destination chain is owned by a different EOA user who is not an investor. This causes `SecuritizeBridge::receiveWormholeMessages` to give a foreign user control over the original investor's account because it registers the foreign user's address as belonging to the investor on the destination chain:
* Alice uses a Gnosis Safe at 0xAAA... on Ethereum
* Alice bridges her DSTokens to Arbitrum
* Bob (malicious) controls EOA 0xAAA... on Arbitrum (same address, different controller)
* The bridge registers 0xAAA... on Arbitrum as Alice's wallet
* Bob now controls all of Alice's tokens on Arbitrum

**Recommended Mitigation:** A simple solution is to allow investors to provide valid destination chain wallets and encode it in the payload, however this may also be ripe for abuse by allowing investors to claim wallets they don't actually control.

In another cross-chain regulated TradFi protocol we've audited, the protocol had functionality to bridge investor addresses and credentials cross-chain, and this occurred separately to token bridging.

The cross-chain token bridging could only work if the destination address and its associated credentials had already been bridged; this ensured that the destination address was always valid.

**Securitize:** Acknowledged; we are aware of this edge case as it was raised in a previous audit. If the destination address is not an EOA and the investor has no control of tokens in destination chain, tokens remain locked due to lock-up period and Securitize has enough time to seize/burn the tokens.


### Bridging `DSToken` back-and-forth between chains causes `totalIssuance` cap to be reached, preventing further issuances and cross-chain transfers

**Description:** `StandardToken::totalIssuance` is not decreased by burns but is used to enforce maximum cap, since `totalIssuance` is supposed to track the total number of tokens ever issued, not the current "supply".

However there is an interesting consequence to this when considering cross-chain bridging via `SecuritizeBridge`; `receiveWormholeMessages` calls `DSToken::issueTokens` on the destination chain which increases `StandardToken::totalIssuance`.

**Impact:** Consider this scenario:
* Alice bridges from Ethereum -> Arbitrum with 1000 `DSToken`
* Alice bridges back from Arbitrum -> Ethereum with the "same" 1000 `DSToken`
* Alice keeps doing this over and over again

This process continually increases the `totalIssuance` on both chains, even though it is just the same tokens going back and forth; at some point this will cause the cap to be hit on one of the chains. This doesn't even require malicious investors, just investors who bridge back-and-forth frequently.

Once the cap is hit further issuances and cross-chain transfers will revert on that chain.

**Recommended Mitigation:** Potential mitigations include:
* have bridging actually decrement `totalIssuance` on the source chain
* have `SecuritizeBridge::receiveWormholeMessages` call `DSToken::issueTokensCustom` passing a `reason == "BRIDGING"` then  in `TokenLibrary::issueTokensCustom` don't increment `totalIssuance` for `"BRIDGING"` reason
* track the number of bridged tokens separately and modify the cap check to account for this

**Securitize:** Fixed in commit [c2e62c9](https://github.com/securitize-io/dstoken/commit/c2e62c9c1137bb7c6f548b72f960d864c42445fc); the cap was deprecated and associated checks removed. There is a similar compliance-related check that uses `totalSupply` so correctly accounts for burns.

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Upgradeable contracts which are inherited from should use ERC7201 namespaced storage layouts or storage gaps to prevent storage collision

**Description:** The protocol has upgradeable contracts which other contracts inherit from. These contracts should either use:
* [ERC7201](https://eips.ethereum.org/EIPS/eip-7201) namespaced storage layouts - [example](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L60-L72)
* storage gaps (though this is an [older and no longer preferred](https://blog.openzeppelin.com/introducing-openzeppelin-contracts-5.0#Namespaced) method)

The ideal mitigation is that all upgradeable contracts use ERC7201 namespaced storage layouts; without using one of the above two techniques storage collision can occur during upgrades. The affected contracts are:

* `CCTPBase`
* `CCTPBase`

**Securitize:** Acknowledged; `CCTPBase` and `CCTPBase` will be removed later as they will become deprecated.


### No way to retrieve ETH sent with call to `SecuritizeBridge::receiveWormholeMessages`

**Description:** `SecuritizeBridge::receiveWormholeMessages` is marked as `payable` however:
* it does nothing with `msg.value`
* there is no function in `SecuritizeBridge` to withdraw ETH

**Impact:** If ETH should be sent along with the call to `SecuritizeBridge::receiveWormholeMessages`, it will be stuck in the contract unable to be retrieved.

**Recommended Mitigation:** Add a function `withdrawETH` that allows the contract owner to withdraw the contract's ETH balance.

**Securitize:** Fixed in commits [923e50e](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/923e50e41dc859fa9516dd370988d01d685759e6), [2b18646](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/2b18646e6344fcebe4f32107cd56812877ddadea#diff-3f58493270011157ff7c863627332c733405a46f8b6524660d25b33ef16f9f74R171) by adding a `withdrawETH` function the owner can call.

**Cyfrin:** Verified.


### Don't use `transfer` to send ETH

**Description:** Using `transfer` to send ETH hasn't been recommended since the Istanbul hard fork in December 2019 which increased the gas cost of some operations; `transfer` hard-codes gas to 2300 which can cause receiving functions to revert hence is not future-proof.

The [recommended way to send eth](https://www.securitize-io.io/glossary/sending-ether-transfer-send-call-solidity-code-example) is to use `call` and Solady has an optimized way of doing this in [SafeTransferLib::safeTransferETH](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L95-L103).

`transfer` also may not work as expected on L2s, for example there was this [incident](https://thedefiant.io/news/defi/zksync-rescues-gemholic) which resulted in 921 ETH being stuck on zksync Era due to the smart contract using transfer to send eth, though eventually zksync developed a [solution](https://www.theblock.co/post/225364/zksync-unfreeze-millions-stuck) to rescue the stuck eth.

Affected code in `USDCBridgeV2::withdrawETH`:
```solidity
bridge/USDCBridgeV2.sol
202:        _to.transfer(amount);
```

**Securitize:** Fixed in commit [2b18646](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/2b18646e6344fcebe4f32107cd56812877ddadea).

**Cyfrin:** Verified.


### Inconsistent usage of `whenNotPaused` modifier for bridging fulfillment in `SecuritizeBridge` and `USDCBridgeV2`

**Description:** `USDCBridgeV2` inherits pause functionality from `BaseRBACContract`. Currently `USDCBridgeV2::receiveWormholeMessages` does not apply the `whenNotPaused` modifier allowing receipt of tokens to occur on a paused destination chain contract.

In contrast `SecuritizeBridge::receiveWormholeMessages` does have the `whenNotPaused` preventing receipt of tokens on a paused destination chain contract.

**Recommended Mitigation:** There is an inconsistent usage of `whenNotPaused` modifier for bridging fulfillment; if there is no good reason for this difference then it should be made consistent. Either:
* don't allow bridging fulfillment when destination contracts are paused
* allow bridging fulfillment when destination contracts are paused but don't allow new bridging requests when paused

**Securitize:** Acknowledged; for now we prefer to leave the modifiers unchanged. We can prevent issuances on flying bridges for dsTokens, as we control them and we can issue, burn, etc. We do not want to pause USDC flying bridges, as we do not have control over usdc circle stable coin.

\clearpage
## Informational


### Use named imports

**Description:** Use named imports consistently throughout the codebase.

**Securitize:** Fixed in commit [85ca7bb](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/85ca7bb455cd78921b4f9ad7c48b0cf9eb0470e4).

**Cyfrin:** Verified.


### Use named mapping parameters to make explicit the purpose of keys and values

**Description:** Use named mapping parameters to make explicit the purpose of keys and values:
```solidity
wormhole/WormholeCCTPUpgradeable.sol
79:    mapping(uint16 => uint32) public chainIdToCCTPDomain;

bridge/USDCBridgeV2.sol
63:    mapping(uint16 => address) public bridgeAddresses;
64:    mapping(uint16 => uint32) public chainIdToCCTPDomain;

bridge/SecuritizeBridge.sol
40:    mapping(uint16 => address) public bridgeAddresses;
```

**Securitize:** Fixed in commit [40f4db0](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/40f4db07a0351b3aebb3547a49236a1ca54a99d3).

**Cyfrin:** Verified.


### Emit missing events on important parameter changes

**Description:** Emit missing events on important parameter changes:
* `CCTPSender::setCCTPDomain`
* `USDCBridgeV2::setCCTPDomain`

**Securitize:** Fixed in commit [cd8c8ad](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/cd8c8ada1240c862458138cc1db9372aaf970573) for `USDCBridgeV2`, leaving the other as it will be deprecated.

**Cyfrin:** Verified.


### Use `SafeERC20` approval and transfer functions instead of standard IERC20 functions

**Description:** Use [SafeERC20::forceApprove](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol#L105-L110) and `safeTransfer` functions instead of standard IERC20 functions:
```solidity
wormhole/WormholeCCTPUpgradeable.sol
121:        IERC20(USDC).approve(address(circleTokenMessenger), amount);

bridge/USDCBridgeV2.sol
150:        IERC20(USDC).transferFrom(_msgSender(), address(this), _amount);
264:        IERC20(USDC).approve(address(circleTokenMessenger), _amount);
```

**Securitize:** Fixed in commit [d75ac6f](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/d75ac6fb219f2f536172e4c7b146cece27ca175e).

**Cyfrin:** Verified.


### Prefer `Ownable2StepUpgradeable` instead of `OwnableUpgradeable` in `BaseContract`

**Description:** In `BaseContract` prefer [Ownable2StepUpgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/Ownable2StepUpgradeable.sol) instead of `OwnableUpgradeable`.

**Securitize:** Acknowledged.


### Rename `SecuritizeBridge::whChainId` to `whRefundChainId`

**Description:** The only purpose of `SecuritizeBridge::whChainId` is to be the wormhole refund chain id; rename it to something like `whRefundChainId` which accurately describes its purpose.

Also there are no functions to change this value; consider adding one if this may be required.

**Securitize:** Acknowledged.


### Upgradeable contracts should call `_disableInitializers` in constructor

**Description:** Upgradeable contracts should [call](https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#initializing_the_implementation_contract) `_disableInitializers` in constructor:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

Affected contracts:
* `SecuritizeBridge`
* `USDCBridgeV2`

**Securitize:** Fixed in commit [4b7f654](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/4b7f654e98b0a2b4d953101372b360c906459d9b).

**Cyfrin:** Verified.


### Use `addressNotZero` modifier on `USDCBridgeV2::setBridgeAddress`

**Description:** Use `addressNotZero` modifier on `USDCBridgeV2::setBridgeAddress`:
```diff
-   function setBridgeAddress(uint16 _chainId, address _bridgeAddress) external override onlyRole(DEFAULT_ADMIN_ROLE) {
+   function setBridgeAddress(uint16 _chainId, address _bridgeAddress) external override addressNotZero(_bridgeAddress) onlyRole(DEFAULT_ADMIN_ROLE) {
```

**Securitize:** Fixed in commit [f51d885](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/f51d885e50218167a7fb16d0152337bf8e8445d6).

**Cyfrin:** Verified.


### Misleading event emission in `USDCBridgeV2::addBridgeCaller, removeBridgeCaller` when role was not granted or revoked

**Description:** `AccessControlUpgradeable::_grantRole,_revokeRole` [return](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L204-L230) `bool` to indicate whether the role has been granted or revoked.

But `USDCBridgeV2::removeBridgeCaller, addBridgeCaller` ignore the returned `bool` since they call the `public` functions and always emits an event even if no role was granted or revoked.

**Recommended Mitigation:**
```diff
    function addBridgeCaller(address _account) external override addressNotZero(_account) onlyRole(DEFAULT_ADMIN_ROLE) {
-       grantRole(BRIDGE_CALLER, _account);
-       emit BridgeCallerAdded(_account);
+       if(_grantRole(BRIDGE_CALLER, _account)) emit BridgeCallerAdded(_account);
    }

    function removeBridgeCaller(address _account) external override addressNotZero(_account) onlyRole(DEFAULT_ADMIN_ROLE) {
-       revokeRole(BRIDGE_CALLER, _account);
-       emit BridgeCallerRemoved(_account);
+       if(_revokeRole(BRIDGE_CALLER, _account)) emit BridgeCallerRemoved(_account);
    }
```

**Securitize:** Acknowledged.


### Remove unused function `USDCBridgeV2::_redeemUSDC`

**Description:** The `private` function `USDCBridgeV2::_redeemUSDC` is not used anywhere; remove it.

**Securitize:** Fixed in commit [07a872e](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/07a872e8266411a440b736e328a86528b75cbdb0).

**Cyfrin:** Verified.


### Uninitialized country for valid investor wallets allows bypassing US compliance lockup period

**Description:** One way that wallets can be registered in the protocol is via `RegistryService.sol::addWallet`, meanwhile the country field for the registered wallet can be set separately using a separate function `setCountry`.

Hence there can be a small window during these two transactions which leaves the country field as an empty string (default value) for a valid wallet .

**Impact:** Since during bridging of DS tokens the `country` would be an empty string, the `region` memory variable will also default to 0. This would mean the `lockPeriod` would store and use the non-US lock period:
```solidity
string memory country = registryService.getCountry(investorId);
uint256 region = complianceConfigurationService.getCountryCompliance(country);

uint256 lockPeriod = (region == US) ? complianceConfigurationService.getUSLockPeriod() : complianceConfigurationService.getNonUSLockPeriod();
        uint256 availableBalanceForTransfer = complianceService.getComplianceTransferableTokens(_msgSender(), block.timestamp, uint64(lockPeriod));
```

This is problematic since:
1. Uninitialized country fields for valid wallets are allowed to perform bridging
2. If the intended country = US, the lockPeriod uses the non-US lock period instead.

This small period of time can be used by malicious wallet owners to use a lower `lockPeriod` (if non-US lock time is smaller than US lock time).

**Recommended Mitigation:** Check if country is an empty string in `validateLockedTokens` and revert if true.

**Securitize:** Acknowledged; If the investor is bridging tokens, they were already minted/issued. Hence compliance rules were validated including country and region at the time of token minting/issuance.


### `USDCBridgeV2` can't bridge to non-EVM chains even though Wormhole and Circle CCTP support this

**Description:** Both Wormhole and Circle CCTP support bridging between EVM and non-EVM chains, however `USCBridgeV2` prevents bridging to non-EVM chains since:

1) `_sendUSDCWithPayloadToEvm` always calls `wormholeRelayer.sendToEvm`
2) `bridgeAddresses[_targetChain]` stores the target bridges using `address`, but this is not compatible with target bridges on non-EVM chains such as Solana

**Impact:** Bridging to non-EVM chains is not supported.

**Recommended Mitigation:** If bridging to non-EVM chains should be supported:
* use `wormholeRelayer.send` instead of `sendToEvm`
* `bridgeAddresses[_targetChain]` should store target bridges as `bytes32` then cast them to `address` when bridging to EVM chains
* generally addresses for remote chains should be passed as input, stored and used using `bytes32` not `address`

**Securitize:** Acknowledged; by design for now.


### Remove unused imports

**Description:** Remove unused imports:
* `USDCBridgeV2.sol`
```solidity
28:import {IBridge} from "./IBridge.sol";
```

**Securitize:** Fixed in commit [a45cb7e](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/a45cb7edcc9ec79c5e1cc30420c826e0566af827).

**Cyfrin:** Verified.


### Follow function declaration solidity style guide in `BaseContract`

**Description:** Functions `pause` and `unpause` defines the visibility `public` after the modifier `onlyOwner`. As per the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#function-declaration), the order expects modifiers to be placed after visibility declarations.
```solidity
function pause() onlyOwner external {
        _pause();
    }

    function unpause() onlyOwner external {
        _unpause();
    }
```

**Recommended Mitigation:** Update the code in the following way:
```solidity
function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
```

**Securitize:** Fixed in commit [61fb6a6](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/61fb6a6e4cb0830d152aa3a436a718fb0e0795ae).

**Cyfrin:** Verified.


### Pending/re-executable messages sourced from old bridge addresses will not be executable if bridge address is updated

**Description:** SecuritizeBridge and USDCBridgeV2 provide owner with the ability to update bridge addresses. This can be done incase a new bridge address is expected to be used and the previous one is being deprecated.

```solidity
function setBridgeAddress(uint16 chainId, address bridgeAddress) external override onlyOwner {
        bridgeAddresses[chainId] = bridgeAddress;
        emit BridgeAddressAdd(chainId, bridgeAddress);
    }
```

**Impact:** One important behaviour to be aware of here is that there could be pending or failed destination messages waiting to be delivered. If the bridge address is updated before these are executed, it is possible for them to never be executable again unless the bridge address is updated to the previous one.

**Recommended Mitigation:** Consider waiting for delivery of pending messages and execute any failed destination messages before updating the bridge address for a chain.

**Securitize:** Acknowledged.

\clearpage
## Gas Optimization


### Cache storage to prevent identical storage reads

**Description:** Reading from storage is expensive; cache storage to prevent identical storage reads:
* `contracts/wormhole/WormholeCCTPUpgradeable.sol`
```solidity
// cache `USDC` in `redeemUSDC`
65:        uint256 beforeBalance = IERC20(USDC).balanceOf(address(this));
67:        return IERC20(USDC).balanceOf(address(this)) - beforeBalance;
```

* `contracts/bridge/SecuritizeBridge.sol`
```solidity
// cache `dsToken` in `bridgeDSTokens`
73:        require(dsToken.balanceOf(_msgSender()) >= value, "Not enough balance in source chain to bridge");
88:        dsToken.burn(_msgSender(), value, BRIDGE_REASON);
108:        emit DSTokenBridgeSend(targetChain, address(dsToken), _msgSender(), value);

// cache `dsToken` in `receiveWormholeMessages`
144:        dsToken.issueTokens(investorWallet, value);
146:        emit DSTokenBridgeReceive(sourceChain, address(dsToken), investorWallet, value);
```

* `contracts/bridge/USDCBridgeV2.sol`
```solidity
// cache `USDC` in `sendUSDCCrossChainDeposit`
143:        if (IERC20(USDC).balanceOf(_msgSender()) < _amount) {
150:        IERC20(USDC).transferFrom(_msgSender(), address(this), _amount);
// also change `_transferUSDC` to take cached `USDC` as parameter to save
// 2 storage reads inside `_transferUSDC`;
// cache `USDC, `circleTokenMessenger` in `_transferUSDC`
264:        IERC20(USDC).approve(address(circleTokenMessenger), _amount);
268:        circleTokenMessenger.depositForBurn(
272:            USDC,          // burnToken
```

**Securitize:** Acknowledged.


### Fail fast without doing unnecessary work

**Description:** If a transaction is going to revert, then revert as fast as possible without doing unnecessary work. Strategies to achieve this include:
* perform all input-related validation first
* read only enough storage or make enough external calls to perform the next validation step

For example in `SecuritizeBridge::bridgeDSTokens`:
```solidity
    function bridgeDSTokens(uint16 targetChain, uint256 value) external override payable whenNotPaused {
        // @audit why do all this work...
        uint256 cost = quoteBridge(targetChain);
        require(msg.value >= cost, "Transaction value should be equal or greater than quoteBridge response");
        require(dsToken.balanceOf(_msgSender()) >= value, "Not enough balance in source chain to bridge");
        address targetAddress = bridgeAddresses[targetChain];
        require(bridgeAddresses[targetChain] != address(0), "No bridge address available");

        IDSRegistryService registryService = IDSRegistryService(dsServiceConsumer.getDSService(dsServiceConsumer.REGISTRY_SERVICE()));
        require(registryService.isWallet(_msgSender()), "Investor not registered");

        // @audit ...if txn will revert here due to invalid input?
        require(value > 0, "DSToken value must be greater than 0");
```

And in `USDCBridgeV2::sendUSDCCrossChainDeposit`
```solidity
    function sendUSDCCrossChainDeposit(
        uint16 _targetChain,
        address _recipient,
        uint256 _amount
    ) external override whenNotPaused nonReentrant onlyRole(BRIDGE_CALLER) {
        uint256 deliveryCost = quoteBridge(_targetChain);
        // @audit why perform this storage read...
        address targetBridge = bridgeAddresses[_targetChain];
        // @audit ...if this check will just revert? Perform this check immediately
        // after `uint256 deliveryCost = quoteBridge(_targetChain);`
        if (address(this).balance < deliveryCost) {
            revert InsufficientContractBalance();
        }
        // @audit why perform this check here?
        if (IERC20(USDC).balanceOf(_msgSender()) < _amount) {
            revert NotEnoughBalance();
        }
        // @audit if it is going to revert from this? Perform this check immediately
        // after ` address targetBridge = bridgeAddresses[_targetChain];`
        if (targetBridge == address(0)) {
            revert BridgeAddressUndefined();
        }
```

**Securitize:** Fixed in commit [2ad89cf](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/2ad89cf65ea61c999f140fa6754fb1077a3674b1).

**Cyfrin:** Verified.


### Use `targetAddress` instead of `bridgeAddresses[targetChain]` for check in `SecuritizeBridge::bridgeDSTokens`

**Description:** Use `targetAddress` instead of `bridgeAddresses[targetChain]` for check in `SecuritizeBridge::bridgeDSTokens`:
```diff
        address targetAddress = bridgeAddresses[targetChain];
-       require(bridgeAddresses[targetChain] != address(0), "No bridge address available");
+       require(targetAddress != address(0), "No bridge address available");
```

**Securitize:** Fixed in commit [9081b85](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/9081b858ffddcf1b9b6a3eafcbee3b6a2da192e8).

**Cyfrin:** Verified.


### Refactor `SecuritizeBridge::bridgeDSTokens` and `quoteBridge` to use `internal` function saves 2 storage reads per bridging transaction

**Description:** `SecuritizeBridge::bridgeDSTokens`:
* L71 calls `quoteBridge` which reads `wormholeRelayer` and `gasLimit` from storage
* L91 calls `wormholeRelayer.sendPayloadToEvm` which reads `wormholeRelayer` from storage again
* L108 reads `gasLimit` from storage again

Storage reads are expensive; refactor like this to avoid identical storage reads here:
```solidity
// new internal function
    function _quoteBridge(IWormholeRelayer relayer, uint256 _gasLimit, uint16 targetChain) internal view returns (uint256 cost) {
        (cost, ) = relayer.quoteEVMDeliveryPrice(targetChain, 0, _gasLimit);
    }

// modify `quoteBridge` to use new internal function
    function quoteBridge(uint16 targetChain) public override view returns (uint256 cost) {
        (cost, ) = _quoteBridge(wormholeRelayer, gasLimit, targetChain);
    }

// in `bridgeDSTokens` to cache `wormholeRelayer` and `gasLimit`
// then pass them to `_quoteBridge` and use them at L91 & L108
```

The same optimization should also be applied to `USDCBridgeV2::sendUSDCCrossChainDeposit`, `quoteBridge` and `_sendUSDCWithPayloadToEvm`.

**Securitize:** Fixed in commit [47c1ad0](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/47c1ad0de51887344785cebb7f5668b769b9d092).

**Cyfrin:** Verified.


### Use named return values where this can eliminate local variables

**Description:** Use named return values where this can eliminate local variables:
* `SecuritizeBridge::getInvestorData`

**Securitize:** Acknowledged.


### Refactor `SecuritizeBridge::validateLockedTokens` to take `dsServiceConsumer` as input parameter

**Description:** `SecuritizeBridge::bridgeDSTokens` at L77 reads `dsServiceConsumer` from storage then at L83 calls `validateLockedTokens`.

The internal function `validateLockedTokens` itself re-reads `dsServiceConsumer` from storage multiple times.

Reading from storage is expensive; instead:
* cache `dsServiceConsumer` once in `bridgeDSTokens`
* refactor `validateLockedTokens` to take `dsServiceConsumer` as an input parameter
* in `bridgeDSTokens` when calling `validateLockedTokens` pass the cached `dsServiceConsumer` as an input parameter

**Securitize:** Fixed in commits [bcc83e0](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/bcc83e04b66320b07fcc621352de72e59985bf8a), [0cf5dd9](https://github.com/securitize-io/bc-securitize-bridge-sc/commit/0cf5dd91a4ff6ba1d2a1d5c9b55c395e415536e1).

**Cyfrin:** Verified.


### Use `ReentrancyGuardTransientUpgradeable` for faster `nonReentrant` modifiers

**Description:** Use [ReentrancyGuardTransientUpgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/utils/ReentrancyGuardTransientUpgradeable.sol) for faster `nonReentrant` modifiers:
```solidity
bridge/USDCBridgeV2.sol
27:import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
51:contract USDCBridgeV2 is IUSDCBridge, IWormholeReceiver, BaseRBACContract, ReentrancyGuardUpgradeable {
86:        __ReentrancyGuard_init();
```

**Securitize:** Acknowledged.


### Remove unused return from `USDCBridgeV2:_sendUSDCWithPayloadToEvm`

**Description:** Function `USDCBridgeV2::_sendUSDCWithPayloadToEvm()` returns the sequence number from the `wormholeRelayer.sendToEvm` external call. However, this value is never utilized thereafter.

**Recommended Mitigation:** Consider removing this variable.

**Securitize:** Acknowledged.


### Pass `_refundChain` as input to `USDCBridgeV2::_buildCCTPKey` saves 1 storage read and external call

**Description:** `USDCBridgeV2::sendUSDCCrossChainDeposit` passes `wormhole.chainId()` as the third-to-last parameter:
```solidity
        _sendUSDCWithPayloadToEvm(
            _targetChain,
            targetBridge, // address (on targetChain) to send token and payload to
            payload,
            0, // receiver value
            gasLimit,
            _amount,
            wormhole.chainId(), // @audit `_refundChain`
            address(this),
            deliveryCost
        );
```

But then `_sendUSDCWithPayloadToEvm` calls `_buildCCTPKey` which performs the same work again:
```solidity
    function _buildCCTPKey() private view returns (MessageKey memory) {
        return MessageKey(CCTP_KEY_TYPE, abi.encodePacked(getCCTPDomain(wormhole.chainId()), uint64(0)));
    }
```

Refactor `_buildCCTPKey` to take `uint16 _whSourceChain` as an input parameter and use it like this:
```solidity
    function _buildCCTPKey(uint16 _whSourceChain) private view returns (MessageKey memory) {
        return MessageKey(CCTP_KEY_TYPE, abi.encodePacked(getCCTPDomain(_whSourceChain), uint64(0)));
    }
```

**Securitize:** Acknowledged.

\clearpage