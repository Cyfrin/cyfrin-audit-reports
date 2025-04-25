**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[Jorge](https://x.com/TamayoNft)

---

# Findings
## Critical Risk


### Missing source validation in CCIP message handling

**Description:** YieldFi integrates with Chainlink CCIP to facilitate cross-chain transfers of its yield tokens (`YToken`). This functionality is handled by the `BridgeCCIP` contract, which manages token accounting for these transfers.

However, in the [`BridgeCCIP::_ccipReceive`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L160-L181) function, there is no validation of the message sender from the source chain:
```solidity
/// handle a received message
function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage) internal override {
    bytes memory message = abi.decode(any2EvmMessage.data, (bytes)); // abi-decoding of the sent text
    BridgeSendPayload memory payload = Codec.decodeBridgeSendPayload(message);
    bytes32 _hash = keccak256(abi.encode(message, any2EvmMessage.messageId));
    require(!processedMessages[_hash], "processed");

    processedMessages[_hash] = true;

    require(payload.amount > 0, "!amount");

    ...
}
```

As a result, an attacker could craft a malicious `Any2EVMMessage` containing valid data and trigger the minting or unlocking of arbitrary tokens by sending it through CCIP to the `BridgeCCIP` contract.


**Impact:** An attacker could drain the bridge of tokens on L1 or mint an unlimited amount of tokens on L2. While a two-step redeem process offers some mitigation, such an exploit would still severely disrupt the protocol’s accounting and could be abused when claiming yield for example.

**Recommended Mitigation:** Consider implementing validation to ensure that messages are only accepted from trusted peers on the source chain:
```solidity
mapping(uint64 sourceChain => mapping(address peer => bool allowed)) public allowedPeers;
...
function _ccipReceive(
    Client.Any2EVMMessage memory any2EvmMessage
) internal override {
    address sender = abi.decode(any2EvmMessage.sender, (address));
    require(allowedPeers[any2EvmMessage.sourceChainSelector][sender],"allowed");
    ...
```

**YieldFi:** Fixed in commit [`a03341d`](https://github.com/YieldFiLabs/contracts/commit/a03341d8103ba08473ea1cd39e64192608692aca)

**Cyfrin:** Verified. `sender` is now verified to be a trusted sender.


### All CCIP messages reverts when decoded

**Description:** YieldFi has integrated Chainlink CCIP alongside its existing LayerZero support to enable cross-chain token transfers using multiple messaging protocols. To support this, a custom message payload is used to indicate the token transfer. This payload is decoded in [`Codec::decodeBridgeSendPayload`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Codec.sol#L22-L51) as follows:
```solidity
(uint32 dstId, address to, address token, uint256 amount, bytes32 trxnType) = abi.decode(_data, (uint32, address, address, uint256, bytes32));
```
This same decoding logic is reused for CCIP message processing.

However, Chainlink uses a `uint64` for `dstId`, and their chain IDs (e.g., [Ethereum mainnet](https://docs.chain.link/ccip/directory/mainnet/chain/mainnet)) all exceed the `uint32` range. For instance, Ethereum’s CCIP chain ID is `5009297550715157269`, which is well beyond the limits of `uint32`.

**Impact:** All CCIP messages will revert during decoding due to the overflow when casting a `uint64` value into a `uint32`. Since the contract is not upgradeable, failed messages cannot be retried, resulting in permanent loss of funds—tokens may be either locked or burned depending on the sending logic.

**Proof of Concept:** Attempting to process a message with `dstId = 5009297550715157269` in the `CCIP Receive: Should handle received message successfully` test causes the transaction to revert silently. The same behavior is observed when manually decoding a 64-bit value as a 32-bit integer using Remix.

**Recommended Mitigation:** Consider updating the type of `dstId` to `uint64` to match the Chainlink format. This change should be safe, as `dstId` is not used after decoding in the current LayerZero integration.

**YieldFi:** Fixed in commit [`14fc17a`](https://github.com/YieldFiLabs/contracts/commit/14fc17a46702bf0db0efb199c48e52530221612b)

**Cyfrin:** Verified. `dstId` is now a `uint64` in `Codec.BridgeSendPayload`.

\clearpage
## High Risk


### Incorrect `owner` passed to `Manager::redeem` in YToken withdrawal flow

**Description:** YieldFi’s yield tokens (`YTokens`) implement a more complex withdrawal mechanism than a standard ERC-4626 vault. Instead of executing withdrawals immediately, they defer them to a central `Manager` contract, which queues the request for off-chain processing and later execution on-chain.

As with any ERC-4626 vault, third parties are allowed to initiate a withdrawal or redemption on behalf of a user, provided the appropriate allowances are in place.

However, in [`YToken::_withdraw`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L161-L172), the wrong address is passed to the `manager.redeem` function. The same issue is also present in [`YTokenL2::_withdraw`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L170-L180):
```solidity
// Override _withdraw to request funds from manager
function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal override nonReentrant notPaused {
    require(receiver != address(0) && owner != address(0) && assets > 0 && shares > 0, "!valid");
    require(!IBlackList(administrator).isBlackListed(caller) && !IBlackList(administrator).isBlackListed(receiver), "blacklisted");
    if (caller != owner) {
        _spendAllowance(owner, caller, shares);
    }
    // Instead of burning shares here, just redirect to Manager
    // The share burning will happen during order execution
    // Don't update totAssets here either, as the assets haven't left the system yet
    // @audit-issue `msg.sender` passed as owner
    IManager(manager).redeem(msg.sender, address(this), asset(), shares, receiver, address(0), "");
}
```

In this call, `msg.sender` is passed as the `owner` to `manager.redeem`, even though the correct `owner` is already passed into `_withdraw`. This works as expected when `msg.sender == owner`, but fails in delegated withdrawal scenarios where a third party is acting on the owner's behalf. In such cases, the `manager.redeem` call may revert, or worse, may burn the wrong user’s tokens if `msg.sender` happens to have shares.


**Impact:** When a third party initiates a withdrawal on behalf of another user (`caller != owner`), the incorrect owner is passed to `manager.redeem`. This can cause the call to revert, blocking the withdrawal. In a worst-case scenario, if `msg.sender` (the caller) also holds shares, it may result in unintended burning of their tokens instead of the intended owner's.

**Proof of Concept:** Place the following test in `yToken.ts` under `describe("Withdraw and Redeem")`, it should pass but fails with `"!balance"`:
```javascript
it("Should handle redeem request through third party", async function () {
  // Grant manager role to deployer for manager operations
  await administrator.grantRoles(MINTER_AND_REDEEMER, [deployer.address]);

  const sharesToRedeem = toN(50, 18); // 18 decimals for shares

  await ytoken.connect(user).approve(u1.address, sharesToRedeem);

  // Spy on manager.redeem call
  const redeemTx = await ytoken.connect(u1).redeem(sharesToRedeem, user.address, user.address);

  // Wait for transaction
  await redeemTx.wait();

  // to check if manager.redeem was called we can check the event of manager contract
  const events = await manager.queryFilter("OrderRequest");
  expect(events.length).to.be.greaterThan(0);
  expect(events[0].args[0]).to.equal(user.address); // owner, who's tokens should be burnt
  expect(events[0].args[1]).to.equal(ytoken.target); // yToken
  expect(events[0].args[2]).to.equal(usdc.target); // Asset
  expect(events[0].args[4]).to.equal(sharesToRedeem); // Amount
  expect(events[0].args[3]).to.equal(user.address); // Receiver
  expect(events[0].args[5]).to.equal(false); // isDeposit (false for redeem)
});
```

**Recommended Mitigation:** Pass the correct `owner` to `manager.redeem` in both `YToken::_withdraw` and `YTokenL2::_withdraw`, instead of using `msg.sender`.

**YieldFi:** Fixed in commit [`adbb6fb`](https://github.com/YieldFiLabs/contracts/commit/adbb6fb27bd23cdedccdaf9c1f484f7780cb354c)

**Cyfrin:** Verified. `owner` is now passed to `manager.redeem`.

\clearpage
## Medium Risk


### Commented-out blacklist check allows restricted transfers

**Description:** In [`PerpetualBond::_update`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L508-L510), the line intended to restrict transfers between non-blacklisted users is currently commented out:

```solidity
function _update(address from, address to, uint256 amount) internal virtual override {
    // Placeholder for Blacklist check
    // require(!IBlackList(administrator).isBlackListed(from) && !IBlackList(administrator).isBlackListed(to), "blacklisted");
```

This effectively disables blacklist enforcement on transfers of `PerpetualBond` tokens.

**Impact:** Blacklisted addresses can freely hold and transfer `PerpetualBond` tokens, bypassing any intended access control or compliance restrictions.

**Recommended Mitigation:** Uncomment the blacklist check in `_update` to enforce transfer restrictions for blacklisted users.

**YieldFi:** Fixed in commit [`a820743`](https://github.com/YieldFiLabs/contracts/commit/a82074332cc1f57eba398100c3a43e8a70a4c8ce)

**Cyfrin:** Verified. Line doing the blacklist check is now uncommented.


### `Manager::_transferFee` returns invalid `feeShares` when `fee` is zero

**Description:** When a user deposits directly into `Manager::deposit`, the protocol fee is calculated via the [`Manager::_transferFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L226-L242) function:

```solidity
function _transferFee(address _yToken, uint256 _shares, uint256 _fee) internal returns (uint256) {
    if (_fee == 0) {
        return _shares;
    }
    uint256 feeShares = (_shares * _fee) / Constants.HUNDRED_PERCENT;

    IERC20(_yToken).safeTransfer(treasury, feeShares);

    return feeShares;
}
```

The issue is that when `_fee == 0`, the function returns the full `_shares` amount instead of returning `0`. This leads to incorrect logic downstream in [`Manager::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L286-L296), where the result is subtracted from the total shares:

```solidity
// transfer fee to treasury, already applied on adjustedShares
uint256 adjustedFeeShares = _transferFee(order.yToken, adjustedShares, _fee);

// Calculate adjusted gas fee shares
uint256 adjustedGasFeeShares = (_gasFeeShares * order.exchangeRateInUnderlying) / currentExchangeRate;

// transfer gas to caller
IERC20(order.yToken).safeTransfer(_caller, adjustedGasFeeShares);

// remaining shares after gas fee
uint256 sharesAfterAllFee = adjustedShares - adjustedFeeShares - adjustedGasFeeShares;
```

If `_fee == 0`, the `adjustedFeeShares` value will incorrectly equal `adjustedShares`, causing `sharesAfterAllFee` to underflow (revert), assuming `adjustedGasFeeShares` is non-zero.

**Impact:** Deposits into the `Manager` contract with a fee of zero will revert if any gas fee is also deducted. In the best-case scenario, the deposit fails. In the worst case—if the subtraction somehow passes unchecked—it could result in zero shares being credited to the user.

**Recommended Mitigation:** Update `_transferFee` to return `0` when `_fee == 0`, to ensure downstream calculations behave correctly:

```diff
  if (_fee == 0) {
-     return _shares;
+     return 0;
  }
```

**YieldFi:** Fixed in commit [`6e76d5b`](https://github.com/YieldFiLabs/contracts/commit/6e76d5beee3ba7a49af6becc58a596a4b67841c3)

**Cyfrin:** Verified. `_transferFee` now returns `0` when `_fee = 0`


### `YtokenL2::previewMint` and `YTokenL2::previewWithdraw` round in favor of user

**Description:** For the L2 `YToken` contracts, assets are not managed directly. Instead, the vault’s exchange rate is provided by an oracle, using the exchange rate from L1 as the source of truth.

This architectural choice requires custom implementations of functions like `previewMint`, `previewDeposit`, `previewRedeem`, and `previewWithdraw`, as well as the internal `_convertToShares` and `_convertToAssets`. These have been re-implemented to rely on the oracle-provided exchange rate instead of local accounting.

However, both `previewMint` and `previewWithdraw` currently perform rounding in favor of the user:

- [`YTokenL2::previewMint`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L249-L250):
  ```solidity
  // Calculate assets based on exchange rate
  return (grossShares * exchangeRate()) / Constants.PINT;
  ```
- [`YTokenL2::previewWithdraw`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L261-L262):
  ```solidity
  // Calculate shares needed for requested assets based on exchange rate
  uint256 sharesWithoutFee = (assets * Constants.PINT) / exchangeRate();
  ```

This behavior contradicts the [security recommendations in EIP-4626](https://eips.ethereum.org/EIPS/eip-4626#security-considerations), which advise rounding in favor of the vault to prevent value leakage.

**Impact:** By rounding in favor of the user, these functions allow users to receive slightly more shares or assets than they should. While the two-step withdrawal process limits the potential for immediate exploitation, this rounding error can result in a slow and continuous value leak from the vault—especially over many transactions or in the presence of automation.

**Recommended Mitigation:** Update `previewMint` and `previewWithdraw` to round in favor of the vault. This can be done by adopting the modified `_convertToShares` and `_convertToAssets` functions with explicit rounding direction, similar to the approach used in the [OpenZeppelin ERC-4626 implementation](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/token/ERC20/extensions/ERC4626Upgradeable.sol#L177-L185).

**YieldFi:** Fixed in commit [`a820743`](https://github.com/YieldFiLabs/contracts/commit/a82074332cc1f57eba398100c3a43e8a70a4c8ce)

**Cyfrin:** Verified. the preview functions now utilizes `_convertToShares` and `_convertToAssets` with the correct rounding direction.


### Missing L2 sequencer uptime check in `OracleAdapter`

**Description:** On L2, the `YToken` exchange rate is provided by custom Chainlink oracles. The exchange rate is queried in [`OracleAdapter::fetchExchangeRate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/OracleAdapter.sol#L52-L77):

```solidity
function fetchExchangeRate(address token) external view override returns (uint256) {
    address oracle = oracles[token];
    require(oracle != address(0), "Oracle not set");

    (, /* uint80 roundId */ int256 answer, , /* uint256 startedAt */ uint256 updatedAt /* uint80 answeredInRound */, ) = IOracle(oracle).latestRoundData();

    require(answer > 0, "Invalid price");
    require(updatedAt > 0, "Round not complete");
    require(block.timestamp - updatedAt < staleThreshold, "Stale price");

    // Get decimals and normalize to 1e18 (PINT)
    uint8 decimals = IOracle(oracle).decimals();

    if (decimals < 18) {
        return uint256(answer) * (10 ** (18 - decimals));
    } else if (decimals > 18) {
        return uint256(answer) / (10 ** (decimals - 18));
    } else {
        return uint256(answer);
    }
}
```

However, this protocol is intended to be deployed on L2 networks such as Arbitrum and Optimism, where it's important to verify that the [sequencer is up](https://docs.chain.link/data-feeds/l2-sequencer-feeds). Without this check, if the sequencer goes down, the latest round data may appear fresh, when in fact it is stale, for advanced users submitting transactions from L1.

**Impact:** If the L2 sequencer goes down, oracle data will stop updating. Actually stale prices can appear fresh and be relied upon incorrectly. This could be exploited if significant price movement occurs during the downtime.

**Recommended Mitigation:** Consider implementing a sequencer uptime check, as shown in the [Chainlink example](https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-consumer-contract), to prevent usage of stale oracle data during sequencer downtime.

**YieldFi:** Fixed in commits [`bb26a71`](https://github.com/YieldFiLabs/contracts/commit/bb26a71e9c57685996f6c853af6df6ed961c2f98) and [`e9c160f`](https://github.com/YieldFiLabs/contracts/commit/e9c160fdfd6dd90650c9537fba73c17cb3c53ea5)

**Cyfrin:** Verified. Sequencer uptime is now verified on L2s.


### Direct YToken deposits can lock funds below minimum withdrawal threshold

**Description:** In [`Manager::deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L134-L155), there is a check enforcing a minimum deposit amount inside [`Manager::_validate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L125-L126):

```solidity
uint256 normalizedAmount = _normalizeAmount(_yToken, _asset, _amount);
require(IERC4626(_yToken).convertToShares(normalizedAmount) >= minSharesInYToken[_yToken], "!minShares");
```

A similar check exists in the [redeem flow](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L157-L197), again via [`Manager::_validate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L130):

```solidity
require(_amount >= minSharesInYToken[_yToken], "!minShares");
```

However, no such minimum is enforced when depositing directly into a `YToken`. In both [`YToken::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L140) and [`YTokenL2::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L150), the only requirement is:

```solidity
require(receiver != address(0) && assets > 0 && shares > 0, "!valid");
```

As a result, a user could deposit an amount that results in fewer shares than `minSharesInYToken[_yToken]`, which cannot be withdrawn through the `Manager` due to its minimum withdrawal check, effectively locking their funds.

**Impact:** Users can bypass the minimum share threshold by depositing directly into a `YToken`. If the resulting share amount is below the minimum allowed for withdrawal via the `Manager`, the user will be unable to exit their position. This can lead to unintentionally locked funds and a poor user experience.

**Recommended Mitigation:** Consider enforcing the `minSharesInYToken[_yToken]` threshold in `YToken::_deposit` and `YTokenL2::_deposit` to prevent deposits that are too small to be withdrawn. Additionally, consider validating post-withdrawal balances to ensure users are not left with non-withdrawable "dust" (i.e., require remaining shares to be either `0` or `> minSharesInYToken[_yToken]`).

**YieldFi:** Fixed in commit [`221c7d0`](https://github.com/YieldFiLabs/contracts/commit/221c7d0644af8fcb4d229d3e95e45323dc6f99a6)

**Cyfrin:** Verified. Minimum shares is now verified in the YToken contracts. Manager also verifies that there is no dust left after redeem.

\clearpage
## Low Risk


### Hardcoded `extraArgs` violates CCIP best practices

**Description:** When sending cross-chain messages via CCIP, Chainlink recommends keeping the `extraArgs` parameter mutable to allow for future upgrades or configuration changes, as outlined in their [best practices](https://docs.chain.link/ccip/best-practices#using-extraargs).

However, this recommendation is not followed in [`BridgeCCIP::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L126-L133), where `extraArgs` is hardcoded:
```solidity
// Sends the message to the destination endpoint
Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
    receiver: abi.encode(_receiver), // ABI-encoded receiver address
    data: abi.encode(_encodedMessage), // ABI-encoded string
    tokenAmounts: new Client.EVMTokenAmount[](0), // Empty array indicating no tokens are being sent
    // @audit-issue `extraArgs` hardcoded
    extraArgs: Client._argsToBytes(Client.EVMExtraArgsV2({ gasLimit: 200_000, allowOutOfOrderExecution: true })),
    feeToken: address(0) // For msg.value
});
```

**Impact:** Because `extraArgs` is hardcoded, any future changes would require deploying a new version of the bridge contract.

**Recommended Mitigation:** Consider making `extraArgs` mutable by either passing it as a parameter to the `send` function or deriving it from configurable contract storage.

**YieldFi:** Fixed in commits [`3cc0b23`](https://github.com/YieldFiLabs/contracts/commit/3cc0b2331c35327a43e95176ce6c5578f145c0ee) and [`fd4b7ab5`](https://github.com/YieldFiLabs/contracts/commit/fd4b7ab57a5ae2ac366b4d9d086eb372defc7f8c)

**Cyfrin:** Verified. `extraArgs` is now passed as a parameter to the call.


### Static `gasLimit` will result in overpayment

**Description:** Since [unspent gas is not refunded](https://docs.chain.link/ccip/best-practices#setting-gaslimit), Chainlink recommends carefully setting the `gasLimit` within the `extraArgs` parameter to avoid overpaying for execution.

In [`BridgeCCIP::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L131), the `gasLimit` is hardcoded to `200_000`, which is also Chainlink’s default:

```solidity
extraArgs: Client._argsToBytes(Client.EVMExtraArgsV2({ gasLimit: 200_000, allowOutOfOrderExecution: true })),
```

This hardcoded value directly affects every user bridging tokens, as they will be consistently overpaying for execution costs on the destination chain.

**Recommended Mitigation:** A more efficient approach would be to measure the gas usage of the `_ccipReceive` function using tools like Hardhat or Foundry and set the `gasLimit` accordingly—adding a margin for safety. This ensures that the protocol avoids overpaying for gas on every cross-chain message.

This issue also reinforces the importance of making `extraArgs` mutable, so the gas limit and other parameters can be adjusted if execution costs change over time (e.g., due to protocol upgrades like [EIP-1884](https://eips.ethereum.org/EIPS/eip-1884)).

**YieldFi:** Fixed in commit [`3cc0b23`](https://github.com/YieldFiLabs/contracts/commit/3cc0b2331c35327a43e95176ce6c5578f145c0ee)

**Cyfrin:** Verified. `extraArgs` is now passed as a parameter to the call.


### Unverified `_receiver` can cause irrecoverable token loss

**Description:** When a user bridges their YTokens using CCIP, they call [`BridgeCCIP::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L117-L158). One of the parameters passed to this function is `_receiver`, which is intended to be the destination contract on the receiving chain:

```solidity
function send(address _yToken, uint64 _dstChain, address _to, uint256 _amount, address _receiver) external payable notBlacklisted(msg.sender) notBlacklisted(_to) notPaused {
    require(_amount > 0, "!amount");
    require(lockboxes[_yToken] != address(0), "!token !lockbox");
    require(IERC20(_yToken).balanceOf(msg.sender) >= _amount, "!balance");
    require(_to != address(0), "!receiver");
    require(tokens[_yToken][_dstChain] != address(0), "!destination");

    bytes memory _encodedMessage = abi.encode(_dstChain, _to, tokens[_yToken][_dstChain], _amount, Constants.BRIDGE_SEND_HASH);

    // Sends the message to the destination endpoint
    Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
        // @audit-issue `_receiver` not verified
        receiver: abi.encode(_receiver), // ABI-encoded receiver address
        data: abi.encode(_encodedMessage), // ABI-encoded string
        tokenAmounts: new Client.EVMTokenAmount[](0), // Empty array indicating no tokens are being sent
        extraArgs: Client._argsToBytes(Client.EVMExtraArgsV2({ gasLimit: 200_000, allowOutOfOrderExecution: true })),
        feeToken: address(0) // For msg.value
    });
```

However, the `_receiver` parameter is not validated. If the user provides an incorrect or malicious address, the message may be delivered to a contract that cannot handle it, resulting in unrecoverable loss of the bridged tokens.

**Recommended Mitigation:** Validate the `_receiver` address against a trusted mapping, such as the `peers` mapping mentioned in a previous finding, to ensure it corresponds to a legitimate contract on the destination chain.

**YieldFi:** Fixed in commit [`a03341d`](https://github.com/YieldFiLabs/contracts/commit/a03341d8103ba08473ea1cd39e64192608692aca)

**Cyfrin:** Verified. `_receiver ` is now verified to be a trusted peer.


### Hardcoded CCIP `feeToken` prevents LINK discount usage

**Description:** In `BridgeCCIP::send`, the [`feeToken`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L126-L133) parameter is hardcoded:
```solidity
// Sends the message to the destination endpoint
Client.EVM2AnyMessage memory evm2AnyMessage = Client.EVM2AnyMessage({
    receiver: abi.encode(_receiver), // ABI-encoded receiver address
    data: abi.encode(_encodedMessage), // ABI-encoded string
    tokenAmounts: new Client.EVMTokenAmount[](0), // Empty array indicating no tokens are being sent
    extraArgs: Client._argsToBytes(Client.EVMExtraArgsV2({ gasLimit: 200_000, allowOutOfOrderExecution: true })),
    // @audit-issue hardcoded fee token
    feeToken: address(0) // For msg.value
});
```

Chainlink CCIP supports paying fees using either the native gas token or `LINK`. By hardcoding `feeToken = address(0)`, the protocol forces all users to pay with the native gas token, removing flexibility.

This design choice simplifies implementation but has cost implications: CCIP offers a [10% fee discount](https://docs.chain.link/ccip/billing#network-fee-table) when using `LINK`, so users holding `LINK` are unable to take advantage of these reduced fees.

**Recommended Mitigation:** Consider allowing users to choose their preferred payment token—either `LINK` or native gas—based on their individual cost and convenience preferences.

**YieldFi:** Fixed in commits [`3cc0b23`](https://github.com/YieldFiLabs/contracts/commit/3cc0b2331c35327a43e95176ce6c5578f145c0ee) and [`e9c160f`](https://github.com/YieldFiLabs/contracts/commit/e9c160fdfd6dd90650c9537fba73c17cb3c53ea5)

**Cyfrin:** Verified.


### Chainlink router configured twice

**Description:** In `BridgeCCIP`, there is a dedicated storage slot for the CCIP router address, [`router`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L32-L33):

```solidity
contract BridgeCCIP is CCIPReceiver, Ownable {
    address public router;
```

This value can be updated by the admin through [`BridgeCCIP::setRouter`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L69-L73):

```solidity
function setRouter(address _router) external onlyAdmin {
    require(_router != address(0), "!router");
    router = _router;
    emit SetRouter(msg.sender, _router);
}
```

The `router` is then used in [`BridgeCCIP::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L157) to send messages via CCIP:

```solidity
IRouterClient(router).ccipSend{ value: msg.value }(_dstChain, evm2AnyMessage);
```

However, the inherited `CCIPReceiver` contract already defines an immutable router address (`i_ccipRouter`), which is used to validate that incoming CCIP messages originate from the correct router.

This introduces an inconsistency: if `BridgeCCIP.router` is changed, the contract will continue to *send* messages via the new router, but *receive* messages only from the original, immutable `i_ccipRouter`. This mismatch could break cross-chain communication or make message delivery non-functional.

**Recommended Mitigation:** Since the router address in `CCIPReceiver` is immutable, any future change to the router would already require redeployment of the `BridgeCCIP` contract. Therefore, the `router` storage slot and the `setRouter` function in `BridgeCCIP` are redundant and potentially misleading. We recommend removing both and relying exclusively on the `i_ccipRouter` value inherited from `CCIPReceiver`.

**YieldFi:** Fixed in commit [`3cc0b23`](https://github.com/YieldFiLabs/contracts/commit/3cc0b2331c35327a43e95176ce6c5578f145c0ee)

**Cyfrin:** Verified. `router` removed and `i_ccipRouter` used from the inherited contract.


### Missing vesting check in `PerpetualBond::setVestingPeriod`

**Description:** Both `YToken` and `PerpetualBond` support reward vesting through a configurable vesting period. The admin can update this period via the `setVestingPeriod` function. However, there is an inconsistency in how the two contracts validate changes to the vesting period:

- [`YToken::setVestingPeriod`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L52-L56) includes a check to ensure that no rewards are currently vesting:
  ```solidity
  function setVestingPeriod(uint256 _vestingPeriod) external onlyAdmin {
      require(getUnvestedAmount() == 0, "!vesting");
      require(_vestingPeriod > 0, "!vestingPeriod");
      vestingPeriod = _vestingPeriod;
  }
  ```

- [`PerpetualBond::setVestingPeriod`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L184-L188) lacks this check:
  ```solidity
  function setVestingPeriod(uint256 _vestingPeriod) external onlyAdmin {
      // @audit-issue no check for `getUnvestedAmount() == 0`
      require(_vestingPeriod > 0, "!vestingPeriod");
      vestingPeriod = _vestingPeriod;
      emit VestingPeriodUpdated(_vestingPeriod);
  }
  ```

This means the vesting period in `PerpetualBond` can be modified even while tokens are still vesting, which could lead to inconsistent or unexpected vesting behavior.

**Recommended Mitigation:** To align with the `YToken` implementation and ensure consistency, add a check in `PerpetualBond::setVestingPeriod` to ensure `getUnvestedAmount() == 0` before allowing updates to the vesting period.

**YieldFi:** Fixed in commit [`f0bf88c`](https://github.com/YieldFiLabs/contracts/commit/f0bf88cb51a92a119cdde896c4b0118be1d1a031)

**Cyfrin:** Verified. `unvestedAmount` is now checked.


### Balance check for yield claims in `PerpetualBond::_validate` can be easily bypassed

**Description:** In [`PerpetualBond::_validate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L312-L314), there's a check to ensure that users have a non-zero balance before claiming yield:

```solidity
// Yield claim
require(balanceOf(_caller) > 0, "!bond balance"); // Caller must hold bonds to claim yield
require(accruedRewardAtCheckpoint[_caller] > 0, "!claimable yield"); // Must have claimable yield
```

However, this check can be bypassed by holding a trivial amount, such as 1 wei, of `PerpetualBond` tokens. A more meaningful check would ensure that the user's balance exceeds the `minimumTxnThreshold`, similar to how other parts of the contract enforce value-based thresholds.

Consider updating the balance check to compare against `minimumTxnThreshold` using the bond-converted value:

```diff
- require(balanceOf(_caller) > 0, "!bond balance");
+ require(_convertToBond(balanceOf(_caller)) > minimumTxnThreshold, "!bond balance");
```

Additionally, the second check on `accruedRewardAtCheckpoint[_caller]` is redundant, since [`PerpetualBond::requestYieldClaim`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L374-L378) already performs a value-based threshold check:

```solidity
// Convert yield amount to bond tokens for threshold comparison
uint256 yieldInBondTokens = _convertToBond(claimableYieldAmount);

// Check if the yield claim is worth executing
require(yieldInBondTokens >= minimumTxnThreshold, "!min txn threshold");
```

This makes the `accruedRewardAtCheckpoint` check in `_validate` unnecessary.

**YieldFi:** Fixed in commit [`f0bf88c`](https://github.com/YieldFiLabs/contracts/commit/f0bf88cb51a92a119cdde896c4b0118be1d1a031)

**Cyfrin:** Verified. Balance check removed as the user might still have yield even if they have no tokens (sold/transferred). Yield check in `_validate` is also removed as it's redundant.

\clearpage
## Informational


### `PerpetualBond.epoch` not updated after yield distribution

**Description:** In [`PerpetualBond::distributeBondYield`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L215-L241) the caller is supposed to provide a `nonce` that matches [`epoch + 1`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L220-L221):
```solidity
function distributeBondYield(uint256 _yieldAmount, uint256 nonce) external notPaused onlyRewarder {
    require(nonce == epoch + 1, "!epoch");
```
However, `epoch` is never incremented afterwards, consider incrementing `epoch`.

**YieldFi:** Fixed in commit [`5c1f0e7`](https://github.com/YieldFiLabs/contracts/commit/5c1f0e7a805caf1d0fddbc5a15c8b6797a424467)

**Cyfrin:** Verified. `epoch` now is incremented with the new `nonce`.


### Order not eligible at `eligibleAt`

**Description:** Both in [`PerpetualBond::executeOrder`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L411) and [`Manager::executeOrder`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L208) there's a check that the order executed is still eligible:
```solidity
require(block.timestamp > order.eligibleAt, "!waitingPeriod");
```
`eligibleAt` indicates that the order should be eligible at this timestamp which is not what the check verifies. Consider changing `>` to `>=`:
```diff
- require(block.timestamp > order.eligibleAt, "!waitingPeriod");
+ require(block.timestamp >= order.eligibleAt, "!waitingPeriod");
```

**YieldFi:** Fixed in commit [`e9c160f`](https://github.com/YieldFiLabs/contracts/commit/e9c160fdfd6dd90650c9537fba73c17cb3c53ea5)

**Cyfrin:** Verified.


### `_receiverGas` check excludes minimum acceptable value

**Description:** In the LayerZero bridge contracts [`BridgeLR::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/BridgeLR.sol#L76) and [`BridgeMB::send`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/BridgeMB.sol#L66), there's a check to ensure the user has provided sufficient `_receiverGas`:

```solidity
require(_receiverGas > MIN_RECEIVER_GAS, "!gas");
```

The variable name `MIN_RECEIVER_GAS` suggests that the specified amount should be *inclusive*, meaning the minimum acceptable value is valid. However, the current `>` check excludes `MIN_RECEIVER_GAS` itself. To align with the semantic expectation, consider changing the comparison to `>=`:

```diff
- require(_receiverGas > MIN_RECEIVER_GAS, "!gas");
+ require(_receiverGas >= MIN_RECEIVER_GAS, "!gas");
```

Same applies to the call [`Bridge::setMIN_RECEIVER_GAS`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L53) and the check in [`Bridge::quote`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L85) as well.

**YieldFi:** Fixed in commit [`9aa242b`](https://github.com/YieldFiLabs/contracts/commit/9aa242b7351314fe07160e98699d8da14a1b9bc2)

**Cyfrin:** Verified.


### Unused errors

**Description:** In the library [`Common`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Common.sol#L5-L6) there are two unused errors:
```solidity
error SignatureVerificationFailed();
error BadSignature();
```
Consider removing these.

**YieldFi:** Fixed in commit [`9aa242b`](https://github.com/YieldFiLabs/contracts/commit/9aa242b7351314fe07160e98699d8da14a1b9bc2)

**Cyfrin:** Verified.


### Potential risk if callback logic is enabled in the future

**Description:** Both the `Manager` and `PerpetualBond` contracts implement a two-step process for user interactions. As part of these calls, users can provide a `_callback` address and accompanying `_callbackData`. For example, here are the parameters for [`Manager::deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L144):

```solidity
function deposit(..., address _callback, bytes calldata _callbackData) external notPaused nonReentrant {
```

However, these parameters are currently not passed along when the request is stored, as shown later in [`Manager::deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L153):

```solidity
uint256 receiptId = IReceipt(receipt).mint(msg.sender, Order(..., address(0), ""));
```

Here, `address(0)` and empty `""` are hardcoded instead of using the user-supplied values.

Later, in the `executeOrder` flow (e.g., [`Manager::executeOrder`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L219-L223)), the callback is conditionally executed:

```solidity
// Execute the callback
if (order.callback != address(0)) {
    (bool success, ) = order.callback.call(order.callbackData);
    require(success, "callback failed");
}
```

If the original user-provided `_callback` and `_callbackData` were passed through and used here, it would pose a serious security risk. Malicious users could exploit this to execute arbitrary external calls and potentially steal tokens that are approved to the `Manager` or `PerpetualBond` contracts.

If callback functionality is not currently intended, consider removing or disabling the `_callback` and `_callbackData` parameters entirely to avoid the risk of these being enabled in the future. Alternatively, ensure strict validation and access control if support for callbacks is added later.


**YieldFi:** Acknowledged.


### Lack of `_disableInitializers` in upgradeable contracts

**Description:** YieldFi utilizes upgradeable contracts. It's [best practice](https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#initializing_the_implementation_contract) to disable the ability to initialize the implementation contracts.

Consider adding a constructor with the OpenZeppelin `_disableInitializers` in all the upgradeable contracts:
```solidity
constructor() {
    _disableInitializers();
}
```

**YieldFi:** Fixed in commit [`584b268`](https://github.com/YieldFiLabs/contracts/commit/584b268a75a8f7c7f10eda46efaaa3ebbe4f0159)

**Cyfrin:** Verified. Constructor with `_disableInitializers` added to all upgradeable contracts.


### Unused imports

**Description:** Consider removing the following unused imports:

- contracts/bridge/Bridge.sol [Line: 7](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L7)
- contracts/bridge/Bridge.sol [Line: 9](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L9)
- contracts/bridge/Bridge.sol [Line: 13](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L13)
- contracts/bridge/Bridge.sol [Line: 15](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L15)
- contracts/bridge/Bridge.sol [Line: 18](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L18)
- contracts/bridge/Bridge.sol [Line: 20](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L20)
- contracts/bridge/BridgeMB.sol [Line: 17](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/BridgeMB.sol#L17)
- contracts/bridge/ccip/BridgeCCIP.sol [Line: 4](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L4)
- contracts/bridge/ccip/BridgeCCIP.sol [Line: 13](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L13)
- contracts/core/Manager.sol [Line: 6](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L6)
- contracts/core/Manager.sol [Line: 15](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L15)
- contracts/core/Manager.sol [Line: 17](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L17)
- contracts/core/OracleAdapter.sol [Line: 6](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/OracleAdapter.sol#L6)
- contracts/core/PerpetualBond.sol [Line: 7](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L7)
- contracts/core/PerpetualBond.sol [Line: 13](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L13)
- contracts/core/interface/IPerpetualBond.sol [Line: 4](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/interface/IPerpetualBond.sol#L4)
- contracts/core/l1/LockBox.sol [Line: 10](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/LockBox.sol#L10)
- contracts/core/l1/LockBox.sol [Line: 13](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/LockBox.sol#L13)
- contracts/core/l1/Yield.sol [Line: 5](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L5)
- contracts/core/l1/Yield.sol [Line: 10](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L10)
- contracts/core/l1/Yield.sol [Line: 11](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L11)
- contracts/core/l1/Yield.sol [Line: 12](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L12)
- contracts/core/l1/Yield.sol [Line: 13](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L13)
- contracts/core/l1/Yield.sol [Line: 14](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L14)
- contracts/core/l1/Yield.sol [Line: 16](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/Yield.sol#L16)
- contracts/core/tokens/YToken.sol [Line: 8](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L8)
- contracts/core/tokens/YToken.sol [Line: 14](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L14)
- contracts/core/tokens/YTokenL2.sol [Line: 12](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L12)

**YieldFi:** Fixed in commit [`8264429`](https://github.com/YieldFiLabs/contracts/commit/826442914cb9829aa302dbaef0741659cc5a1a67)

**Cyfrin:** Verified.


### Unused constants

**Description:** In `Constants.sol` there are a some unused constants, consider removing thses:
* [#L21: `SIGNER_ROLE`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L21)
* [#L38: `VESTING_PERIOD`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L38)
* [#L41 `MAX_COOLDOWN_PERIOD`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L41)
* [#L44: `MIN_COOLDOWN_PERIOD`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L44)
* [#L47 `ETH_SIGNED_MESSAGE_PREFIX`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L47)
* [#L50`REWARD_HASH`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L50)
* [#L56-L59 `DEPOSIT`, `WITHDRAW`, `DEPOSIT_L2`, `WITHDRAW_L2`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/libs/Constants.sol#L56-L59)

**YieldFi:** Fixed in commit [`125ec4a`](https://github.com/YieldFiLabs/contracts/commit/125ec4a944c436e587d7380b8c4bf6232d3264aa)

**Cyfrin:** Verified.


### Lack of event emissions on important state changes

**Description:** The following functions change state but doesn't emit an event. Consider emitting an event from the following:


- [`Access::setAdministrator`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/administrator/Access.sol#L76)
- [`Administrator::cancelAdminRole`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/administrator/Administrator.sol#L109)
- [`Administrator::cancelTimeLockUpdate`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/administrator/Administrator.sol#L148)
- [`Bridge::setMIN_RECEIVER_GAS`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/Bridge.sol#L52)
- [`BridgeMB::setManager`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/BridgeMB.sol#L42)
- [`BridgeCCIP::setManager`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L82)
- [`Manager::setTreasury`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L52)
- [`Manager::setReceipt`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L61)
- [`Manager::setCustodyWallet`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L71)
- [`Manager::setMinSharesInYToken`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L81)
- [`OracleAdapter::setStaleThreshold`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/OracleAdapter.sol#L48)
- [`LockBox::setManager`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/LockBox.sol#L31)
- [`YToken::setManager`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L42)
- [`YToken::setYield`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L47)
- [`YToken::setVestingPeriod`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L52)
- [`YToken::setFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L62)
- [`YToken::setGasFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L72)
- [`YToken::updateTotalAssets`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L179)
- [`YTokenL2::setManager`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L83)
- [`YTokenL2::setFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L92)
- [`YTokenL2::setGasFee`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L102)


**YieldFi:** Fixed in commit [`b978ddf`](https://github.com/YieldFiLabs/contracts/commit/b978ddfc6ba8299a6045fde5e065f5fc276c02f7)

**Cyfrin:** Verified.


### Access to `LockBox::unlock` doesn't follow principle of least privilege

**Description:** The function [`LockBox::unlock`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/l1/LockBox.sol#L97) has the modifier [`onlyBridgeOrLockBox`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/administrator/Access.sol#L37-L40) which allows callers with either the role `BRIDGE_ROLE` or `LOCKBOX_ROLE` to access the call.

The function is however only called from the bridge contracts. Consider removing the access from the `LOCKBOX_ROLE` to follow principle of least privileges.

**YieldFi:** Fixed in commit [`f0c751a`](https://github.com/YieldFiLabs/contracts/commit/f0c751a25d3cf8d46661f7508b72193c88e6fc91)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### `BridgeCCIP.isL1` can be immutable

**Description:** [`BridgeCCIP.isL1`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L34) is only [assigned](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/bridge/ccip/BridgeCCIP.sol#L44) in the constructor. Therefore it can be made immutable as immutable values are cheaper to read.

Consider making `BridgeCCIP.isL1` immutable.

**YieldFi:** Fixed in commit [`823b010`](https://github.com/YieldFiLabs/contracts/commit/823b010d74fd55fb88b31619c1a94dac2ef65ad3)

**Cyfrin:** Verified.


### `bondFaceValue` read in `PerpetualBond::_convertToBond` can be cached

**Description:** The storage value `bondFaceValue` is read twice in [`PerpetualBond::__convertToBond`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L291-L294):
```solidity
function _convertToBond(uint256 assetAmount) internal view returns (uint256) {
    if (bondFaceValue == 0) return 0; // Prevent division by zero
    return (assetAmount * 1e18) / bondFaceValue;
}
```
The value can be cached and only read once:
```solidity
function _convertToBond(uint256 assetAmount) internal view returns (uint256) {
    // cache read
    uint256 _bondFaceValue = bondFaceValue;
    if (_bondFaceValue == 0) return 0; // Prevent division by zero
    return (assetAmount * 1e18) / _bondFaceValue;
}
```

**YieldFi:** Fixed in commit [`823b010`](https://github.com/YieldFiLabs/contracts/commit/823b010d74fd55fb88b31619c1a94dac2ef65ad3)

**Cyfrin:** Verified.


### Unnecessary external call in `YToken::_decimalsOffset` and `YTokenL2::_decimalsOffset`

**Description:** In [`YToken::_decimalsOffset`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YToken.sol#L314-L316) and [`YTokenL2::_decimalsOffset`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/tokens/YTokenL2.sol#L314-L316) the decimals of the underlying token is queried:
```solidity
function _decimalsOffset() internal view virtual override returns (uint8) {
    return 18 - IERC20Metadata(asset()).decimals();
}
```
This value is however already stored in the OpenZeppelin base contract `ERC4626Upgradeable` and can be used instead of an external call.

**YieldFi:** Acknowledged.


### Order read twice in `Manager::executeOrder`

**Description:** In [`Manager::executeOrder`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L207-L214) the order data is fetched from the Receipt:
```solidity
Order memory order = IReceipt(receipt).readOrder(_receiptId);
require(block.timestamp > order.eligibleAt, "!waitingPeriod");
require(_fee <= Constants.ONE_PERCENT, "!fee");
if (order.orderType) {
    _deposit(msg.sender, _receiptId, _amount, _fee, _gas);
} else {
    _withdraw(msg.sender, _receiptId, _amount, _fee, _gas);
}
```
Then order is read again in both [`Manager::_deposit`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L252-L253):
```solidity
function _deposit(address _caller, uint256 _receiptId, uint256 _shares, uint256 _fee, uint256 _gasFeeShares) internal {
    Order memory order = IReceipt(receipt).readOrder(_receiptId);
```

and [`Manager::_withdraw`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/Manager.sol#L327-L328):
```solidity
function _withdraw(address _caller, uint256 _receiptId, uint256 _assetAmountOut, uint256 _fee, uint256 _gasFeeShares) internal {
    Order memory order = IReceipt(receipt).readOrder(_receiptId);
```

This extra read is unnecessary. Consider passing the `Order memory order` as a parameter to `Manager::_deposit` and `Manager::_withdraw` instead. Thus saving to read the data again from the receipt:
```solidity
function _deposit(..., Order memory order) internal {

function _withdraw(..., Order memory order) internal {
```

**YieldFi:** Fixed in commit [`823b010`](https://github.com/YieldFiLabs/contracts/commit/823b010d74fd55fb88b31619c1a94dac2ef65ad3)

**Cyfrin:** Verified.

\clearpage