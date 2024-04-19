**Lead Auditors**

[Dacian](https://twitter.com/DevDacian)

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## High Risk


### On-chain slippage calculation using exchange rate derived from `pool.slot0` can be easily manipulated

**Description:** [On-chain slippage calculation](https://dacian.me/defi-slippage-attacks#heading-on-chain-slippage-calculation-can-be-manipulated) using price from [`pool.slot0` can be easily manipulated](https://solodit.xyz/issues/h-4-no-slippage-protection-during-repayment-due-to-dynamic-slippage-params-and-easily-influenced-slot0-sherlock-real-wagmi-2-git) causing users to receive less tokens than they intended.

**Impact:** Swaps can result in users receiving less tokens than they intended.

**Proof of Concept:** `Portico::calcMinAmount` attempts to on-chain calculate the minimum amount of tokens a swap should return. It does this using:
1) L85 taking as input either the `maxSlippageStart` or `maxSlippageFinish` parameters which users can specify for the 2 possible swaps,
2) L135 getting the current exchange rate on-chain by reading price information from `pool.slot0`

The problem is that [`pool.slot0` is easy to manipulate using flash loans](https://solodit.xyz/issues/h-02-use-of-slot0-to-get-sqrtpricelimitx96-can-lead-to-price-manipulation-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git) so the actual exchange rate used in the slippage calculation could be far worse than what the user expects; it is very likely users will be continually exploited via sandwich attacks on the swaps.

**Recommended Mitigation:**
1. If price information is required on-chain, use [Uniswap V3 TWAP](https://docs.uniswap.org/concepts/protocol/oracle) instead of `pool.slot0` for more manipulation-resistant price info (note: this does [not offer the same level of protection on Optimism](https://docs.uniswap.org/concepts/protocol/oracle#oracles-integrations-on-layer-2-rollups)),
2. Use `minAmountReceivedStart` and `minAmountReceivedFinish` parameters instead of  `maxSlippageStart` and `maxSlippageFinish` and remove the on-chain slippage calculation. There is no "safe" way to calculate slippage on-chain. If users specify % slippage params, calculate the exact minimum amounts off-chain and pass these in as input.

**Wormhole:**
Fixed in commit af089d6.

**Cyfrin:** Verified.

\clearpage
## Medium Risk


### Checking `bool` return of ERC20 `approve` and `transfer` breaks protocol for mainnet USDT and similar tokens which don't return true

**Description:** Checking `bool` return of ERC20 `approve` and `transfer` breaks protocol for mainnet USDT and similar tokens which [don't return true](https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#code) even though the calls were successful.

**Impact:** Protocol won't work with mainnet USDT and similar tokens.

**Proof of Concept:** Portico.sol L58, 61, 205, 320, 395, 399.

**Recommended Mitigation:** Use [SafeERC20](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol) or [SafeTransferLib](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol).

**Wormhole:**
Fixed in commits 3f08be9 & 55f93e2.

**Cyfrin:** Verified.


### No precision scaling or minimum received amount check when subtracting `relayerFeeAmount` can revert due to underflow or return less tokens to user than specified

**Description:** `PorticoFinish::payOut` L376 attempts to subtract the `relayerFeeAmount` from the final post-bridge and post-swap token balance:
```solidity
finalUserAmount = finalToken.balanceOf(address(this)) - relayerFeeAmount;
```

There is [no precision scaling](https://dacian.me/precision-loss-errors#heading-no-precision-scaling) to ensure that `PorticoFinish`'s token contract balance and `relayerFeeAmount` are in the same decimal precision; if the `relayerFeeAmount` has 18 decimal places but the token is USDC with only 6 decimal places, this can easily revert due to underflow resulting in the bridged tokens being stuck.

An excessively high `relayerFeeAmount` could also significantly reduce the amount of post-bridge and post-swap tokens received as there is no check on the minimum amount of tokens the user will receive after deducting `relayerFeeAmount`. This current configuration is an example of the ["MinTokensOut For Intermediate, Not Final Amount"](https://dacian.me/defi-slippage-attacks#heading-mintokensout-for-intermediate-not-final-amount) vulnerability class; as the minimum received tokens check is before the deduction of `relayerFeeAmount` a user will always receive less tokens than their specified minimum if `relayerFeeAmount > 0`.

**Impact:** Bridged tokens stuck or user receives less tokens than their specified minimum.

**Recommended Mitigation:** Ensure that token balance and `relayerFeeAmount` have the same decimal precision before combining them. Alternatively check for underflow and don't charge a fee if this would be the case. Consider enforcing the user-specified minimum output token check again when deducting `relayerFeeAmount`, and if this would fail then decrease `relayerFeeAmount` such that the user at least receives their minimum specified token amount.

Another option is to check that even if it doesn't underflow, that the remaining amount after subtracting `relayerFeeAmount` is a high percentage of the bridged amount; this would prevent a scenario where `relayerFeeAmount` takes a large part of the bridged amount, effectively capping `relayerFeeAmount` to a tiny % of the post-bridge and post-swap funds. This scenario can still result in the user receiving less tokens than their specified minimum however.

From the point of view of the smart contract, it should protect itself against the possibility of the token amount and `relayerFeeAmount` being in different decimals or that `relayerFeeAmount` would be too high, similar to how for example L376 inside `payOut` doesn't trust the bridge reported amount and checks the actual token balance.

**Wormhole:**
Fixed in commit 05ba84d by adding an underflow check. Any misbehavior is due to bad user input and should be corrected off-chain. Only the user is able to set the relayer fee in the input parameters.

**Cyfrin:** Verified potential underflow due to mismatched precision between relayer fee & token amount is now handled. The implementation now favors the relayer however this is balanced by the fact that only the user can set the relayer fee, so the attack surface is limited to self-inflicted harm. If in the future another entity such as the relayer could set the relayer fee then this could be used to drain the bridged tokens, but with the current implementation this is not possible unless the user sets an incorrectly large relayer fee which is self-inflicted.

\clearpage
## Low Risk


### Use low level `call()` to prevent gas griefing attacks when returned data not required

**Description:** Using `call()` when the returned data is not required unnecessarily exposes to gas griefing attacks from huge returned data payload. For example:
```solidity
(bool sentToUser, ) = recipient.call{ value: finalUserAmount }("");
require(sentToUser, "Failed to send Ether");
```

Is the same as writing:
```solidity
(bool sentToUser, bytes memory data) = recipient.call{ value: finalUserAmount }("");
require(sentToUser, "Failed to send Ether");
```

In both cases the returned data will be copied into memory exposing the contract to gas griefing attacks, even though the returned data is not used at all.

**Impact:** Contract unnecessarily exposed to gas griefing attacks.

**Recommended Mitigation:** Use a low-level call when the returned data is not required, eg:
```solidity
bool sent;
assembly {
    sent := call(gas(), recipient, finalUserAmount, 0, 0, 0, 0)
}
if (!sent) revert Unauthorized();
```

Consider using [ExcessivelySafeCall](https://github.com/nomad-xyz/ExcessivelySafeCall).

**Wormhole:**
Fixed in commit 5f3926b.

**Cyfrin:** Verified.

\clearpage
## Informational


### Missing sanity check for address validity in `PorticoBase::unpadAddress`

**Description:** `PorticoBase::unpadAddress` is a re-implementation of [`Utils::fromWormholeFormat`](https://github.com/wormhole-foundation/wormhole-solidity-sdk/blob/main/src/Utils.sol#L10-L15) from the Wormhole Solidity SDK, but is missing a sanity check for address validity which is in the SDK implementation.

**Recommended Mitigation:** Consider adding the address validity sanity check to `PorticoBase::unpadAddress`.

**Wormhole:**
Fixed in commit 6208dd1.

**Cyfrin:** Verified.


### Move payable `receive()` function from `PorticoBase` into `PorticoFinish`

**Description:** Move payable `receive()` function from `PorticoBase` into `PorticoFinish` since `PorticoFinish` is the only contract which needs to receive eth when it calls `WETH.withdraw()`.

`PorticoStart` which also inherits from `PorticoBase` never needs to receive eth apart from the payable `start` function, so does not need to have or inherit a payable `receive()` function.

**Wormhole:**
Fixed in commit 6208dd1.

**Cyfrin:** Verified.


### `Portico::start` not used internally could be marked external

**Description:** `Portico::start` not used internally could be marked external.

**Wormhole:**
Fixed in commit 6208dd1.

**Cyfrin:** Verified.


### `TokenBridge::isDeployed` could be declared pure

**Description:** `TokenBridge::isDeployed` could be declared pure. Also not sure what the point of this contract is; if it is used for testing perhaps move it into a `mocks` directory.

**Wormhole:**
Removed this contract.

**Cyfrin:** Verified.


### Remove unused code

**Description:**
```solidity
File: PorticoStructs.sol L67-79:
  //16 + 32 + 24 + 24 + 16 + 16 + 8 + 8 == 144
  struct packedData {
    uint16 recipientChain;
    uint32 bridgeNonce;
    uint24 startFee;
    uint24 endFee;
    int16 slipStart;
    int16 slipEnd;
    bool wrap;
    bool unwrap;
  }
```

**Wormhole:**
Fixed in commit 6208dd1.

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Fail fast in `_completeTransfer` by checking for incorrect address/chainId immediately after calling `TOKENBRIDGE.parseTransferWithPayload`

**Description:** Fail fast in `_completeTransfer` by checking for incorrect address/chainId immediately after calling `TOKENBRIDGE.parseTransferWithPayload` per the [example code](https://docs.wormhole.com/wormhole/quick-start/tutorials/hello-token#receiving-a-token).

**Impact:** Gas optimization; want to fail fast instead of performing a number of unnecessary operations then failing later anyway.

**Proof of Concept:** Portico.sol L278-300.

**Recommended Mitigation:** Perform the L300 check immediately after L278.

**Wormhole:**
Fixed in commit 5f3926b.

**Cyfrin:** Verified.


### Don't initialize variables with default value

**Description:** Don't initialize variables with default value, eg in `TickMath::getTickAtSqrtRatio()`:

```solidity
uint256 msb = 0;
```

**Impact:** Gas optimization.

**Wormhole:**
`TickMath` is no longer used as on chain slippage calculations are not being done anymore.


### Use custom errors instead of revert error strings

**Description:** Using custom errors instead of revert error strings to reduce deployment and runtime cost:

```solidity
File: Portico.sol

64:         require(token.approve(spender, 0), "approval reset failed");

67:       require(token.approve(spender, 2 ** 256 - 1), "infinite approval failed");

185:     require(poolExists, "Pool does not exist");

215:       require(value == params.amountSpecified + whMessageFee, "msg.value incorrect");

225:       require(value == whMessageFee, "msg.value incorrect");

232:       require(params.startTokenAddress.transferFrom(_msgSender(), address(this), params.amountSpecified), "transfer fail");

240:       require(amount >= params.amountSpecified, "transfer insufficient");

333:     require(unpadAddress(transfer.to) == address(this) && transfer.toChain == wormholeChainId, "Token was not sent to this address");

420:         require(sentToUser, "Failed to send Ether");

425:         require(sentToRelayer, "Failed to send Ether");

432:         require(finalToken.transfer(recipient, finalUserAmount), "STF");

436:         require(finalToken.transfer(feeRecipient, relayerFeeAmount), "STF");
```

**Wormhole:**
Error strings have all been confirmed to be length < 32, this is sufficient for the purposes of this contract.

\clearpage