**Lead Auditors**

[0kage](https://twitter.com/0kage_eth)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

[Hans](https://twitter.com/hansfriese)

[Carlos](https://twitter.com/carlitox477)

**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)


---

# Findings
## Medium Risk


### Chainlink price and L2 sequencer uptime feeds are not used with recommended validations and guardrails

**Description:** [`ChainlinkPriceOracleV1`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/external/oracles/ChainlinkPriceOracleV1.sol) is an implementation of [IPriceOracle](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/external/oracles/ChainlinkPriceOracleV1.sol#L38) which is used in [`Storage::fetchPrice`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/Storage.sol#L455-L456). The protocol currently validates [price cannot be zero](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/Storage.sol#L457-L462), but there exist no checks for staleness and round incompleteness which could result in use of an incorrect non-zero price. `ChainlinkPriceOracleV1` currently uses the [deprecated](https://docs.chain.link/data-feeds/api-reference) `IChainlinkAggregator::latestAnswer` function instead of the recommended `IChainlinkAggregator::latestRoundData` function in conjunction with these additional validations.

L2 sequencer downtime validation is handled by calls to a contract conforming to the [IOracleSentinel interface](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/interfaces/IOracleSentinel.sol#L27-L28) in both [`OperationImpl::_verifyFinalState`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/OperationImpl.sol#L317) and [`LiquidateOrVaporizeImpl::liquidate`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/LiquidateOrVaporizeImpl.sol#L64). The contract on which [`getFlag`](https://arbiscan.io/address/0x3c14e07edd0dc67442fa96f1ec6999c57e810a83#code) is called simply returns the sequencer uptime status and nothing else.

When an L2 sequencer comes back online after a period of downtime and oracles update their prices, all price movements that occurred during downtime are applied at once. If these movements are significant, borrowers rush to save their positions, while liquidators rush to liquidate borrowers. Since liquidations are in the future intended to be handled by Chainlink Automation, without some grace period where liquidations are disallowed, borrowers are likely to suffer mass liquidations. This is unfair to borrowers, as they could not act on their positions even if they wanted to due to the L2 downtime.

**Impact:**
1. Lack of staleness and round-incompleteness validation could result in the use of an incorrect non-zero price.
2. Lack of a sequencer downtime grace period could mean that borrow positions become immediately liquidatable once the sequencer is back up and running if there is a large price deviation in the intermediate time period.

**Recommended Mitigation:** The Dolomite Margin protocol should correctly validate values returned by Chainlink data feeds and give borrowers a grace period to deposit additional collateral prior to allowing liquidations to resume after a period of L2 sequencer downtime.

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Acknowledged.


### Admin can drain market of double-entrypoint ERC-20 using `AdminImpl::ownerWithdrawUnsupportedTokens`

**Description:** `AdminImpl::ownerWithdrawUnsupportedTokens` is intended to allow the owner to withdraw any unsupported ERC-20 token which might have ended up at the Dolomite Margin address. If a double-entrypoint ERC-20 token is listed as a market on Dolomite, it is possible for the admin to drain the entire token balance.

Such tokens are problematic because the legacy token delegates its logic to the new token, meaning that two separate addresses are used to interact with the same token. Previous examples include TUSD which resulted in [vulnerability when integrated into Compound](https://blog.openzeppelin.com/compound-tusd-integration-issue-retrospective/). This highlights the importance of carefully selecting the collateral token, especially as this type of vulnerability is not easily detectable. In addition, it is not unrealistic to expect that an upgradeable collateral token could become a double-entrypoint token in the future, e.g. USDT, so this must also be considered.

By passing the legacy token address of a double-entrypoint token as argument to [`AdminImpl::ownerWithdrawUnsupportedTokens`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/AdminImpl.sol#L183), the admin can drain the entire token balance. The legacy token will not have a valid market id as it has not been added to Dolomite, so [`AdminImpl::_requireNoMarket`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/AdminImpl.sol#L589) will pass.

```solidity
function ownerWithdrawUnsupportedTokens(
    Storage.State storage state,
    address token,
    address recipient
)
    public
    returns (uint256)
{
    _requireNoMarket(state, token);

    uint256 balance = IERC20Detailed(token).balanceOf(address(this));
    token.transfer(recipient, balance);

    emit LogWithdrawUnsupportedTokens(token, balance);

    return balance;
}
```

However, function calls on the legacy token will be forwarded to the new version, so the balance returned will be that of the token in the protocol, which will be transferrable to the admin.

**Impact:** This finding would have a critical impact, leaving the protocol in an insolvent state at the expense of its users; however, the likelihood is low due to external assumptions, and so we evaluate the severity as MEDIUM.

**Recommended Mitigation:** Loop through all supported Dolomite Margin markets and validate the collateral token balances before withdrawing unsupported tokens are equal to the token balances after.

**Dolomite:** Since Dolomite’s core protocol is built to support listing hundreds (or thousands) or assets, we don’t want to implement the proposed fix. First, we don’t intend to list any tokens with this strange behavior. Second, the proposed fix could cause us to run out of gas for a given block since iterating through the balances for each token will get really costly as the number of assets listed grows.

We may provide a hot fix for it in the future through an ownership adapter that adds this functionality.

**Cyfrin:** Acknowledged.


### Inaccurate accounting in `TradeImpl::buy` could lead to loss of user funds

**Description:** Within Dolomite Margin, [`TradeImpl::buy`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/TradeImpl.sol#L44-L110) is used to perform a buy trade and takes `Actions.BuyArgs memory args` as one of its parameters. Given these arguments are supplied by the caller, they are free to set any arbitrary value for `args.exchangeWrapper`.

This `args.exchangeWrapper` parameter is used to [calculate the amount of `takerWei`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/Exchange.sol#L106-L111) the contract should receive, and to [calculate how much should actually be transferred](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/Exchange.sol#L138-L145) to the Dolomite contract.

Given it is not guaranteed that these two values will be the same, the issue arises when there is a difference between the amount that should be received versus the actual amount received. This is partially handled in [`TradeImpl::buy`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/TradeImpl.sol#L84-L89), which ensures the received amount is greater than or equal to the expected amount, acting as a slippage check. However, the internal accounting is [updated](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/TradeImpl.sol#L84-L95) based on the value expected to be received, instead of the value actually received.

**Impact:** Incorrect accounting could result in loss of user funds. Given that it is expected, but not guaranteed, that `takerWei == tokensReceived`, we evaluate the severity to MEDIUM.

**Recommended Mitigation:** Modify [these lines](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/TradeImpl.sol#L91-L95) to guarantee a correct update to protocol accounting.

```diff
//  TradeImpl::buy
    Require.that(
        tokensReceived.value >= makerWei.value,
        FILE,
        "Buy amount less than promised",
        tokensReceived.value
    );

-   state.setPar(
-       args.account,
-       args.makerMarket,
-       makerPar
-   );
+   state.setParFromDeltaWei(
+       args.account,
+       args.makerMarket,
+       makerIndex,
+       tokensReceived
+   );
```

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Resolved.


### `AdminImpl::ownerWithdrawExcessTokens` does not check the solvency of given market before attempting to withdraw excess tokens

**Description:** [`AdminImpl::ownerWithdrawExcessTokens`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/AdminImpl.sol#L152-L181) allows the protocol admin to withdraw excess tokens in Dolomite Margin for a specific market. Excess tokens are calculated using the following formula:

```
Excess tokens = Token Balance (L) + Total Borrowed (B) - Total Supplied (S)
```

Here, `L` represents the real liquidity, which is the actual token balance in Dolomite Margin. `B` and `S` are virtual Dolomite balances. Over time, excess tokens increase as the protocol earns fees after passing the borrowers' interest fee to suppliers. The extent of these fees depends on the total outstanding borrowing in the market and the earnings rate.

However, in certain scenarios, the admin's withdrawal of `numExcessTokens` can lead to temporary insolvency in the protocol. This occurs when the token balance remaining after withdrawal is lower than the maximum withdrawable value for that market after adjusting for collateralization. This situation is especially likely in less liquid markets or in markets with high concentration risk, where a single entity has provided a significant portion of liquidity.

**Impact:** In this situation, withdrawal actions might cause a denial-of-service (DoS) due to the protocol's inadequate balance. While the consequences could be significant, the chance of this happening is minimal since fees are typically much lower than pool balances. As a result, we assess the severity level as MEDIUM.

**Proof of Concept:** _Assumptions:_
- The interest rate on USDC is 10% per year
- Earnings rate = 80% (20% of borrowing interest is the protocol fee)

Consider a simplified scenario below:

| Time  | Action | Alice | Bob  | Pete | USDC Balance | ETH Balance |  Excess USDC  |
|------|--------|---------|------|------| ------------| --------------| -------------- |
| T =0 | Alice deposits 2 ETH, Bob 5000 USDC    | 2   | 5000  | -  | 5000 | 2 |  0 |
| T=0 | Alice borrows 2000 USDC    | 2 , -2000    | 5000  | -  | 5000 | 2 |  0 |
| T=1yr | 200 USDC interest accrued    | 2, -2200  | 5160  | -  | 5000 | 2 |  40 |
| T=1yr | Pete deposits 1000 USDC    | 2, -2200  | 5160  | 1000  | 6000 | 2 |  40 |
| T=1yr | Bob withdraws 5160 USDC    | 2, -2200  | 0  | 1000  | 840 | 2 |  40 |
| T=1yr | Protocol withdraws 40 USDC    | 2, -2200  | 0  | 1000  | 800 | 2 |  0 |

At this stage, Pete cannot withdraw his deposit even though there is no loan against his account. This is because the protocol is temporarily insolvent until another liquidity provider deposits fresh liquidity.

**Recommended Mitigation:** To address this issue, it is recommended to introduce solvency checks for each market in the `AdminImpl::ownerWithdrawExcessTokens` function before completing withdrawals. The protocol should ensure that withdrawing excess tokens does not result in temporary insolvency.

**Dolomite:** A way to mitigate this in the future (without any code changes to the core protocol) is to have the admin withdraw their tokens and atomically redeposit them. This would enable the admin to “compound” their earnings, keeping liquidity in the protocol, while still enabling the admin to “zero out” their excess tokens.

**Cyfrin:** Acknowledged.


### Inadequate systemic risk-controls to support cross-asset collateralization across a wide range of assets

**Description:** Current Dolomite Margin risk controls can be classified into two categories:
 - Account-level risk controls
 - Systemic risk controls

Dolomite incorporates a robust risk monitoring architecture that comprehensively verifies the final state's validity at the conclusion of each operation. An operation, which encompasses a collection of transactions, undergoes thorough system checks to ensure the integrity and accuracy of the final state. This calculation happens in [`OperationImpl::_verifyFinalState`](https://github.com/dolomite-exchange/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/OperationImpl.sol#L309) where both account-level and system-level risk is measured.

While the existing systemic risk controls address various aspects, such as borrowing limits, supply limits, collateral-only mode, and oracle sentinel, they fail to consider the systemic risk introduced by cross-asset collateralisation.

The creation of virtual liquidity without sufficient token backing can expose the protocol to risks associated with liquidity squeezes, freezes, and fluctuating asset correlations. This is similar to fractional banking in traditional finance, i.e., if a bank lends more than 10x its deposits, the bank exposes itself to insolvency risks due to tight liquidity conditions.

In the case of Dolomite Margin, the ratio of virtual liquidity to actual token balance can be considered as leverage - the higher the leverage, the greater the insolvency risk. If this virtual liquidity is utilised as collateral for additional borrowing, it can further amplify the leverage.

**Impact:** Higher protocol leverage can directly increase the risk of insolvency during periods of tight liquidity. Since such risks are attributed to extremely rare black-swan type of events, we evaluate the severity to MEDIUM.

**Proof of Concept:** Consider a USDT de-peg scenario where we see the following events unfold:

1. Virtual USDT holders will scramble to convert to real USDT liquidity, attempting to offload it anywhere possible.
2. Speculators, seeing an opportunity, will initiate cross-collateral borrow positions in USDT. High potential profits in short periods can make them overlook even steep interest rates at higher utilisation levels.
3. These virtual USDT tokens can then be swiftly exchanged for other stable tokens within Dolomite's internal pools.
4. Liquidators might hesitate to liquidate positions with USDT as collateral, anticipating potential high slippage in one-sided markets.

All the above factors may trigger a cascading effect, leading Dolomite to accumulate substantial USDT bad debt. While borrow/supply limits exist, introducing additional safeguards to curb unbacked liquidity could better equip Dolomite to manage potential contagion scenario.

**Recommended Mitigation:** To enhance the system's robustness, consider adding a systemic risk measure to the `OperationImpl::_verifyFinalState` function that caps the leverage per market. Consider implementing a cap on leverage for less liquid markets restricting the ability of users to open cross asset borrowing positions without having enough real liquidity.


**Dolomite:** We think this is better managed through the use of a Global Operator. Each situation has so much nuance to it. So the ability to force close, or add mechanisms that can modify positions will be really helpful in tackling nearly any situation

**Cyfrin:** Acknowledged. While Global Operators certainly bolster Dolomite's agility in making rapid account adjustments, their responsiveness and efficacy in widespread crises remain ambiguous. Past events, such as the Terra Luna incident, have shown that speculators often exploit de-peg situations, making aggressive bets that potentially saddle the protocol with significant bad debt. We continue to recommend additional risk controls that limit the creation of unbacked virtual liquidity to mitigate any existential threats during such rare contagion scenarios.


\clearpage
## Low Risk


### Incorrect logic in `Bits::unsetBit` when applied to a zero bit

**Description:** `Bits::unsetBit` might not work as expected for cases when the bit to be unset is not 1.

It is currently implemented as:

```solidity
function unsetBit(
    uint bitmap,
    uint bit
) internal pure returns (uint) {
    return bitmap - (ONE << bit);
}
```

This implementation will only correctly unset a bit if that bit is already set to 1. If the bit were set to 0, due to the way in which binary subtraction works, this operation would instead set it to 1 and modify other bits as well (which is unlikely to be the intended behavior).

A more appropriate way to unset a bit would be to use a bitwise `AND` operation with the complement of the bit mask. The corrected implementation would look like this:

```solidity
function unsetBit(
    uint bitmap,
    uint bit
) internal pure returns (uint) {
    return bitmap & ~(ONE << bit);
}
```

In this version, `(ONE << bit)` creates a mask where only the bit at position bit is set to 1. The `~` operator then inverts this mask, setting the bit at position bit to 0 and all other bits to 1. Finally, the bitwise `AND` operation leaves all bits in the bitmap unchanged, except for the bit at position bit, which is unset (set to 0).

**Impact:** It appears this function is only ever called with set bits due to `Bits::getLeastSignificantBit` being called beforehand in [both](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/external/helpers/LiquidatorProxyBase.sol#L431-L441) [instances](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/Storage.sol#L919-L935); otherwise, this finding would have a much higher impact, but we evaluate the severity to LOW.

**Recommended Mitigation:** Use the modified version of the function above.

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Acknowledged.


### OpenZeppelin v2.5.1 is not supported for non-critical security patches

The Dolomite Margin smart contracts currently use OpenZeppelin contracts v2.5.1, while the latest release is v4.9.2. Per the [OpenZeppelin security policy](https://github.com/OpenZeppelin/openzeppelin-contracts/security?page=1#supported-versions), only critical severity bug fixes will be backported to past major releases. In light of this, it is possible that future bug reports or changes to the protocol may introduce vulnerabilities and so it is recommended to use a more up-to-date version.

**Dolomite:** In order to maintain compatibility with the rest of Dolomite’s smart contracts which use Solidity v5, we use the latest major version of OpenZeppelin v2. If we ever decide to upgrade the smart contracts, we’ll be sure to bump the OpenZeppelin version as well.

**Cyfrin:** Acknowledged.


### It may be possible to exploit external call in `CallImpl::call`

**Description:** [`CallImpl::call`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/CallImpl.sol#L39) contains the following logic:
```solidity
state.requireIsOperator(args.account, msg.sender);
ICallee(args.callee).callFunction(
    msg.sender,
    args.account,
    args.data
);
```
Selector clashing and/or fallback function for a given callee can be triggered here with arbitrary data in the context of `DolomiteMargin`, assuming the sender is an operator for the given account. `DolomiteMargin` libraries are deployed as standalone contracts, so it appears `OperationImpl` will be `msg.sender` in the context of the call.

Fortunately, this cannot be used to exploit the [infinite WETH approval](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/external/proxies/DepositWithdrawalProxy.sol#L102) in `DepositWithdrawalProxy::initializeETHMarket` as there are no clashing selectors and the WETH fallback function simply attempts to deposit `msg.value`.

**Impact:** This finding could have critical severity under certain circumstances but depends on a number of external assumptions, which significantly reduce the likelihood, and so we evaluate the severity to LOW.

**Recommended Mitigation:** Consider whitelisting the trusted contracts that can be used as `args.callee`.

**Dolomite:** We’d prefer to keep the implementation as permissionless as possible. If there’s another possible check we can put in place, we’d gladly explore it.

**Cyfrin:** Acknowledged.


### Violation of the Checks Effects Interactions Pattern in `LiquidateOrVaporize::liquidate` and `LiquidateOrVaporize::vaporize` could result in read-only reentrancy vulnerabilities

**Description:** When liquidating or vaporizing an undercollateralized account, there are [a](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/LiquidateOrVaporizeImpl.sol#L124-L130) [number](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/LiquidateOrVaporizeImpl.sol#L144-L150) [of](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/LiquidateOrVaporizeImpl.sol#L262-L268) [instances](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/LiquidateOrVaporizeImpl.sol#L277-L283) where [SafeLiquidationCallback::callLiquidateCallbackIfNecessary](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/SafeLiquidationCallback.sol#L44) is called, temporarily [handing off execution](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/SafeLiquidationCallback.sol#L53) to the liquid account owner. While there are [precautions in place](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/lib/SafeLiquidationCallback.sol#L54-L55) to mitigate against gas-griefing and return data bombing attacks, this logic fails to prevent vulnerabilities in third-party protocols which may rely on state from Dolomite Margin. Updates to state balances are performed after these calls, so whilst it is [acknowledged](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/interfaces/ILiquidationCallback.sol#L34-L36) in the interface and cannot be exploited directly given the global protocol-level reentrancy guard, this may expose integrating protocols to a read-only reentrancy attack vector.

**Impact:** There is no immediate impact on Dolomite Margin, but this finding could impact other ecosystem protocols which may be affected by intermediate protocol state, so we evaluate the severity as LOW.

**Recommended Mitigation:** Update state balances prior to making unsafe external calls.

**Dolomite:** We’re adding the callback mechanism to all Actions that modify the user’s virtual balance but don’t materialize an ERC20 transfer event.  To standardise it, they were added before the Action’s events are logged. Those actions are `Transfer` , `Trade`, `Liquidate` , and `Vaporize`.  We also added a variable called `callbackGasLimit` that lets the admin set the amount of gas to allocate to the callback functions. This allows for more control over deployments where gas may not be measured the same way.

Fixes added as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Acknowledged. In the specified commit, we noted changes unrelated to this audit concern, particularly changes related to callbacks and the introduction of callbackGasLimit replacing the prior hardcoded gas. Our review focused solely on the consistency of the CEI pattern in the liquidate and vaporize functions, without delving into the wider implications of these modifications.




### Lack of max value validation in `AdminImpl::ownerSetAccountMaxNumberOfMarketsWithBalances`

**Description:** Currently, there is no protection to stop the admin from setting a value greater than an upper bound when calling [`AdminImpl::ownerSetAccountMaxNumberOfMarketsWithBalances`](https://github.com/feat/dolomite-margin/blob/e10f14320ece20d7492e8e68400333c5c7dec656/contracts/protocol/impl/AdminImpl.sol#L403), only the condition that it should be at least 2:

```solidity
Require.that(
    accountMaxNumberOfMarketsWithBalances >= 2,
    FILE,
    "Acct MaxNumberOfMarkets too low"
);
```

This could lead to a denial-of-service scenario that is intended to be prevented, so there should be an additional maximum validation.

**Impact:** There is low likelihood due to reliance on admin error and so we evaluate the severity as LOW.

**Recommended Mitigation:** Add additional validation for the upper bound when the owner sets the maximum allowed number of markets with balances for a given account.

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb). Added an upper bound of 64 markets.

**Cyfrin:** Acknowledged.


### Inadequate checks and high trust assumptions while setting global operators

**Description:** Dolomite introduces the concept of `Global Operators`, which are accounts authorised to perform actions on behalf of other users. The purpose of these accounts is to enhance user experience by minimising the need for constant transaction approvals. However, it is important to recognise the potential risks associated with malicious global operators who possess privileged access. Two instances in the code highlight these risks:

Malicious global operators, because of their privileged access, can potentially cause a lot of damage. Two such instances observed in the code are:

1.Global operators can create new borrow positions on behalf of users using the `BorrowPositionProxyV2::openBorrowPositionWithDifferentAccounts` function

2. Global operators implementing `IAutoTrader` can act as market makers for users, engaging in trading activities with their taker counterparts.

Upon discussions with the protocol team, it was clarified that only specific contracts are assigned the Global Operator role, with no intention to designate externally owned accounts (EOAs) as Global Operators. However, considering the significant control wielded by global operators, the current checks and controls for assigning this role are inadequate.

**Impact:** A malicious global operator has the capability to manipulate funds by engaging in unauthorized trading or borrowing against user accounts.

**Recommended Mitigation:** To strengthen the security of the system, the following additional checks are advised when assigning a global operator:

- Explicitly check that global operator is not a Externally Owned Account (EOA).
- Implement a time-lock mechanism when registering a new global operator.
- Establish a whitelisting mechanism, allowing only specific contracts within the whitelisted universe to be assigned as global operators.

**Dolomite:** Dolomite maximizes being generic on the core level and we’ve tried to put in place as many safeguards as possible for input validation.

The protocol is currently governed by a delayed multi sig and eventually a time-locked DAO (implementation not complete as of now). This enables the protocol to time-gate everything and leave the details to match the needs of the protocol depending on who owns it.

We’re not going to add the EOA check because there are valid use cases in the future for setting a create2 address as a global operator, which would not be possible anymore with the proposed check.

If for any reason control of the protocol is hijacked, the hijacker can create a malicious operator contract which would be just as bad as an EOA, anyway.

**Cyfrin:** Acknowledged.

\clearpage
## Informational


### Repeated logic can be reused with a shared internal function

`BorrowPositionProxyV1::openBorrowPosition` and `BorrowPositionProxyV1::transferBetweenAccounts` both contain the following repeated code:
```solidity
AccountActionLib.transfer(
    DOLOMITE_MARGIN,
    /* _fromAccountOwner = */ msg.sender, // solium-disable-line
    _fromAccountNumber,
    /* _toAccountOwner = */ msg.sender, // solium-disable-line
    _toAccountNumber,
    _marketId,
    Types.AssetAmount({
        sign: false,
        denomination: Types.AssetDenomination.Wei,
        ref: Types.AssetReference.Delta,
        value: _amountWei
    }),
    _balanceCheckFlag
);
```
Consider moving this to a shared internal function to reduce bytecode size.

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Acknowledged.


### `BorrowPositionProxyV2` allows authorized global operators to unilaterally modify positions and transfer debt between accounts

`BorrowPositionProxyV2` contains functions for opening/closing/transferring/repaying borrow positions with different accounts when called by an authorized sender. Whilst this is the intended behavior of the protocol with its global operators and this specific proxy, it is worth noting that this does allow authorized operators to transfer debt from one account to another unilaterally.

**Dolomite:** We use this functionality to cross boundaries of accounts owned by the same user. For example, Isolation Mode vaults are essentially smart contract wallets owned by an EOA. We use the BorrowPositionProxyV2 so the user can transfer funds from their account to their vault.

**Cyfrin:** Acknowledged.


### Inconsistencies in project README.md

The project README states that `numberOfMarketsWithBorrow` field has been added to `Account.Storage`, but it should instead be `numberOfMarketsWithDebt`.

Additionally, it states that a require statement has been added to `OperationImpl` that forces liquidations to come from a global operator, but this should be `LiquidateOrVaporizeImpl`.

Similarly, the require statement that forces expirations to come from a global operator has been added to `TradeImpl::trade` and not `OperationImpl`.

Consider adding links to relevant lines of code to make navigating these changes easier.

**Dolomite:** Fixed as of commit [6a8ae06](https://github.com/dolomite-exchange/dolomite-margin/commit/6a8ae061fa84110db7b111512f705a6cd0a472bb).

**Cyfrin:** Acknowledged.


### Unverifiable contracts resulting from logic abstraction in externally scoped implementations

**Description:** Dolomite is a versatile base layer that facilitates various actions across multiple tokens. The current audit scope encompasses contracts such as `GenericTraderProxyV1.sol` and `LiquidatorProxyV4WithGenericTrader.sol`. These contracts rely on interfaces like `IIsolationModeUnwrapperTrader::createActionsForUnwrapping` and `IIsolationModeWrapperTrader::createActionsForWrapping` within key functions such as `GenericTraderProxyBase::_appendTraderActions`. Similarly, the interface function `IIsolationModeToken.isTokenConverterTrusted` is utilised in `GenericTraderProxyBase::_validateIsolationModeStatusForTraderParam`.

During the audit, the absence of wrapper/unwrapper trader implementations hindered our ability to verify the precise logic behind creating wrapping and unwrapping actions. The incorrect sequencing or execution of these actions may introduce vulnerabilities that impact the business logic of the mentioned contracts. Additionally, the lack of isolation mode token contracts within the audit's scope prevented us from examining the rationale behind token converter trust. Consequently, we are unable to verify critical functionalities of certain proxy contracts.

**Impact:** Interacting with these interfaces may lead to unforeseen issues that we are currently unable to comprehend.

**Recommended Mitigation:** To address this, it is crucial to provide the necessary implementations for the missing contracts and functions.

**Dolomite:** Acknowledged.

**Cyfrin:** Acknowledged.

\clearpage