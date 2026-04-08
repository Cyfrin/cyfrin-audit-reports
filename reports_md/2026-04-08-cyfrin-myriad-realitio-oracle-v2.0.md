**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

[Kiki](https://x.com/Kiki_developer)

**Assisting Auditors**



---

# Findings
## Informational


### Pre-finalization return value `(0, false)` collides with `Outcomes.YES`

**Description:** `getResult` returns `(0, false)` when the Reality.eth question has not yet been finalised:

```solidity
if (!realitio.isFinalized(questionId)) {
    return (0, false);
}
```

The integer `0` is numerically identical to `Outcomes.YES` (defined as `uint256 internal constant YES = 0` in `Outcomes.sol`). Any integration that reads the `outcome` return value without first checking `resolved == true` will silently interpret a pending, unresolved market as "resolved YES".

While correct callers should always guard on `resolved`, this is a latent footgun. The `IMarketOracle` interface provides no explicit sentinel to distinguish "not yet resolved" from "resolved YES", making defensive coding harder than necessary.

**Recommended Mitigation:** Return a value that cannot be confused with any valid resolved outcome when the market is unresolved.

```solidity
if (!realitio.isFinalized(questionId)) {
-   return (0, false);
+   return (-2, false);
}
```

**Myriad:** Fixed in commit [`fc2276a`](https://github.com/Polkamarkets/polkamarkets-js/commit/fc2276abd525ec99043ce1cff242f55e23ac775c)

**Cyfrin:** Verified.


### `MyriadCTFExchange::_matchOrdersSingleValidation` duplicates most of `_matchOrders`

**Description:** `MyriadCTFExchange::_matchOrdersSingleValidation` is largely a copy of `_matchOrders` with two differences: the taker is pre-validated and its `filledAmounts` update is deferred to the caller. The shared logic, fee config validation, price checks, self-trade check, maker fill accounting, balance checks, match type determination, and settlement dispatch, is duplicated in full across both functions.

This increases contract size and creates a maintenance burden: any future fix or change to the settlement logic (e.g. a new match type, a balance check adjustment) must be applied in two places, with the risk of the two diverging.

**Recommended Mitigation:** Extract the shared logic into lower-level internal functions that both `_matchOrders` and `_matchOrdersSingleValidation` delegate to.



**Myriad:** Fixed in commit [`d2dec86`](https://github.com/Polkamarkets/polkamarkets-js/commit/d2dec86fbc35eaf7ac6a7db57c682461f072497c)

**Cyfrin:** Verified.


### Consider using named mappings

**Description:** The `questions` mapping uses an unnamed key type:

```solidity
mapping(uint256 => bytes32) public questions;
```

Solidity 0.8.18 introduced named mapping parameters, which improve readability and tooling support.

**Recommended Mitigation:**
```solidity
mapping(uint256 marketId => bytes32 questionId) public questions;
```


**Myriad:** Fixed in commit [`e3e2876`](https://github.com/Polkamarkets/polkamarkets-js/commit/e3e28763a0c807f673032aae678cd63378ebf80f)

**Cyfrin:** Verified.


### Multiple order match front-run gas grief

**Description:** Orders are off-chain signatures only; no on-chain lock or escrow holds trader collateral or outcome tokens. Settlement pulls from traders via `safeTransferFrom` after validations and state updates, so a front-run that moves collateral or outcome tokens causes a revert after gas is spent. In `matchMultipleOrdersWithFees` the code loops over makers and calls `_matchOrdersSingleValidation` per pair; each call validates, checks balance and allowance, updates `filledAmounts`, then settles.

For example, If the 10th pair has a trader who revoked approval or moved balance, the transaction reverts after the first nine matches have already consumed gas. In `matchCrossMarketOrders` the contract validates all orders in a first loop, then in a second loop for each trader it calls `_checkCollateralBalance` and immediately `safeTransferFrom` in the same iteration. So if the 10th trader front-runs and moves funds, the revert happens after nine check-and-transfer iterations have run; there is no dedicated pass that checks every trader balance and allowance before any transfer. Both paths allow gas griefing, the griefer pays one cheap transfer per grief and the operator loses gas up to the revert. Blacklisting does not scale as this can be done across arbitrary wallets.

**Impact:** Operators are repeatedly gas-griefed. The griefer cost is one transfer per grief; the operator cost is the gas spent up to the revert.

**Recommended Mitigation:** In both `matchMultipleOrdersWithFees` and `matchCrossMarketOrders`, check every trader balance and allowance before the match or transfer loop so any insufficient balance reverts before expensive work. Additionally document that operators should use private mempools.

**Myriad:** We acknowledge this behaviour.
- We'll be the operators running the CLOB and intend to be using a private mempool
- Balance/Allowance checks are done in our API before the order settlement is triggered
- The sorting of the maker orders array can't be determined by an attacker, which therefore creates an unpredictability layer for the attacker


### Oracle data mismatch can breaks market integrity

**Description:** The manager calls oracle `PredictionMarketV3ManagerCLOB::initialize` during market creation and during oracle updates without validating that `oracleData` matches the market configuration. The market stores `question` and `closesAt` as the values users trade against and as the time gate for resolution. The oracle uses `oracleData` to create the Reality question and its opening timestamp, which defines the resolved outcome. If `oracleData` encodes a different question or a different close time, users trade on one question and the oracle resolves a different question, or the market close time diverges from the oracle answering window.

**Recommended Mitigation:** Validate `oracleData` question and close time match stored market values before calling oracle `initialize` in market creation and oracle update.

**Myriad:** Fixed in commit [`b11e9e3`](https://github.com/Polkamarkets/polkamarkets-js/commit/b11e9e38f8bb651f2b6ffa43142600524126abbc)

**Cyfrin:** Verified.

\clearpage