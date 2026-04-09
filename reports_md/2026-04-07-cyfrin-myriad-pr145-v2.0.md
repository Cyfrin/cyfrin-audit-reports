**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

**Assisting Auditors**



---

# Findings
## Low Risk


### Fee basis diverges from actual proceeds in merge matches when price sum `< 1e18`

**Description:** In `_paySellerWithFees`, the fee for each party is computed on a notional derived from the maker's price:

```solidity
uint256 makerNotional = (fillAmount * maker.price) / ONE;  // price1 when maker = NO seller
uint256 takerNotional = fillAmount - makerNotional;        // complement, NOT taker.price
makerFee = (makerNotional * feeConfig.makerFeeBps) / BPS;
takerFee = (takerNotional * feeConfig.takerFeeBps) / BPS;
```

The parties' actual proceeds, however, are split based on the YES order's price:

```solidity
outcome0Notional = fillAmount * outcome0Order.price / ONE   // = price_YES × fillAmount
outcome1Notional = fillAmount - outcome0Notional            // = (1 - price_YES) × fillAmount
```

When `price_YES + price_NO == 1` (old constraint), these two bases are identical: `1 - price_NO == price_YES`. With the new relaxation allowing `price_YES + price_NO < 1`, the two bases diverge when the NO seller is designated as maker.

In that configuration:

```
takerNotional (fee basis)  = fillAmount × (1 - price_NO) / 1e18
takerProceeds              = fillAmount × price_YES / 1e18
```

Since `1 - price_NO > price_YES` when the sum is below 1, the taker's fee is charged on a larger notional than their actual proceeds. The effective fee rate on proceeds is inflated by a factor of `(1 - price_NO) / price_YES`.

**Impact:** Two failure modes, depending on the degree of price overlap and fee level.

1. **Silent overcharge** - inflated fee fits within proceeds but is larger than it should be. The YES taker pays fees on a notional larger than their actual proceeds; the excess goes to the fee module at the taker's expense.

   Example - `price_YES = 0.30`, `price_NO = 0.40` (sum = 0.70), `fillAmount = 1,000,000`, `takerFeeBps = 300` (3%):

   | | Expected (on proceeds) | Actual (on complement notional) |
   |---|---|---|
   | Fee basis | 300,000 | 600,000 |
   | Fee charged | 9,000 | 18,000 |
   | Taker net proceeds | 291,000 | 282,000 |
   | Effective fee rate | 3% | 6% |

2. **Spurious revert** - when the inflated fee exceeds the taker's actual proceeds, `TakerFeesExceedProceeds` is thrown and a legitimate match is blocked entirely. This happens when:
   ```
   price_YES < (1 − price_NO) × takerFeeBps / BPS
   ```

   Example - `price_YES = 0.10`, `price_NO = 0.40` (sum = 0.50), `takerFeeBps = 5000` (50%):

   | | Value |
   |---|---|
   | `takerProceeds` | `0.10 × fill` |
   | Fee basis (inflated) | `0.60 × fill` |
   | `takerFee` | `0.30 × fill` |
   | Result | revert - yet at the correct fee basis the taker would net `0.05 × fill` |

**Recommended Mitigation:** Compute fees on the outcome-based notionals rather than the maker/complement split:

```diff
-   uint256 makerNotional = (fillAmount * maker.price) / ONE;
-   uint256 takerNotional = fillAmount - makerNotional;
+   uint256 makerNotional = makerTrader == outcome0Order.trader ? outcome0Notional : outcome1Notional;
+   uint256 takerNotional = makerTrader == outcome0Order.trader ? outcome1Notional : outcome0Notional;
```

This ensures fees are always charged on the same base as the proceeds they are deducted from, regardless of maker/taker designation or price sum.

**Myriad:** Fixed in commits [`aa31b2b`](https://github.com/Polkamarkets/polkamarkets-js/commit/aa31b2b6f9671a82fd708ec6a2227e1f6f8e3ff1), [`9db9cfd`](https://github.com/Polkamarkets/polkamarkets-js/commit/9db9cfdc6e6b374f8d93fa32107cc7fcc9fa3366), and [`9854d44`](https://github.com/Polkamarkets/polkamarkets-js/commit/9854d44fb45bc06ea551ef2fcad6a92ecfb9d8d9)

**Cyfrin:** Verified.


### Fee rate looked up at stated `taker.price` but applied to complement-derived notional

**Description:** In same-side matches (both Buy for mint; both Sell for merge), the taker fee rate is queried from FeeModule using the taker's stated price:

```solidity
(feeConfig.makerFeeBps, ) = _feeModule.getFeesAtPrice(makers[i].marketId, makers[i].price);
(, feeConfig.takerFeeBps) = _feeModule.getFeesAtPrice(makers[i].marketId, taker.price);
```

However, the actual taker notional (and therefore fee payment) is computed as `fillAmount * (ONE - maker.price) / ONE` — the complement of the maker's price. When `priceSum != ONE` (now possible for both mint and merge matches), the price at which the taker's fee rate is looked up (`taker.price`) differs from the price at which they actually settle (`ONE - maker.price`).

This only matters when both:
1. `priceSum != ONE` (newly unlocked by PR145)
2. FeeModule has non-flat price-dependent fee schedules

The FeeModule contract does support tiered pricing (confirmed via code inspection), so this is a real precondition in deployed configurations.


**Impact:** If the FeeModule uses price-dependent fee tiers (e.g., lower fees near 0.5, higher fees at extremes), a taker can receive a fee rate intended for their stated price tier even though their actual settlement price is in a different tier.

**Recommended Mitigation:** Look up the taker's fee rate at the effective settlement price rather than the stated price:

```solidity
(, feeConfig.takerFeeBps) = _feeModule.getFeesAtPrice(makers[i].marketId, ONE - makers[i].price);
```

**Myriad:** Fixed in commit [`b2c05b6`](https://github.com/Polkamarkets/polkamarkets-js/commit/b2c05b632c74f599fa06e0cbd219b3a5a85f1296)

**Cyfrin:** Verified.

\clearpage
## Informational


### Price overlap surplus accrues to one counterparty rather than the protocol in both mint and merge matches

**Description:** Both settlement functions split proceeds using the complement of one party's price rather than both parties' signed prices. When prices overlap, the difference is gifted to one counterparty as price improvement rather than captured by the protocol.

* **Mint match (sum > 1):** The taker's cost is the complement of the maker's price, not the taker's signed price:

  ```solidity
  uint256 makerNotional = (fillAmount * maker.price) / ONE;
  uint256 takerNotional = fillAmount - makerNotional;   // 1 - maker.price, not taker.price
  ```

  Example - YES buyer (maker) at 0.70, NO buyer (taker) at 0.60, sum = 1.30:

  | | Signed price | Actual |
  |---|---|---|
  | YES buyer (maker) | 0.70 × fill | 0.70 × fill |
  | NO buyer (taker) | 0.60 × fill | 0.30 × fill |
  | Surplus | — | **0.30 × fill to taker** |

* **Merge match (sum < 1):** Proceeds anchor on the YES seller's price; the NO seller receives the complement:

  ```solidity
  uint256 outcome0Notional = (fillAmount * outcome0Order.price) / ONE;  // YES seller — exact
  uint256 outcome1Notional = fillAmount - outcome0Notional;              // NO seller — complement
  ```

  Example - YES seller at 0.30, NO seller at 0.40, sum = 0.70:

  | | Signed price | Actual |
  |---|---|---|
  | YES seller | 0.30 × fill | 0.30 × fill |
  | NO seller | 0.40 × fill | 0.70 × fill |
  | Surplus | — | **0.30 × fill to NO seller** |

In both cases `(1 − price_YES − price_NO) × fillAmount` goes to one counterparty as windfall. The cross-market path handles by routing the surplus to `feeModule`:

```solidity
uint256 surplus = totalNotional - fillAmount;
uint256 toFeeModule = totalFees + surplus;
collateral.safeTransfer(address(_feeModule), toFeeModule);
```

Consider applying the same sweep in `_settleMintMatch` (when `price0 + price1 > 1`) and an equivalent in `_settleMergeMatch` (when `price0 + price1 < 1`), consistent with the cross-market path and the intent that counterparties execute at their signed limit rather than better.

**Myriad:** Acknowledged. We're aware of that behaviour, however we do believe it's the correct behaviour, which mimics how settle direct match orders work on order books - the taker gets the better market price and might pay a value per share below the limit order. Imagine a scenario where a user creates a limit buy order on the BTC/USDT pair on binance at $100,000 - the user will be matched with a sell order at a lower price, and pay the seller (maker) amount.

There was an issue however in _settleMergeMatch, where the complement was always going in outcome1 direction. That was fixed in [PR146](https://github.com/Polkamarkets/polkamarkets-js/pull/146), which is part of a fix of L-01


### `PriceAboveOne` is reused for two distinct constraints

**Description:** `PriceAboveOne` is thrown in two different contexts:

```solidity
// Individual price validation — either order's price exceeds 1
if (maker.price > ONE || taker.price > ONE) revert PriceAboveOne();

// Merge match constraint — the sum of two valid individual prices exceeds 1
if (outcome0Order.price + outcome1Order.price > ONE) revert PriceAboveOne();
```

The name implies a single price is invalid, but in the merge path it signals a combined constraint on two individually valid prices. This is inconsistent with the mint path, which uses the dedicated `PriceSumBelowOne` error for its equivalent sum constraint.

An integrator or off-chain system catching `PriceAboveOne` cannot distinguish between "an order has an out-of-range price" and "the two orders' prices are individually valid but cannot be matched as a merge pair".

Consider renaming to `PriceSumAboveOne` (or similar), parallel to `PriceSumBelowOne`:

```diff
- if (outcome0Order.price + outcome1Order.price > ONE) revert PriceAboveOne();
+ if (outcome0Order.price + outcome1Order.price > ONE) revert PriceSumAboveOne();
```

**Myriad:** Fixed in commits [`ccf1bcf`](https://github.com/Polkamarkets/polkamarkets-js/pull/147/changes/ccf1bcf1c9f27aa449ec10507632a5d7cd0587cf) and [`6f8c947`](https://github.com/Polkamarkets/polkamarkets-js/commit/6f8c947f7ad35b52f073ae4f6455a4fe66882b33)

**Cyfrin:** Verified.

\clearpage