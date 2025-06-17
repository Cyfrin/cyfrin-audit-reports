**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## Low Risk


### Instant withdrawals via Manager bypass withdrawal fee

**Description:** When a user performs a withdrawal, if the amount is small enough and sufficient assets are available in the `Manager`, the withdrawal can be completed instantly in [`Manager::redeem`](https://github.com/YieldFiLabs/contracts/blob/e43fa029e2af65dae447882c53777e3bed387385/contracts/core/Manager.sol#L203-L208):

```solidity
// if redeeming yToken.asset() and vaultAssetAmount is less than maxRedeemCap and balance of contract is greater than vaultAssetAmount, redeem immediately and return
if (_asset == IERC4626(_yToken).asset() && vaultAssetAmount <= maxRedeemCap[_yToken] && IERC20(_asset).balanceOf(address(this)) >= vaultAssetAmount) {
    IERC20(_asset).safeTransfer(_receiver, vaultAssetAmount);
    emit InstantRedeem(caller, _yToken, _asset, _receiver, vaultAssetAmount);
    return;
}
```

However, this bypasses the fee applied in the asynchronous [`_withdraw`](https://github.com/YieldFiLabs/contracts/blob/e43fa029e2af65dae447882c53777e3bed387385/contracts/core/Manager.sol#L379-L395) flow.

**Impact:** Withdrawals can be initiated through both the `ERC4626` YToken vaults and directly via the `Manager` contract. This allows users to circumvent the fee applied in the YToken withdrawal path by opting for instant withdrawals directly through the `Manager`.

**Recommended Mitigation:** Consider taking the fee also in the instant withdrawal flow.

**YieldFi:** Acknowledged. Currently fees are set to 0 hence this doesn't affect the protocol fees.

\clearpage
## Informational


### `isNewYToken` can be omitted in YToken contracts

**Description:** To support the accounting of underlying assets, a new parameter `isNewYToken` was introduced in `mintYToken`. This parameter is used in the [`dYTokenL1::mintYToken`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/dYTokenL1.sol#L67-L81) and [`dYTokenL2::mintYToken`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/dYTokenL2.sol#L65-L79) contracts to determine whether minting `dYTokens` should also update the balances of the underlying `YTokens`.

However, the parameter is unused in the [`YToken`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/YToken.sol#L215-L225) and [`YTokenL2`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/YTokenL2.sol#L198-L208) implementations:

```solidity
function mintYToken(address to, uint256 shares, bool isNewYToken) external virtual {
    require(msg.sender == manager, "!manager");
    _mint(to, shares);
}
```

Consider omitting the parameter to make its unused status explicit:

```diff
- function mintYToken(address to, uint256 shares, bool isNewYToken) external virtual {
+ function mintYToken(address to, uint256 shares, bool ) external virtual {
```

**YieldFi:** Fixed in commit [`a3a9bad`](https://github.com/YieldFiLabs/contracts/commit/a3a9badf7a2ef877e128add79f52453a5cbc0fa5)

**Cyfrin:** Verified. `isNewYToken` is now removed from the above function parameter declarations.


### Redundant `virtual` declaration in` YToken::_withdraw`

**Description:** In the [pull request](https://github.com/YieldFiLabs/contracts/pull/19), the function [`YToken::_withdraw`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/YToken.sol#L193) was updated to be declared `virtual`, allowing it to be overridden in derived contracts. However, it is never actually overridden in any of the `dYToken` implementations.

Consider removing the `virtual` modifier from both `YToken::_withdraw` and `YTokenL2::_withdraw` to clarify intent and avoid misleading extensibility.

**YieldFi:** Acknowledged.


### Price Change Sensitivity in Instant Withdrawals

**Description:** Since instant withdrawals allow users to withdraw the underlying asset immediately, they can potentially react to price changes in a way that introduces economic inefficiencies. Because prices are delivered via an oracle on L2, this creates two potential vectors for abuse:

1. Cross-chain arbitrage: Large price discrepancies between L1 and L2 can be exploited by users performing arbitrage across chains.
2. Sandwiching price updates: If a user observes a significant price movement, they can deposit just before the change and withdraw immediately after—capturing the gain at the expense of existing holders. This also works in reverse: a user can withdraw just before a large drop, avoiding losses that others would bear.

This behavior is already mitigated to some extent by the cap on instant withdrawals, which limits the amount a user can redeem at once, and by keeping only a limited balance available for instant redemptions.

However, it may be beneficial to monitor the price delta between L1 and L2 or to detect significant price swings. In such cases, consider pausing the contract to prevent potential abuse during volatile conditions.

**YieldFi:** Acknowledged. The price differences between L1 and L2, as well as short-term price movements, are typically small. Under normal conditions, this behavior is unlikely to be profitable. In the case of a catastrophic event, the affected vaults can be paused while changes are addressed.

\clearpage
## Gas Optimization


### Avoid unnecessary computation in `dYToken::mintYToken` when `isNewYToken == false`

**Description:** In the new [`dYToken::mintYToken`](https://github.com/YieldFiLabs/contracts/blob/702a931df3adb2f6e48807203cdc7a92604ea249/contracts/core/tokens/dYTokenL1.sol#L67-L81), there is special logic for handling newly minted `dYTokens`, i.e., tokens generated through deposits or accrued fees:

```solidity
function mintYToken(address to, uint256 shares, bool isNewYToken) external override {
    require(msg.sender == manager, "!manager");
    uint256 assets = convertToAssets(shares);

    // if isNewYToken i.e external deposit has triggered minting of dyToken, we mint yToken to this contract
    if(isNewYToken) {
        // corresponding shares of yToken based on assets
        uint256 yShares = YToken(yToken).convertToShares(assets);
        // can pass isNewYToken here as it is not used in yToken
        ManageAssetAndShares memory manageAssetAndShares = ManageAssetAndShares({
            yToken: yToken,
            shares: yShares,
            assetAmount: assets,
            updateAsset: true,
            isMint: true,
            isNewYToken: isNewYToken
        });
        IManager(manager).manageAssetAndShares(address(this), manageAssetAndShares);
    }
    // minting dYToken to receiver
    _mint(to, shares);
}
```

The `assets` variable is only used within the `if (isNewYToken)` block. Moving its declaration inside the block would save gas when `isNewYToken == false`, by avoiding unnecessary computation:

```diff
function mintYToken(address to, uint256 shares, bool isNewYToken) external override {
    require(msg.sender == manager, "!manager");
-   uint256 assets = convertToAssets(shares);

    // if isNewYToken i.e external deposit has triggered minting of dyToken, we mint yToken to this contract
    if(isNewYToken) {
+       uint256 assets = convertToAssets(shares);
        // corresponding shares of yToken based on assets
        uint256 yShares = YToken(yToken).convertToShares(assets);
```

**YieldFi:** Fixed in commit [`f1f6996`](https://github.com/YieldFiLabs/contracts/commit/f1f69960c4d6d84aa8fe7658ac535a79fb77f505)

**Cyfrin:** Verified. `convertToAssets` now moved inside the if-statmement.

\clearpage