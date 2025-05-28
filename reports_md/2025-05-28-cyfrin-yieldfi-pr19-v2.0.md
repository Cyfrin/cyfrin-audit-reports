**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

---

# Findings
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