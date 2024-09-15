**Lead Auditors**

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

[Immeas](https://twitter.com/0ximmeas)

**Assisting Auditors**



---

# Findings
## Critical Risk


### USDs stability can be compromised as collateral deposited to Gamma vaults is not considered during liquidation

**Description:** Users of The Standard can take out `USDs` stablecoin loans against their collateral deposited into an instance of `SmartVaultV4`. If the collateral value of a Smart Vault falls below 110% of the `USDs` debt value, it can be liquidated in full. Users can also move collateral tokens into Gamma Vaults (aka Hypervisors) that hold LP positions in Uniswap V3 to earn an additional yield on their deposited collateral.

Collateral held as yield positions in Gamma Vaults are represented by Hypervisor tokens transferred to and held by the `SmartVaultV4` contract; however, these tokens are not affected by liquidation:

```solidity
function liquidate() external onlyVaultManager {
    if (!undercollateralised()) revert NotUndercollateralised();
    liquidated = true;
    minted = 0;
    liquidateNative();
    ITokenManager.Token[] memory tokens = ITokenManager(ISmartVaultManagerV3(manager).tokenManager()).getAcceptedTokens();
    for (uint256 i = 0; i < tokens.length; i++) {
        if (tokens[i].symbol != NATIVE) liquidateERC20(IERC20(tokens[i].addr));
    }
}
```

Currently, Hypervisor tokens present in the `SmartVaultV4::hypervisors` array are not included in the array returned by `TokenManager::getAcceptedTokens` as this would require them to have a Chainlink data feed. Therefore, any collateral deposited as a yield position within a Gamma Vault will remain unaffected.

A user could reasonably have a Smart Vault with 100% of their collateral deposited to Gamma, with 100% of the maximum USDs minted. At this point, any small market fluctuation would leave the Smart Vault undercollateralised and susceptible to liquidation. Given that the `minted` state variable is reset to zero upon successful liquidation, the user is again able to access this collateral via [`SmartVaultV4::removeCollateral`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L186) due to the validation in [`SmartVaultV4::canRemoveCollateral`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L171):

```solidity
function canRemoveCollateral(ITokenManager.Token memory _token, uint256 _amount) private view returns (bool) {
    if (minted == 0) return true;
    /* snip: collateral calculations */
}
```

Consequently, the user can withdraw the collateral without repaying the original `USDs` loan. Given the `liquidated` state variable would now be set to `true`, any attacker would need to create a new Smart Vault before the collateral could be used again.

**Impact:** An attacker could repeatedly borrow against collateral deposited in a yield position after being liquidated, resulting in bad debt for the protocol and likely compromising the stability of `USDs` if executed on a large scale.

**Proof of Concept:** The following test can be added to `SmartVault.js`:
```javascript
it('cant liquidate yield positions', async () => {
  const ethCollateral = ethers.utils.parseEther('0.1')
  await user.sendTransaction({ to: Vault.address, value: ethCollateral });

  let { collateral, totalCollateralValue } = await Vault.status();
  let preYieldCollateral = totalCollateralValue;
  expect(getCollateralOf('ETH', collateral).amount).to.equal(ethCollateral);

  depositYield = Vault.connect(user).depositYield(ETH, HUNDRED_PC.div(10));
  await expect(depositYield).not.to.be.reverted;
  await expect(depositYield).to.emit(YieldManager, 'Deposit').withArgs(Vault.address, MockWeth.address, ethCollateral, HUNDRED_PC.div(10));

  ({ collateral, totalCollateralValue } = await Vault.status());
  expect(getCollateralOf('ETH', collateral).amount).to.equal(0);
  expect(totalCollateralValue).to.equal(preYieldCollateral);

  const mintedValue = ethers.utils.parseEther('100');
  await Vault.connect(user).mint(user.address, mintedValue);

  await expect(VaultManager.connect(protocol).liquidateVault(1)).to.be.revertedWith('vault-not-undercollateralised')

  // drop price, now vault is liquidatable
  await CL_WBTC_USD.setPrice(1000);

  await expect(VaultManager.connect(protocol).liquidateVault(1)).not.to.be.reverted;
  ({ minted, maxMintable, totalCollateralValue, collateral, liquidated } = await Vault.status());

  // hypervisor tokens (yield position) not liquidated
  await expect(MockWETHWBTCHypervisor.balanceOf(Vault.address)).to.not.equal(0);

  // since minted is zero, the vault owner still has access to all collateral
  expect(minted).to.equal(0);
  expect(maxMintable).to.not.equal(0);
  expect(totalCollateralValue).to.not.equal(0);
  collateral.forEach(asset => expect(asset.amount).to.equal(0));
  expect(liquidated).to.equal(true);

  // price returns
  await CL_WBTC_USD.setPrice(DEFAULT_ETH_USD_PRICE.mul(20));

  // user exits yield position
  await Vault.connect(user).withdrawYield(MockWETHWBTCHypervisor.address, ETH);
  await Vault.connect(user).withdrawYield(MockUSDsHypervisor.address, ETH);

  // and withdraws assets
  const userBefore = await ethers.provider.getBalance(user.address);
  await Vault.connect(user).removeCollateralNative(await ethers.provider.getBalance(Vault.address), user.address);
  const userAfter = await ethers.provider.getBalance(user.address);

  // user should have all collateral back minus protocol fee from yield withdrawal
  expect(userAfter.sub(userBefore)).to.be.closeTo(ethCollateral, ethers.utils.parseEther('0.01'));

  // and user also has the minted USDs
  const usds = await USDs.balanceOf(user.address);
  expect(usds).to.equal(mintedValue);
});
```

**Recommended Mitigation:** Ensure that collateral held in yield positions is also subject to liquidation.

**The Standard DAO:** Fixed by commit [`c6af5d2`](https://github.com/the-standard/smart-vault/commit/c6af5d21fc20244531c0202b70eb9392a6ea9b6a).

**Cyfrin:** Verified, `SmartVault4::liquidate` now also loops over the `SmartVaultV4::hypervisors` array. However, native liquidation should be performed last to mitigate re-entrancy risk. Similarly, revocation of roles in `SmartVaultManagerV6::liquidateVault` should occur before invoking `SmartVaultV4::liquidate`.

**The Standard DAO:** Fixed by commit [`23c573c`](https://github.com/the-standard/smart-vault/commit/23c573cba241b0dc6af276f56ee8772efc8b4a5c).

**Cyfrin:** Verified, the order of calls had been modified.


### USDs stability can be compromised as collateral can be stolen by removing Hypervisor tokens directly from a vault without repaying USDs debt

**Description:** When the owner of a Smart Vault calls [`SmartVaultV4::depositYield`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L167-L180), [`SmartVaultYieldManager::deposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L299-L310) is invoked to deposit the specified collateral tokens to a given Gamma Vault (aka Hypervisor) via the [`IUniProxy`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/interfaces/IUniProxy.sol#L6) contract. Gamma Hypervisors work such that they hold a position in a Uniswap V3 pool that is made fungible to depositors who own shares in this position represented as an ERC-20 token. On completion of a deposit, the Hypervisor tokens are transferred back to the calling `SmartVaultV4` contract where they remain as backing for any minted `USDs` debt.

However, due to insufficient input validation, these Hypervisor collateral tokens can be removed from the Smart Vault by calling [`SmartVaultV4::removeAsset`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L191-L196):

```solidity
function removeAsset(address _tokenAddr, uint256 _amount, address _to) external onlyOwner {
    ITokenManager.Token memory token = getTokenManager().getTokenIfExists(_tokenAddr);
    if (token.addr == _tokenAddr && !canRemoveCollateral(token, _amount)) revert Undercollateralised();
    IERC20(_tokenAddr).safeTransfer(_to, _amount);
    emit AssetRemoved(_tokenAddr, _amount, _to);
}
```

Hypervisor tokens are present only in the [`SmartVaultV4::hypervisors`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L26) array and are not handled by the `TokenManager` contract, so `token.addr` will equal `address(0)` and the collateralisation check will be bypassed. Thus, these tokens can be extracted from the contract, leaving the Smart Vault in an undercollateralised state and the protocol with bad debt.

**Impact:** An attacker can borrow the maximum mintable amount of `USDs` against their deposited yield collateral, then leave their Smart Vault undercollateralised by simply removing the collateral Hypervisor tokens. The attacker receives both the `USDs` and its backing collateral while the protocol is left with bad debt, likely compromising the stability of `USDs` if executed on a large scale or atomically with funds obtained from a flash loan.

**Proof of Concept:** The following test can be added to `SmartVault.js`:

```javascript
it('can steal collateral hypervisor tokens', async () => {
  const ethCollateral = ethers.utils.parseEther('0.1')
  await user.sendTransaction({ to: Vault.address, value: ethCollateral });

  let { collateral, totalCollateralValue } = await Vault.status();
  let preYieldCollateral = totalCollateralValue;
  expect(getCollateralOf('ETH', collateral).amount).to.equal(ethCollateral);

  depositYield = Vault.connect(user).depositYield(ETH, HUNDRED_PC);
  await expect(depositYield).not.to.be.reverted;
  await expect(depositYield).to.emit(YieldManager, 'Deposit').withArgs(Vault.address, MockWeth.address, ethCollateral, HUNDRED_PC);

  ({ collateral, totalCollateralValue } = await Vault.status());
  expect(getCollateralOf('ETH', collateral).amount).to.equal(0);
  expect(totalCollateralValue).to.equal(preYieldCollateral);

  const mintedValue = ethers.utils.parseEther('100');
  await Vault.connect(user).mint(user.address, mintedValue);

  // Vault is fully collateralised after minting USDs
  expect(await Vault.undercollateralised()).to.be.equal(false);

  const hypervisorBalanceVault = await MockUSDsHypervisor.balanceOf(Vault.address);
  await Vault.connect(user).removeAsset(MockUSDsHypervisor.address, hypervisorBalanceVault , user.address);

  // Vault has no collateral left and as such is undercollateralised
  expect(await MockUSDsHypervisor.balanceOf(Vault.address)).to.be.equal(0);
  expect(await Vault.undercollateralised()).to.be.equal(true);

  // User has both the minted USDs and Hypervisor collateral tokens
  expect(await MockUSDsHypervisor.balanceOf(user.address)).to.be.equal(hypervisorBalanceVault);
  expect(await USDs.balanceOf(user.address)).to.be.equal(mintedValue);
});
```

**Recommended Mitigation:** Validate that the asset removed is not a Hypervisor token present in the `hypervisors` array.

If considering adding the Hypervisor tokens as collateral in the `TokenManager`, ensure that they are excluded from [this loop](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L108-L111) within `SmartVaultV4::usdCollateral` and the [pricing calculation](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L131) in `SmartVaultV4::getAssets` is also updated accordingly.

**The Standard DAO:** Fixed by commit [`5862d8e`](https://github.com/the-standard/smart-vault/commit/5862d8e10ac8648b89a7e3a78498ff20dc31e42e).

**Cyfrin:** Verified, Hypervisor tokens can no longer be removed without causing `SmartVault::removeAsset` to revert due to being undercollateralised. However, the use of the `remainCollateralised()` modifier in `SmartVaultV4::removeCollateralNative` has introduced a re-entrancy vulnerability whereby the protocol burn fee can be bypassed by the Smart Vault owner: deposit native collateral → mint USDs → remove native collateral → re-enter & self-liquidate. Here, the original validation should be used as this does not affect Hypervisor tokens.

**The Standard DAO:** Fixed by commit [`d761d48`](https://github.com/the-standard/smart-vault/commit/d761d48e957d45c5d61eb494d41b7362f7001155).

**Cyfrin:** Verified, `SmartVaultV4::removeCollateralNative` can no longer be used to re-enter in an undercollateralised state.

\clearpage
## High Risk


### `USDs` self-backing breaks assumptions around economic peg-maintenance incentives

**Description:** When `SmartVaultYieldManager::deposit` is called via `SmartVaultV4::depositYield`, [at least 10%](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L168) of the deposited collateral must be directed toward the `USDs` Hypervisor (which in turn holds an LP position in a protocol-managed `USDs/USDC` Ramses pool):

```solidity
function deposit(address _collateralToken, uint256 _usdPercentage) external returns (address _hypervisor0, address _hypervisor1) {
    if (_usdPercentage < MIN_USDS_PERCENTAGE) revert StablePoolPercentageError();
    uint256 _balance = IERC20(_collateralToken).balanceOf(address(msg.sender));
    IERC20(_collateralToken).safeTransferFrom(msg.sender, address(this), _balance);
    HypervisorData memory _hypervisorData = hypervisorData[_collateralToken];
    if (_hypervisorData.hypervisor == address(0)) revert HypervisorDataError();
    _usdDeposit(_collateralToken, _usdPercentage, _hypervisorData.pathToUSDC);
    /* snip: other hypervisor deposit */
}
```

When the value of the Smart Vault's collateral is determined by `SmartVaultV4::yieldVaultCollateral`, ignoring the issue of hardcoding stablecoins to $1, the value of the tokens underlying each Hypervisor is used:

```solidity
if (_token0 == address(USDs) || _token1 == address(USDs)) {
    // both USDs and its vault pair are € stablecoins, but can be equivalent to €1 in collateral
    _usds += _underlying0 * 10 ** (18 - ERC20(_token0).decimals());
    _usds += _underlying1 * 10 ** (18 - ERC20(_token1).decimals());
```

The issue for `USDs` Hypervisor deposits is that this [underlying balance](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L90-L93) of `USDs` counts toward the [total collateral value](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L113) of the Smart Vault, and there is no restriction on the maximum amount of collateral that can be directed toward this Hypervisor. Hence, users can use `USDs` to collateralize their `USDs` loans with up to as much as 100% of the total collateral deposited to the `USDs/USDC` pool (50% in `USDs` if both stablecoin tokens are assumed to be at peg).

**Impact:** Once the peg is lost for endogenously collateralized stablecoins, such as those backed by themselves, it becomes increasingly difficult to return to recover as the value of both the stablecoin and its collateral decrease in tandem. This self-backing also breaks the assumptions surrounding the economic incentives of the protocol intended to contribute to peg-maintenance.

**Recommended Mitigation:** Consider disallowing the use of `USDs` Hypervisor tokens as backing collateral and implementing some other mechanism to ensure sufficient liquidity in the pool. Alternatively, the percentage of collateral allowed to be directed toward the `USDs` Hypervisor could be limited, but this would not completely mitigate the risk.

**The Standard DAO:** Fixed by commit [`cc86606`](https://github.com/the-standard/smart-vault/commit/cc86606ef6f8c1fea84f378e7f324e648f9bcbc8).

**Cyfrin:** Verified, `USDs` no longer contributes to Smart Vault yield collateral.


### USD stablecoins are incorrectly assumed to always be at peg

**Description:** [`SmartVaultV4::yieldVaultCollateral`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L79-L103) returns the value of collateral held in yield positions for a given Smart Vault. For all Gamma Vaults other than the `USDs` Hypervisor, the dollar value of the underlying amounts of collateral tokens fetched for each Gamma Vault in which collateral is deposited is calculated using prices reported by Chainlink.

```solidity
function yieldVaultCollateral(ITokenManager.Token[] memory _acceptedTokens) private view returns (uint256 _usds) {
    for (uint256 i = 0; i < hypervisors.length; i++) {
        IHypervisor _Hypervisor = IHypervisor(hypervisors[i]);
        uint256 _balance = _Hypervisor.balanceOf(address(this));
        if (_balance > 0) {
            uint256 _totalSupply = _Hypervisor.totalSupply();
            (uint256 _underlyingTotal0, uint256 _underlyingTotal1) = _Hypervisor.getTotalAmounts();
            address _token0 = _Hypervisor.token0();
            address _token1 = _Hypervisor.token1();
            uint256 _underlying0 = _balance * _underlyingTotal0 / _totalSupply;
            uint256 _underlying1 = _balance * _underlyingTotal1 / _totalSupply;
            if (_token0 == address(USDs) || _token1 == address(USDs)) {
                // both USDs and its vault pair are € stablecoins, but can be equivalent to €1 in collateral
                _usds += _underlying0 * 10 ** (18 - ERC20(_token0).decimals());
                _usds += _underlying1 * 10 ** (18 - ERC20(_token1).decimals());
            } else {
                for (uint256 j = 0; j < _acceptedTokens.length; j++) {
                    ITokenManager.Token memory _token = _acceptedTokens[j];
                    if (_token.addr == _token0) _usds += calculator.tokenToUSD(_token, _underlying0);
                    if (_token.addr == _token1) _usds += calculator.tokenToUSD(_token, _underlying1);
                }
            }
        }
    }
}
```

On every collateral deposit to a Gamma Vault, a minimum amount is required to be directed to the `USDs/USDC` pair. Thus, there will always be a non-zero balance of `USDs` Hypervisor tokens if the balance of any other Hypervisor tokens is also non-zero for a given Gamma Vault.

As such, and because there is no Chainlink price feed for `USDs`, this Hypervisor is handled separately; however, this logic incorrectly assumes that the prices of `USDC` and `USDs` will always be equivalent at $1. This is not always true – there have been instances where USDC has experienced de-pegging events, significant in both magnitude and duration. Similar concerns are present for `USDs`, ignoring issues related to self-backing raised in a separate finding.

In the event of either stablecoin de-pegging, Smart Vault owners can borrow above their true collateral value. While strictly hypothetical, it may also be possible to bring about this scenario by direct manipulation of the`USDs/USDC` pool through the following actions:
- Flash loan `WETH` collateral & deposit to Smart Vault.
- Deposit 100% of collateral to the `USDs` Hypervisor.
- Mint a large amount of `USDs`.
- Sell into the `USDs/USDC` pool.
- Assuming `USDs` de-pegs such that more of the position underlying the `USDs` Hypervisor is in `USDs`, this "borrowing above collateral value" effect would be amplified and the Smart Vault yield collateral would increase.
- Borrow more `USDs` using the inflated yield vault collateral calculation, pay back the loan, and repeat.

**Impact:** If either `USDC` or `USDs` fall below their $1 peg, users can mint more `USDs` collateralized by a `USDs/USDC` Hypervisor deposit than should be possible. It may also be possible to directly influence the stability of `USDs` depending on conditions in the `USDs/USDC` pool when one or both stablecoins de-peg.

Additionally, ignoring the separate finding related to Hypervisor tokens not being affected by liquidations, a collateral deposit fully directed to the `USDs` Hypervisor can never be liquidated even if one or both stablecoins de-peg, causing the Smart Vault to become undercollateralised in reality.

**Recommended Mitigation:** Chainlink data feeds should be used to determine the price of `USDC`.

As a general recommendation, a manipulation-resistant alternative should be leveraged for pricing `USDs`; however, this finding underscores the issue with USDs self-backing as the intended economic incentives of the protocol will not apply in this scenario.

**The Standard DAO:** Fixed by commit [`cc86606`](https://github.com/the-standard/smart-vault/commit/cc86606ef6f8c1fea84f378e7f324e648f9bcbc8).

**Cyfrin:** Verified, `USDC` price is now obtained from Chainlink and `USDs` is no longer included in yield vault collateral. Consider querying the Chainlink data feed decimals instead of hardcoding to `1e8`.

**The Standard DAO:** Fixed by commit [`5febbc4`](https://github.com/the-standard/smart-vault/commit/5febbc4768602433db029d85aee29a4e4b1aa5f3).

**Cyfrin:** Verified, decimals are now queried dynamically.

\clearpage
## Medium Risk


### Yield deposits are susceptible to losses of up to 10\%

**Description:** To deal with the slippage incurred through multiple [[1](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L99), [2](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L127), [3](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L141), [4](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L151), [5](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L191), [6](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L197), [7](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L205)] intermediate DEX swaps and Gamma Vault interactions when [`SmartVaultV4::depositYield`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L299-L310) and [`SmartVaultV4::withdrawYield`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L312-L322) are called, there is a requirement that the total collateral value should not have decreased more than 90%:

```solidity
    function significantCollateralDrop(uint256 _preCollateralValue, uint256 _postCollateralValue) private pure returns (bool) {
    return _postCollateralValue < 9 * _preCollateralValue / 10;
}
```

While this design will successfully protect users against complete and immediate loss, 10% is nevertheless a significant amount to lose on each deposit/withdrawal action.

Currently, due to the existence of a centralized sequencer, MEV on Arbitrum does not exist in the typical sense; however, it is still possible to execute latency-driven strategies for predictable events such as liquidations. As such, it may still be possible for MEV bots to cause collateral yield deposits/withdrawals to return 90% of the original collateral value, putting the Smart Vault unnecessarily close to liquidation.

**Impact:** Users could lose a significant portion of collateral when depositing into and withdrawing from Gamma Vaults.

**Recommended Mitigation:** While the existing validation can remain, consider allowing the user to pass a more restrictive collateral drop percentage and more fine-grained slippage parameters for the interactions linked above.

**The Standard DAO:** Fixed by commit [`cc86606`](https://github.com/the-standard/smart-vault/commit/cc86606ef6f8c1fea84f378e7f324e648f9bcbc8).

**Cyfrin:** Verified, `SmartVaultV4::depositYield` and `SmartVaultV4::withdrawYield` now accept a user-supplied minimum collateral percentage parameter. Note that due to the re-ordering of validation in `SmartVaultV4::mint`, the `remainCollateralised()` modifier can be used for this function.

**The Standard DAO:** Fixed by commit [e89daee](https://github.com/the-standard/smart-vault/commit/e89daee950d76180a969c6f93839addd8d43b195).

**Cyfrin:** Verified, the modifier is now used for `mint()`.


### Hardcoded pool fees can result in increased slippage and failed swaps

**Description:** The issue raised in the previous CodeHawks contest as report item [M-03](https://codehawks.the-standard.io/c/2023-12-the-standard/s/483) remains present in `SmartVaultV4::swap` where the pool fee is [hardcoded](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L267) to `3000`:

```solidity
ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn: inToken,
        tokenOut: getTokenisedAddr(_outToken),
        fee: 3000, // @audit hardcoded pool fee
        recipient: address(this),
        deadline: block.timestamp + 60,
        amountIn: _amount - swapFee,
        amountOutMinimum: minimumAmountOut,
        sqrtPriceLimitX96: 0
    });
```

The same issue is present within [`SmartVaultYieldManager::_usdDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L158) and [`SmartVaultYieldManager::_withdrawDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L198), where collateral tokens are swapped to/from `USDC` and `USDs` with a hardcoded pool fee of `500`:

```solidity
function _usdDeposit(address _collateralToken, uint256 _usdPercentage, bytes memory _pathToUSDC) private {
    _swapToUSDC(_collateralToken, _usdPercentage, _pathToUSDC);
    _swapToRatio(USDC, usdsHypervisor, ramsesRouter, 500);
    _deposit(usdsHypervisor);
}
...
function _withdrawUSDsDeposit(address _hypervisor, address _token) private {
    IHypervisor(_hypervisor).withdraw(_thisBalanceOf(_hypervisor), address(this), address(this), [uint256(0),uint256(0),uint256(0),uint256(0)]);
    _swapToSingleAsset(usdsHypervisor, USDC, ramsesRouter, 500);
    _sellUSDC(_token);
}
```

**Impact:** As mentioned in [M-03](https://codehawks.the-standard.io/c/2023-12-the-standard/s/483) of the CodeHawks contest, with the possible exception of the `USDs/USDC` pool created and maintained by the protocol, the pool with the highest liquidity will not necessarily always be equal to the hardcoded values, so trading in a pool with low liquidity will result in increased slippage or failed swaps. If the loss exceeds 10% of the collateral value, this results in a DoS of yield deposits/withdrawals due to validation in [`SmartVaultV4::significantCollateralDrop`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L295-L297). For calls to `SmartVaultV4::swap`, there is no such validation to prevent the Smart Vault from being put unnecessarily close to liquidation – the minimum amount output from the swap is that required to remain collateralized within 1% of liquidation.

**Recommended Mitigation:** The same recommendation as in [M-03](https://codehawks.the-standard.io/c/2023-12-the-standard/s/483) applies here – consider allowing the user to pass the pool fee as a parameter to the call(s).

**The Standard DAO:** Collateral swap pool fees fixed by commit [`f9f7093`](https://github.com/the-standard/smart-vault/commit/f9f70930168499f2de6b7aadf49995b7a766f1a1). Hypervisor swap pool fees acknowledged – not fixed as these swap routes will be managed by admins in `hypervisorData`.

**Cyfrin:** Verified, `SmartVaultV4::swap` now accepts a user-supplied pool fee parameter.


### Insufficient validation of Chainlink data feeds

**Description:** `PriceCalculator` is a contract responsible for providing the Chainlink oracle prices for assets used by The Standard. Here, the price for an asset is queried and then normalized to 18 decimals before being returned to the caller:

```solidity
function tokenToUSD(ITokenManager.Token memory _token, uint256 _tokenValue) external view returns (uint256) {
    Chainlink.AggregatorV3Interface tokenUsdClFeed = Chainlink.AggregatorV3Interface(_token.clAddr);
    uint256 scaledCollateral = _tokenValue * 10 ** getTokenScaleDiff(_token.symbol, _token.addr);
    (,int256 _tokenUsdPrice,,,) = tokenUsdClFeed.latestRoundData();
    return scaledCollateral * uint256(_tokenUsdPrice) / 10 ** _token.clDec;
}

function USDToToken(ITokenManager.Token memory _token, uint256 _usdValue) external view returns (uint256) {
    Chainlink.AggregatorV3Interface tokenUsdClFeed = Chainlink.AggregatorV3Interface(_token.clAddr);
    (, int256 tokenUsdPrice,,,) = tokenUsdClFeed.latestRoundData();
    return _usdValue * 10 ** _token.clDec / uint256(tokenUsdPrice) / 10 ** getTokenScaleDiff(_token.symbol, _token.addr);
}
```

However, these calls to `AggregatorV3Interface::latestRoundData` lack the necessary validation for Chainlink data feeds to ensure that the protocol does not ingest stale or incorrect pricing data that could indicate a faulty feed.

**Impact:** Stale prices can result in unnecessary liquidations or the creation of insufficiently collateralised positions.

**Recommended Mitigation:** Implement the following validation:

```diff
-   (,int256 _tokenUsdPrice,,,) = tokenUsdClFeed.latestRoundData();
+   (uint80 _roundId, int256 _tokenUsdPrice, , uint256 _updatedAt, ) = tokenUsdClFeed.latestRoundData();
+   if(_roundId == 0) revert InvalidRoundId();
+   if(_tokenUsdPrice == 0) revert InvalidPrice();
+   if(_updatedAt == 0 || _updatedAt > block.timestamp) revert InvalidUpdate();
+   if(block.timestamp - _updatedAt > TIMEOUT) revert StalePrice();
```

Given the intention to deploy these contracts to Arbitrum, it is also recommended to check the sequencer uptime. The documentation for implementing this is [here](https://docs.chain.link/data-feeds/l2-sequencer-feeds) with a [code example](https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code).

**The Standard DAO:** Fixed by commit [`8e78f7c`](https://github.com/the-standard/smart-vault/commit/8e78f7c55cc321e789da3d9f6b818ea740b55dc8).

**Cyfrin:** Verified, additional validation of Chainlink price feed data has been added; however, timeouts should be specified on a per-feed basis, and 24 hours is likely too long for most feeds. The sequencer uptime feed has also not been implemented, but this is an important addition. Note that the `hardhat/console.sol` import should be removed from `PriceCalculator.sol`.

**The Standard DAO:** Fixed by commit [`7dfbff1`](https://github.com/the-standard/smart-vault/commit/7dfbff1c6a36b184f71eebcf0763131e53dccfc9).

**Cyfrin:** Verified, additional timeout logic and the sequencer uptime check have been added.

\clearpage
## Low Risk


### Allowance reset for incorrect token in `SmartVaultYieldManager::_sellUSDC`

**Description:** When swapping `USDC` in `SmartVaultYieldManager::_sellUSDC`, there is an allowance given to the router:

```solidity
IERC20(USDC).safeApprove(uniswapRouter, _balance);
ISwapRouter(uniswapRouter).exactInput(ISwapRouter.ExactInputParams({
    /* snip: swap */
}));
IERC20(USDs).safeApprove(uniswapRouter, 0);
```
Consistent with all other swaps performed in this contract, the allowance is reset after interaction with the router; however, in this instance, the allowance is [incorrectly reset](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L193) to `0` for `USDs` instead of `USDC`.

**Impact:** There can be small `USDC` dust allowances left on the router.

**Recommended Mitigation:** Replace `USDs` with `USDC`:

```diff
  IERC20(USDC).safeApprove(uniswapRouter, _balance);
  ISwapRouter(uniswapRouter).exactInput(ISwapRouter.ExactInputParams({
      /* snip: swap */
  }));
- IERC20(USDs).safeApprove(uniswapRouter, 0);
+ IERC20(USDC).safeApprove(uniswapRouter, 0);
```

**The Standard DAO:** Fixed by commit [`217de3a`](https://github.com/the-standard/smart-vault/commit/217de3a777ec692e3ecc781464d8644814df3ab9).

**Cyfrin:** Verified, approval is now reset for `USDC`.


### Insufficient deadline protection when adding/removing collateral from yield positions

**Description:** When the owner of a Smart Vault transfers its collateral assets to/from one of the supported Gamma Vaults, several swaps are executed with a deadline of `block.timestamp + 60`. For example, in `SmartVaultYieldManager::_sellUSDC`:

```solidity
ISwapRouter(uniswapRouter).exactInput(ISwapRouter.ExactInputParams({
    path: _pathFromUSDC,
    recipient: address(this),
    deadline: block.timestamp + 60,
    amountIn: _balance,
    amountOutMinimum: 0
}));
```

This deadline will always be valid whenever the transaction is included in a block, with the addition of 60 seconds from the current timestamp doing nothing, as the timestamp of execution will always be `block.timestamp`.

**Impact:** The lack of a proper deadline can result in swaps being executed in market conditions that differ significantly from those intended, possibly resulting in less favorable outcomes. This is somewhat mitigated by the  `significantCollateralDrop()` protection in `SmartVaultV4`; however, this relies on Chainlink oracle values for calculation of the Smart Vault collateral that might have also changed since the transaction was submitted.

**Recommended Mitigation:** Consider allowing the user to specify a deadline for the swaps executed when adding/removing collateral from yield positions. Note that the deadline does not need to be passed directly to all swap invocations but can be checked once directly in the function bodies of `SmartVaultV4::depositYield` and `SmartVaultV4::withdrawYield`.

**The Standard DAO:** Fixed by commit [`71bad0a`](https://github.com/the-standard/smart-vault/commit/71bad0a8cc4bf8ff60321e41c9acb1e7d7fe1b2c).

**Cyfrin:** Verified, `SmartVaultV4::depositYield`, `SmartVaultV4:withdrawtYield`, and `SmartVaultV4::swap` now accept a user-supplied deadline parameter.


### Removal of Hypervisor data locks deposited Smart Vault collateral

**Description:** A Gamma Vault (aka Hypervisor) is an external contract that maintains and offers fungible shares in Uniswap V3 liquidity positions. The Standard leverages multiple Hypervisors to enable the collateral backing `USDs` to earn yield, configured by admin calls to [`SmartVaultYieldManager::addHypervisorData`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L222-L224). When Smart Vault collateral is deposited into one of these Hypervisors, it is minted Hypervisor ERC-20 tokens to represent a share of the underlying position and internally calls [`SmartVaultV4::addUniqueHypervisor`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L279-L284) to maintain a list of Hypervisors in which it has collateral deposited.

If an admin call is made to [`SmartVaultYieldManager::removeHypervisorData`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L226-L228) to remove a Hypervisor in which Smart Vaults still have open positions, the underlying collateral will be locked. This is due to the following validation in [`SmartVaultYieldManager::_withdrawOtherDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L202-L207) that requires the Hypervisor data to be valid and configured:

```solidity
function _withdrawOtherDeposit(address _hypervisor, address _token) private {
    HypervisorData memory _hypervisorData = hypervisorData[_token];
    if (_hypervisorData.hypervisor != _hypervisor) revert IncompatibleHypervisor();
    /* snip: withdraw and swap */
}
```

However, this collateral locked in the removed Hypervisor will still contribute to the collateral calculation of the Smart Vault due to looping over its independently maintained `SmartVaultV4::hypervisors` array (from which Hypervisors are only removed when collateral is withdrawn).

**Impact:** Hypervisor tokens and the corresponding Smart Vault collateral can be locked indefinitely unless the protocol admin re-adds the Hypervisor data, ignoring a separate finding detailing the malicious removal of Hypervisor tokens from Smart Vaults.

**Proof of Concept:** The following test can be added to `SmartVault.js`:
```javascript
it('locks collateral when hypervisor is removed', async () => {
  const ethCollateral = ethers.utils.parseEther('0.1')
  await user.sendTransaction({ to: Vault.address, value: ethCollateral });

  let { collateral, totalCollateralValue } = await Vault.status();
  let preYieldCollateral = totalCollateralValue;
  expect(getCollateralOf('ETH', collateral).amount).to.equal(ethCollateral);

  depositYield = Vault.connect(user).depositYield(ETH, HUNDRED_PC.div(10));
  await expect(depositYield).not.to.be.reverted;
  await expect(depositYield).to.emit(YieldManager, 'Deposit').withArgs(Vault.address, MockWeth.address, ethCollateral, HUNDRED_PC.div(10));

  ({ collateral, totalCollateralValue } = await Vault.status());
  expect(getCollateralOf('ETH', collateral).amount).to.equal(0);
  expect(totalCollateralValue).to.equal(preYieldCollateral);

  await YieldManager.connect(admin).removeHypervisorData(MockWeth.address);

  // collateral is still counted
  ({ collateral, totalCollateralValue } = await Vault.status());
  expect(getCollateralOf('ETH', collateral).amount).to.equal(0);
  expect(totalCollateralValue).to.equal(preYieldCollateral);

  // user cannot remove collateral
  await expect(Vault.connect(user).withdrawYield(MockWETHWBTCHypervisor.address, ETH))
    .to.be.revertedWithCustomError(YieldManager, 'IncompatibleHypervisor');
});
```

**Recommended Mitigation:** If it is necessary to have the ability to remove Hypervisors, consider also allowing Smart Vault owners to remove Hypervisor tokens from their Vaults if they have been delisted from `SmartVaultYieldManager`, with a check that they are still sufficiently collateralized.

**The Standard DAO:** Acknowleged, not fixed as we believe a user can remove with `removeAsset()`. As long as the vault remains collateralised, there shouldn’t be a problem. We are also not intending to remove Hypervisors if we can avoid it.

**Cyfrin:** Acknowledged, while removed Hypervisor tokens will continue to contribute to the collateralization value of a given Smart Vault, they can be removed by calling `SmartVaultV4::removeAsset` so long as the Vault remains sufficiently collateralized.


### Dust amounts of swapped collateral tokens remain in `SmartVaultYieldManager`

**Description:** Due to rounding, swaps made via Uniswap-style routers with exact input parameters can result in residual dust amounts left in the calling contract. This is not an issue for deposits to Gamma Vaults, as all swapped tokens are sent to the corresponding Hypervisor contract; however, the use of [`SmartVaultYieldManager::_swapToSingleAsset`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L113-L131) called from [`SmartVaultYieldManager::_withdrawUSDsDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L196-L200) and [`SmartVaultYieldManager::_withdrawOtherDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L202-L207) during withdrawals can leave dust amounts of the input token.

**Impact:** Dust amounts of collateral tokens can accumulate in `SmartVaultYieldManager` and will be utilized by the next caller for a given token.

**Recommended Mitigation:** Consider checking for non-zero residual amounts of the input token(s) to swaps made during the withdrawal of yield positions and, if present, return them to the Smart Vault.

**The Standard DAO:** Fixed by commit [`a62973e`](https://github.com/the-standard/smart-vault/commit/a62973ef32942bc74c364d20f03f03229fe8c3bb).

**Cyfrin:** Verified, dust amounts of the unwanted token are now transferred back to the sender.


### `WETH` collateral cannot be swapped in `SmartVaultV4`

**Description:** [`SmartVaultV4::swap`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L259-L277) allows Smart Vault collateral, specified by its `bytes32` symbol, to be swapped for other supported collateral tokens. The corresponding token address for a given symbol is returned by [`SmartVaultV4::getTokenisedAddr`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L228-L231) based on the output of [`SmartVaultV4::getToken`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L220-L226):

```solidity
function getToken(bytes32 _symbol) private view returns (ITokenManager.Token memory _token) {
    ITokenManager.Token[] memory tokens = ITokenManager(ISmartVaultManagerV3(manager).tokenManager()).getAcceptedTokens();
    for (uint256 i = 0; i < tokens.length; i++) {
        if (tokens[i].symbol == _symbol) _token = tokens[i];
    }
    if (_token.symbol == bytes32(0)) revert InvalidToken();
}

function getTokenisedAddr(bytes32 _symbol) private view returns (address) {
    ITokenManager.Token memory _token = getToken(_symbol);
    return _token.addr == address(0) ? ISmartVaultManagerV3(manager).weth() : _token.addr;
}
```

Native `ETH` is present in the list of accepted tokens; however, it returns `address(0)`. Hence, the symbols for both `ETH` and `WETH` correspond to the `WETH` address which is used as the [`tokenIn`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L265) parameter for the Uniswap V3 Router swap instruction. This is the correct method for swapping native `ETH` via the Uniswap V3 Router which will first [attempt to utilize any native balance](https://github.com/Uniswap/v3-periphery/blob/0682387198a24c7cd63566a2c58398533860a5d1/contracts/base/PeripheryPayments.sol#L58-L61) to cover `amountIn`.

After the swap parameters are populated, execution of the actual swap occurs based on [`SmartVaultV4::executeNativeSwapAndFee`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L233-L237) or [`SmartVaultV4::executeERC20SwapAndFee`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L239-L248), depending on the `inToken` address:

```solidity
inToken == ISmartVaultManagerV3(manager).weth() ?
    executeNativeSwapAndFee(params, swapFee) :
    executeERC20SwapAndFee(params, swapFee);
```

Here, the first conditional branch will be executed if the caller intends to swap `WETH` or native `ETH`; however, this logic assumes that the caller exclusively wants to swap native `ETH`, so it will fail for `WETH` unless the Smart Vault has a sufficient balance of `ETH` to perform a native `ETH` swap.

**Impact:** It is impossible for `WETH` collateral to be swapped directly within a Smart Vault.

**Proof of Concept:** The following test can be added to `SmartVault.js`:

```javascript
it('cant swap WETH', async () => {
  const ethCollateral = ethers.utils.parseEther('0.1')
  await MockWeth.connect(user).deposit({value: ethCollateral});
  await MockWeth.connect(user).transfer(Vault.address, ethCollateral);

  let { collateral } = await Vault.status();
  expect(getCollateralOf('WETH', collateral).amount).to.equal(ethCollateral);

  await expect(
    Vault.connect(user).swap(
      ethers.utils.formatBytes32String('WETH'),
      ethers.utils.formatBytes32String('WBTC'),
      ethers.utils.parseEther('0.05'),
      0)
    ).to.be.revertedWithCustomError(Vault, 'TransferError');
});
```

**Recommended Mitigation:** Consider handling `WETH` with `SmartVaultV4::executeERC20SwapAndFee` by modifying the conditional logic in `SmartRouterV4::swap`:

```diff
-   inToken == ISmartVaultManagerV3(manager).weth() ?
+   _inToken == NATIVE ?
        executeNativeSwapAndFee(params, swapFee) :
        executeERC20SwapAndFee(params, swapFee);
```

**The Standard DAO:** Fixed by commit [`fb965bd`](https://github.com/the-standard/smart-vault/commit/fb965bdee4036cb525e4df18f77ece7b32720a66).

**Cyfrin:** Verified, `WETH` collateral can now be swapped; however, if the output token is specified as `NATIVE` then any existing `WETH` collateral in the Smart Vault will also be withdrawn. Also, `SmartVaultV4::executeNativeSwapAndFee` is now no longer used and can be removed.

**The Standard DAO:** Fixed by commit [`589d645`](https://github.com/the-standard/smart-vault/commit/589d645eae5bc5a10aa0e32302942fcbc5a07491).

**Cyfrin:** Verified, now only the `WETH` output from the swap is withdrawn to native.


### Liquidations could be blocked by reverting ERC-20 transfers

**Description:** When liquidations are performed via `SmartVaultV4::liquidate`, ERC-20 collateral tokens are handled within a loop:

```solidity
function liquidate() external onlyVaultManager {
    /* snip: validation, state updates & native liquidation
    ITokenManager.Token[] memory tokens = ITokenManager(ISmartVaultManagerV3(manager).tokenManager()).getAcceptedTokens();
    for (uint256 i = 0; i < tokens.length; i++) {
        if (tokens[i].symbol != NATIVE) liquidateERC20(IERC20(tokens[i].addr));
    }
}
```

If the contract balance of a given ERC-20 is non-zero, it will proceed to perform a transfer to the protocol address, as show below:

```solidity
function liquidateERC20(IERC20 _token) private {
    if (_token.balanceOf(address(this)) != 0) _token.safeTransfer(ISmartVaultManagerV3(manager).protocol(), _token.balanceOf(address(this)));
}
```

However, if any of these transfers revert, the whole call will revert and liquidation will be blocked. Analysis of the collateral tokens currently intended to be supported failed to identify any immediate risks, although it is prescient to note the following:
- `GMX` includes rewards distribution logic on transfers (that, however unlikely, could potentially revert).
- `WETH` and `ARB` are Transparent Upgradeable proxies.
- `WBTC`, `LINK`, `PAXG`, and `SUSHI` are Beacon proxies.
- `RDNT` is a LayerZero bridge token.

**Impact:** Liquidations for a given Smart Vault will be blocked if `GMX` collateral transfers revert. If any other collateral tokens are upgraded to introduce novel transfer logic, they could also make Smart Vaults susceptible to this issue. If an attacker can force a single collateral token transfer to revert, they can avoid being liquidated.

**Recommended Mitigation:** Consider separate handling of each ERC-20 transfer with `try/catch` to avoid blocked liquidations.

**The Standard DAO:** Fixed by commit [`efda8d2`](https://github.com/the-standard/smart-vault/commit/efda8d2de7cb4406598d50099f52fc1275769c0a).

**Cyfrin:** Verified, liquidation will no longer revert if a single transfer fails. Direct use of `ERC20::transfer` instead of `SafeERC20::safeTransfer` appears to be okay because:
- The Smart Vault will always be calling a contract with code when looping through the accepted tokens
- The current list of accepted collateral tokens all return `true` or revert on failed transfer.


### Potentially incorrect encoding of swap paths

**Description:** During fork testing, it became apparent that swap paths should use packed encoding; however, the [existing mocked test suite](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/test/SmartVault.js#L499-L509) does the following:

```javascript
// data about how yield manager converts collateral to USDC, vault addresses etc
await YieldManager.addHypervisorData(
  MockWeth.address, MockWETHWBTCHypervisor.address, 500,
  new ethers.utils.AbiCoder().encode(['address', 'uint24', 'address'], [MockWeth.address, 3000, USDC.address]),
  new ethers.utils.AbiCoder().encode(['address', 'uint24', 'address'], [USDC.address, 3000, MockWeth.address])
)
```

Referring to the [ethers documentation](https://docs.ethers.org/v5/api/utils/hashing/#utils-solidityPack), this shows that `AbiCoder::encode` is the incorrect method for packed encoding. If extended to the real configuration of Hypervisor data for deployed contracts, this would result in all yield deposit functionality reverting due to failed swaps.

**Impact:** Yield deposit functionality would not work due to incorrect configuration of Hypervisor data.

**Recommended Mitigation:** Use tightly packed encoding for swap paths.

**The Standard DAO:** Acknowledged. We are aware that this kind of encoding would not work in production with real routers, but could not figure out how to decode the correct path types in the mock swap router. Will amend the tests & mock swap router if you are aware of a solution.

**Cyfrin:** Acknowledged. The solution would be to use the Uniswap V3 [Path](https://github.com/Uniswap/v3-periphery/blob/main/contracts/libraries/Path.sol) and [BytesLib](https://github.com/Uniswap/v3-periphery/blob/main/contracts/libraries/BytesLib.sol) libraries; however, this additional complexity may not be desired for the mock tests.


### Collateral tokens with more than 18 decimals are not supported

**Description:** Due to the existing decimals scaling logic within [`PriceCalculator::getTokenScaleDiff`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/PriceCalculator.sol#L15-L17), any collateral tokens with more than 18 decimals will not be supported and will result in DoS of Smart Vault functionality:

```solidity
function getTokenScaleDiff(bytes32 _symbol, address _tokenAddress) private view returns (uint256 scaleDiff) {
    return _symbol == NATIVE ? 0 : 18 - ERC20(_tokenAddress).decimals();
}
```

Similar scaling is present in [`SmartVaultV4::yieldVaultCollateral`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L92-L93); however, this would require another `USDs` Hypervisor with a problematic underlying token to be added, which is unlikely.

**Impact:** Smart Vault collateral cannot be calculated if a token with more than 18 decimals is added to the list of accepted tokens, resulting in denial-of-service.


**Recommended Mitigation:** Consider scaling to a greater number of decimals if collateral tokens with more than 18 decimals will be added.

**The Standard DAO:** Fixed by commit [`cf871f7`](https://github.com/the-standard/smart-vault/commit/cf871f7950465904f3f8967e6504eacdd1cbc75c) – not suitable for hypervisor deposits, but should be ok for collateral.

**Cyfrin:** Verified, now supports collateral tokens with more than 18 decimals; however, division before multiplication for the `scale < 0` branch` could be problematic – it might be better to first scale all decimals to 36 and then divide back down to 18 in the return statement of `tokenToUSD`.

**The Standard DAO:** Fixed in commit [`2342302`](https://github.com/the-standard/smart-vault/commit/23423024550bca2dbe182e079403b28cc8d1f6e9).

**Cyfrin:** Verified, now scales decimals to 36 before rescaling back down to 18.

\clearpage
## Informational


### Unnecessary typecast of `msg.sender` to `address`

**Description:** There is an [instance](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L169) of the `msg.sender` context variable that is unnecessarily cast to `address` in `SmartVaultYieldManager::deposit`:

```solidity
uint256 _balance = IERC20(_collateralToken).balanceOf(address(msg.sender));
```

**Recommended Mitigation:** Consider removing the `address` typecast as `msg.sender` is already an address.

**The Standard DAO:** Fixed by commit [`1a9dc5f`](https://github.com/the-standard/smart-vault/commit/1a9dc5fc3f553d1b3dbf285e863d0f8cf5f8bbc0).

**Cyfrin:** Verified, typecast has been removed.


### Comment incorrectly refers to `€` when it should be `$`

**Description:** The following comment is [present](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L91) when summing the stablecoin collateral in `SmartVaultV4::yieldVaultCollateral`:

```solidity
// both USDs and its vault pair are € stablecoins, but can be equivalent to €1 in collateral
```

Here, the `€` symbol is used for USD instead of `$`.

**Recommended Mitigation:** Update the comment to use the `$` symbol.

**The Standard DAO:** No longer applicable. Comment removed in commit [`5862d8e`](https://github.com/the-standard/smart-vault/commit/5862d8e10ac8648b89a7e3a78498ff20dc31e42e).

**Cyfrin:** Verified, comment has been removed.


### Inconsistent use of equivalent function parameter and immutable variable in `SmartVaultYieldManager::_withdrawUSDsDeposit` is confusing

**Description:** When withdrawing collateral from the `USDs` Hypervisor in `SmartVaultYieldManager::_withdrawUSDsDeposit`, the `_hypervisor` parameter will always be equal to the immutable `usdsHypervisor` variable due to the following [conditional check](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L211-L213) in `SmartVaultYieldManager::withdraw`:

```solidity
_hypervisor == usdsHypervisor ?
    _withdrawUSDsDeposit(_hypervisor, _token) :
    _withdrawOtherDeposit(_hypervisor, _token);
```

However, a mixture of both the `_hypervisor` parameter and the equivalent immutable variable is used within[`SmartVaultYieldManager::_withdrawUSDsDeposit`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L196-L200):

```solidity
    function _withdrawUSDsDeposit(address _hypervisor, address _token) private {
    IHypervisor(_hypervisor).withdraw(_thisBalanceOf(_hypervisor), address(this), address(this), [uint256(0),uint256(0),uint256(0),uint256(0)]);
    _swapToSingleAsset(usdsHypervisor, USDC, ramsesRouter, 500);
    _sellUSDC(_token);
}
```

This is confusing to the reader as it could imply that the `_hypervisor` parameter differs from the immutable `usdsHypervisor`, which is not the case.

**Recommended Mitigation:** Consider consistent utilization of either the `_hypervisor` parameter or the immutable `usdsHypervisor` variable.

**The Standard DAO:** Fixed by commit [`f601a11`](https://github.com/the-standard/smart-vault/commit/f601a1173e0b2e2006e73c13339051ae7c7e6af1).

**Cyfrin:** Verified, the immutable variable is now used exclusively.


### `USDC` cannot be added as an accepted collateral token

**Description:** At least 10% of each collateral deposit to Gamma must be directed toward the `USDs/USDC` pool underlying the `USDs` Hypervisor:

```solidity
function _usdDeposit(address _collateralToken, uint256 _usdPercentage, bytes memory _pathToUSDC) private {
    _swapToUSDC(_collateralToken, _usdPercentage, _pathToUSDC);
    _swapToRatio(USDC, usdsHypervisor, ramsesRouter, 500);
    _deposit(usdsHypervisor);
}
```

During this process, [`SmartVaultYieldManager::_swapToUSDC`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L133-L144) swaps the collateral token to `USDC`; however, this would fail for `USDC` without additional handling as it has no path to itself. A similar issue is present in [`SmartVaultYieldManager::_sellUSDC`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L182-L194) when attempting to withdraw the `USDs` Hypervisor deposits to USDC.

Additionally, assuming the was correctly handled, broad use of [`SmartVaultYieldManager::thisBalanceOf`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L49-L51) would result in the entire balance of USDC being utilized for the `USDs` Hypervisor deposit within [`SmartVaultYieldManager::_swapToRatio`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L60-L61) without considering the subsequent Hypervisor deposit:

```solidity
uint256 _tokenBBalance = _thisBalanceOf(_tokenB);
(uint256 _amountStart, uint256 _amountEnd) = IUniProxy(uniProxy).getDepositAmount(_hypervisor, _tokenA, _thisBalanceOf(_tokenA));
```

Furthermore, if `USDC` were to be added as an accepted collateral token, this would result in liquidations being blocked for blacklisted Smart Vaults. An attacker could deposit illegally-obtained `USDC` into their Smart Vault, borrowing `USDs` and avoiding ever being liquidated as the attempt by the protocol to transfer these tokens out would fail.

**Impact:** `USDC` cannot be added as an accepted collateral.

**Recommended Mitigation:** These issues should first be addressed if it is desired to add `USDC` as an accepted collateral token.

**The Standard DAO:** Acknowledged. Not fixing because we have no intentions to add `USDC` as a collateral type. If we were to add it, we believe it would still be fine, as long we didn’t add hypervisor data for it. This seems acceptable to us.

**Cyfrin:** Acknowledged.


### Native asset cannot be removed using `SmartVaultV4::removeAsset`

**Description:** `SmartVault::removeAsset` allows Smart Vault owners to remove assets from their Vault, including collateral assets so long as the Vault remains fully collateralized. This currently works for ERC-20 collateral tokens; however, there is no handling for the case where `_tokenAddr == address(0)`. This address corresponds to the `NATIVE` symbol in the list of accepted `TokenManager` tokens, but native transfers attempted by `SafeERC20::safeTransfer` fail because this edge case is not considered.

```solidity
function removeAsset(address _tokenAddr, uint256 _amount, address _to) external onlyOwner {
    ITokenManager.Token memory token = getTokenManager().getTokenIfExists(_tokenAddr);
    if (token.addr == _tokenAddr && !canRemoveCollateral(token, _amount)) revert Undercollateralised();
    IERC20(_tokenAddr).safeTransfer(_to, _amount);
    emit AssetRemoved(_tokenAddr, _amount, _to);
}
```

While native collateral withdrawals are already correctly handled by `SmartVaultV4::removeCollateralNative`, this edge case results in an asymmetry between ERC-20 and native asset transfers within `SmartVault::removeAsset`.

**Impact:** Smart Vault owners cannot use `SmartVault::removeAsset` to remove native tokens from their Vault.

**Recommended Mitigation:** Consider handling the case where the native asset is attempted to be removed. Also, the use of events should be reconsidered depending on whether the asset removed is a collateral asset.

```diff
function removeAsset(address _tokenAddr, uint256 _amount, address _to) external onlyOwner {
    ITokenManager.Token memory token = getTokenManager().getTokenIfExists(_tokenAddr);
    if (token.addr == _tokenAddr && !canRemoveCollateral(token, _amount)) revert Undercollateralised();
+   if(_tokenAddr == address(0)) {
+       (bool sent,) = payable(_to).call{value: _amount}("");
+       if (!sent) revert TransferError();
+   } else {
-   IERC20(_tokenAddr).safeTransfer(_to, _amount);
+        IERC20(_tokenAddr).safeTransfer(_to, _amount);
+   }
    emit AssetRemoved(_tokenAddr, _amount, _to);
}
```

**The Standard DAO:** Fixed by commits [`8257c4c`](https://github.com/the-standard/smart-vault/commit/8257c4c267fa86c2c237ff6a2acdcfe94bcfeb20) & [`57d5db4`](https://github.com/the-standard/smart-vault/commit/57d5db47e072d8730c0d0988217db8d66ef565d9).

**Cyfrin:** Verified, native collateral can now be removed via either function.

\clearpage
## Gas Optimization


### Unnecessary call to `SmartVaultV4::usdCollateral` when depositing/withdrawing collateral to/from yield positions

**Description:** When depositing/withdrawing collateral to/from yield positions in `SmartVaultV4`, the Smart Vault is validated to remain sufficiently collateralized and the collateral value is validated to have not dropped by more than 10%:

```solidity
if (undercollateralised() || significantCollateralDrop(_preDepositCollateral, usdCollateral())) revert Undercollateralised();
```

This logic calls [`SmartVaultV4::usdCollateral`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L105-L114) to obtain the value of the Smart Vault collateral; however, this is an expensive call that performs multiple loops over collateral tokens and is also invoked within [`SmartVaultV4::undercollateralised`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultV4.sol#L142-L144):

```solidity
function undercollateralised() public view returns (bool) {
    return minted > maxMintable(usdCollateral());
}
```

**Recommended Mitigation:** Consider calling `usdCollateral()` only once after the deposit/withdrawal of collateral, then pass that value to `undercollaterlised()` and `significantCollateralDrop()`. The current implementation of `undercollateralised()` can be refactored into a public function that calls `usdCollateral()` and passes the result to an internal `_undercollateralised()` function that takes the collateral value as argument.

**The Standard DAO:** Fixed by commit [`3fdefc8`](https://github.com/the-standard/smart-vault/commit/3fdefc8d9b4f46aad33993a26ca5a04defdf740a).

**Cyfrin:** Verified, a private function has been introduced.


### Cached `_token0` not used

**Description:** In [`SmartVaultYieldManager::_swapToSingleAsset`](https://github.com/the-standard/smart-vault/blob/c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361/contracts/SmartVaultYieldManager.sol#L114-L117), the cached address `_token0` is not used in the condition of the ternary operation:

```solidity
address _token0 = IHypervisor(_hypervisor).token0();
address _unwantedToken = IHypervisor(_hypervisor).token0() == _wantedToken ?
    IHypervisor(_hypervisor).token1() :
    _token0;
```

**Recommended Mitigation:** Use the cached `_token0` variable in the comparison.

**The Standard DAO:** Fixed by commit [`1c30144`](https://github.com/the-standard/smart-vault/commit/1c3014465689d75d1fc057cadb5cdd75d8f18a2d).

**Cyfrin:** Verified, the cached address is now used.

\clearpage