**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**



---

# Findings
## Critical Risk


### Incomplete access control over deposit and redeem

**Description:** `SecuritizeVault` was designed to limit access to deposit and redeem but due to missed overrides it is still possible to use the access-controlled functions.
The vault contract inheritied the OpenZeppelin's `ERC4626Upgradeable` and `ERC4626Upgradeable` has several public functions exposed by default. Especially, `ERC4626Upgradeable` allows mint/deposit and redeem/withdraw in two ways.
```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256);
function mint(uint256 shares, address receiver) public virtual returns (uint256);

function withdraw(uint256 assets, address receiver, address owner) public virtual returns (uint256);
function redeem(uint256 shares, address receiver, address owner) public virtual returns (uint256);
```
Note that `deposit()` and `withdraw()` functions accept the asset amount while `mint()` and `redeem()` functions accept the share amount as parameters.

`SecuritizeVault` has overriden the function `deposit()` and `redeem()` with additional access controls.
For the function `deposit()`, the vault only allowed depositing to itself and for the function `redeem()` the vault allowed only redeemers.
But because the vault did not override the other functions `mint()` and `withdraw()`, it is still possible to work around this limitation.

Moreover, deposit and redeem will be possible even when the vault is paused by the owner.

**Impact:** Access control is broken and anyone can deposit to any other address and anyone can redeem while it is not the protocol's intention.
Furthermore, deposit and redeem will function even when the vault contract is paused by the owner.
We evaluate the impact to be CRITICAL.

**Proof Of Concept:**
Put the test inside `deposit.test.ts`.
```typescript
    it('Cyfrin: Can deposit using a mint function even if receiver is not the same as sender', async () => {
      const { vault, dsMock, redeemer, owner } = await loadFixture(deployRedemptionVault);
      await dsMock.mint(owner.address, amount);
      await dsMock.approve(vault.target, amount);

      console.log(await vault.balanceOf(redeemer.address));
      await vault.mint(amount, redeemer.address);
      console.log(await vault.balanceOf(redeemer.address));
    });
```
**Recommended Mitigation:**
- Override the other functions `mint()` and `withdraw()` with the same access control.
- Note that `deposit()` and `redeem()` is not an ideal pair to be implemented and exposed. In general, it is either deposit and withdraw, or mint and redeem.
- Note that the modifier `receiverSenderNotEqual(receiver)` is technically not meaningful because anyone can transfer the shares (vault token) to others.

**Securitize:** Fixed in Commit [52350aa](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/52350aa809c140edc6f794baabc7e53891b37852).

**Cyfrin:** Verified.
- Public functions `mint()` and `withdraw()` are overridden to revert all the time.
- The modifier `receiverSenderNotEqual(receiver)` has been removed.

\clearpage
## Low Risk


### Unsafe ERC20 Operations should not be used

**Description:** In several places, the current implementation uses the function `transfer()` to transfer ERC20 tokens.
```solidity
SecuritizeVault.sol
186: bool success = assetToken.transfer(_to, _transferAmount);
307: bool success = liquidationToken.transfer(msg.sender, assets);
```
But not all ERC20 tokens adhere to the standard. Some tokens do not return boolean and some tokens do not revert on failure.

**Recommended Mitigation:** Use OpenZeppelin's SafeERC20 where the safeTransfer and safeTransferFrom functions handle the return value check as well as non-standard-compliant tokens

**Securitize:** Fix in [3cd6413](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/3cd641372c614587ca3b9f7b6ca850397caa6e5c).

**Cyfrin:** Verified.

\clearpage
## Informational


### Some function names are misleading

**Description:** Some function names are misleading given the usages.

- The modifier `receiverSenderNotEqual()` is used to ensure the `msg.sender` is equal to the argument and the name that includes the parameter name is not desirable here, especially given that the same modifier is used to check if the `msg.sender==owner` at L273.
`senderEqualTo` or `msgSenderEqualTo` would be better.
```solidity
37: modifier receiverSenderNotEqual(address _receiver) {
38:         require(_receiver == msg.sender, "Receiver must be equal to sender");
39:         _;
40:     }
```
- `assetIsImpaired()` is better than `impairedAsset()` given that this function does not return the actual impaired amount but the status as boolean.
- `vaultIsImpaired()` is better than `impairedVault()`.

**Securitize:** Fixed in [b337b12](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/b337b1271b72c5d53e46412c734672c45afc6039).

**Cyfrin:** Verified.


### Some comments are misleading

**Description:** Some comments are wrong/misleading.

In the below snippet, `impairedAssetBalance` is not a flag, it was supposed to be the function `impairedAsset()`.
```solidity
SecuritizeVault.sol
177: * - The `impairedAssetBalance` flag must be true, indicating that the asset balance is indeed impaired.
```

The comment in the below snippet is incorrect (L321) because there is no possibility that the vault contract transfers assets directly to users.
```solidity
SecuritizeVault.sol
320:      * This can occur if users transfer assets directly to the vault instead of using the deposit function,
321:      * or if the vault transfers assets directly to users instead of using the redeem function.
```

**Securitize:** Fixed in [a2bae8](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/a2bae865466a79c9a079a0957efa05ea0d6f68a6) and [b337b1](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/b337b1271b72c5d53e46412c734672c45afc6039).

**Cyfrin:** Verified.


### Avoid emitting unnecessary events

**Description:** The function `setLiquidationOpenToPublic` is used to set the state `liquidationOpenToPublic` and it is set to the provided parameter regardless of the current status. If the provided parameter is the same to the current value, a redundant event `LiquidationOpenToPublic` will be emitted.

**Securitize:** Fixed in [a2bae86](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/a2bae865466a79c9a079a0957efa05ea0d6f68a6).

**Cyfrin:** Verified.


### General notes on the design

**Description:**
1. In general, it is not clear why the team inherited ERC4626 vault.
The main point of using an ERC-4626 vault is to provide a standardized interface for managing "yield-bearing" tokenized vaults, enabling consistent tracking and calculation of share prices (i.e., the value of vault shares relative to the underlying assets).
But the `SecuritizeVault` enforces 1:1 ratio between the share and the asset, it voids the main point.
Furthermore, the vault has a function `liquidate()` that is not in the ERC4626 standard and it could confuse users and engineers because the term `liquidate` is used in lending protocols.
The current implementation does not show any clear evidence of necessity of using ERC4626.
It could be an overkill and also error prone.

2. The current implementaion has `impairedAssetBalance` and `impairedVaultBalance` and each of them has its relevant transfer functions. It is not clear why these are necessary. Based on the context given by the team during the call, we think these are introduced to swipe the redundant assets or shares that are sent to the vault contract "by mistake". In general, it is not a big concern for the protocol itself because it is after all the caller's mistake and that is not the protocol's responsibility. If the protocol is really concerned with the user mistakes, it is enough to have a single admin function. (refer to [Compound's sweep function](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/CErc20.sol#L124) below.) Note that the current implementation also consumes unnecessary gas because the internal function `_validateBalance()` is called for every transaction.
```solidity
    /**
     * @notice A public function to sweep accidental ERC-20 transfers to this contract. Tokens are sent to admin (timelock)
     * @param token The address of the ERC-20 token to sweep
     */
    function sweepToken(EIP20NonStandardInterface token) override external {
        require(msg.sender == admin, "CErc20::sweepToken: only admin can sweep tokens");
        require(address(token) != underlying, "CErc20::sweepToken: can not sweep underlying token");
        uint256 balance = token.balanceOf(address(this));
        token.transfer(admin, balance);
    }
```


**Securitize:** We chose to implement the `ERC-4626` standard over a `wrapped ERC-20` due to our future plans to implement a variable Net Asset Value (NAV) price. This means that the share-to-asset ratio will vary, making `ERC-4626’s` standardized interface for managing yield-bearing tokenized vaults beneficial. For the current use case, we are enforcing a 1:1 ratio, but this will change as we evolve our implementation.

Regarding the `liquidate()` function, it was included to meet the specific needs of our integration with lending protocols which will be the primary destination for the szTokens. The `liquidate()` method facilitates the process of converting `szTokens` to USDC. While we acknowledge that this function is not part of the `ERC-4626` standard and might cause some confusion, it is essential for our intended functionality. Additionally, not all users will be able to redeem their `szTokens` for a `DS Token`, so the only exit for them will be the liquidation method.

We removed the `_validateBalance()` and modified the impiarment methods:

```solidity
    /**
     * @dev Checks if the vault's asset balance impairment.
     *
     * @return uint256 Returns true if the asset balance is impaired, false otherwise.
     */
    function assetImpairedBalance() public view returns (uint256) {
        uint256 assetBalance = IERC20(asset()).balanceOf(address(this));
        uint256 impairedAssetBalance;
        if (assetBalance > totalSupply()) {
            impairedAssetBalance = assetBalance - totalSupply();
        }
        return impairedAssetBalance;
    }

    /**
     * @dev Checks if the vault's balance imparement.
     *
     * @return uint256 Returns the impaired vault balance.
     */
    function vaultImpairedBalance() public view returns (uint256) {
        uint256 impairedVaultBalance;
        if (balanceOf(address(this)) > 0) {
            impairedVaultBalance = balanceOf(address(this));
        }
        return impairedVaultBalance;
    }
```
Now this is a view, so the calculation will be on demand and gas free.
The need to extract the wrongly deposited tokens, is because of the DS Token is a regulated token, and we need to have an error fix mechanism. When an error occurs we need to have the consistency 1:1 ratio. If a szToken is locked, then the DS Token will be also locked.  Compound's sweep method as-is is not suitable, and also is very similar to the `transferImpairedXbalance` methods.
For the current model, the vault will have a specific owner-admin, and the owner-admin will be able to fix the error on demand.
```solidity
    /**
     * @dev Transfers the impaired asset balance to a specified address.
     * This method is used when the asset balance of the vault is considered impaired,
     * meaning it does not reflect the expected balance due to incorrect transfers into the vault.
     * Only callable by an account with the DEFAULT_ADMIN_ROLE.
     *
     * Requirements:
     * - The `assetIsImpaired()` function must return a value greater than 0.
     *
     * @param _to The address to which the impaired asset balance will be transferred.
     */
    function transferImpairedAssetBalance(address _to) external addressNotZero(_to) onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 _assetImpairedBalance = assetImpairedBalance();
        require(_assetImpairedBalance>0, "Asset balance is not impaired");
        IERC20 assetToken = IERC20(asset());
        assetToken.safeTransfer(_to, _assetImpairedBalance);
    }

    /**
     * @dev Transfers the impaired vault balance to a specified address.
     * This method is used when the vault's balance is considered impaired,
     * meaning it does not reflect the expected balance due to incorrect transfers out of the vault.
     * Only callable by an account with the DEFAULT_ADMIN_ROLE.
     *
     * Requirements:
     * - The `vaultImpairedBalance()` function must be return a value greater than 0.
     *
     * @param _to The address to which the impaired vault balance will be transferred.
     */
    function transferImpairedVaultBalance(address _to) external addressNotZero(_to) onlyRole(DEFAULT_ADMIN_ROLE) {
        uint _vaultImpairedBalance = vaultImpairedBalance();
        require(_vaultImpairedBalance>0, "Vault balance is not impaired");
        IERC20(address(this)).safeTransfer(_to, _vaultImpairedBalance);
    }
```

**Cyfrin:** Acknowledged.

\clearpage
## Gas Optimization


### Unnecessary modifier

**Description:** The function `redeem()` has a modifier `receiverSenderNotEqual(_owner)` and it ensures that the caller is actually the owner of the shares.
But this modifier is unnecessary here because it is checked in the `ERC4626::_withdraw()` function.
```solidity
openzeppelin-contracts-upgradeable\contracts\token\ERC20\extensions\ERC4626Upgradeable.sol
291:         ERC4626Storage storage $ = _getERC4626Storage();
292:         if (caller != owner) {
293:             _spendAllowance(owner, caller, shares);
294:         }
```

**Securitize:** Modifier deleted in [52350aa](https://bitbucket.org/securitize_dev/bc-securitize-vault-sc/commits/52350aa809c140edc6f794baabc7e53891b37852).

**Cyfrin:** Verified.

\clearpage