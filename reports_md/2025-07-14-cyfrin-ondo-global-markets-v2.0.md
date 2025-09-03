**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[Al-Qa'qa'](https://twitter.com/al_qa_qa)

**Assisting Auditors**



---

# Findings
## Low Risk


### `guardian` missing `PAUSER_ROLE` grant in `onUSD` deployment

**Description:** Deployment of the `onUSD` token is handled via the `onUSDFactory`, which sets up the token as an upgradeable proxy using the transparent proxy pattern (EIP-1967).

As documented in the contract comments, the `guardian` address is expected to be granted both the `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE`:

[globalMarkets/onUSDFactory.sol#L33-36](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSDFactory.sol#L33-L36)

```solidity
/**
...
 *         Following the above mentioned deployment, the address of the onUSD_Factory contract will:
 *         i) Grant the `DEFAULT_ADMIN_ROLE` & PAUSER_ROLE to the `guardian` address <<----------------
 *         ii) Revoke the `MINTER_ROLE`, `PAUSER_ROLE` & `DEFAULT_ADMIN_ROLE` from address(this).
 *         iii) Transfer ownership of the ProxyAdmin to that of the `guardian` address.
 */
```

However, in the actual deployment logic, only the `DEFAULT_ADMIN_ROLE` is granted to the `guardian`. The `PAUSER_ROLE` is omitted:

[globalMarkets/onUSDFactory.sol#L88](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSDFactory.sol#L88)

```solidity
  function deployonUSD( ... ) external onlyGuardian returns (address, address, address) {
    ...

    // @audit `PAUSER_ROLE` not granted to guardian
>>  onusdProxied.grantRole(DEFAULT_ADMIN_ROLE, guardian);

    onusdProxied.revokeRole(MINTER_ROLE, address(this));
    onusdProxied.revokeRole(PAUSER_ROLE, address(this));
    onusdProxied.revokeRole(DEFAULT_ADMIN_ROLE, address(this));

    onusdProxyAdmin.transferOwnership(guardian);
    assert(onusdProxyAdmin.owner() == guardian);
    initialized = true;
    emit onUSDDeployed( ... );

    return ( ... );
  }
```

As a result, deployment completes without the `guardian` address having the `PAUSER_ROLE` in the `onUSD` token contract, contrary to the intended and documented behavior.


**Impact:** The `guardian` will not have the `PAUSER_ROLE` in the deployed `onUSD` token contract. This prevents them from pausing the token immediately after deployment, potentially limiting their ability to respond to emergencies or enforce compliance controls. However, since the guardian retains the `DEFAULT_ADMIN_ROLE`, they can manually grant themselves the `PAUSER_ROLE` later. Still, this deviates from the intended one-step initialization flow and introduces the risk of operational oversight.

**Recommended Mitigation:** Grant the `PAUSER_ROLE` to the `guardian` address immediately after assigning the `DEFAULT_ADMIN_ROLE`, to match both the contract’s intended behavior and its documentation:

```diff
  onusdProxied.initialize(name, ticker, complianceView);

  onusdProxied.grantRole(DEFAULT_ADMIN_ROLE, guardian);
+ onusdProxied.grantRole(PAUSER_ROLE, guardian);

  onusdProxied.revokeRole(MINTER_ROLE, address(this));
  onusdProxied.revokeRole(PAUSER_ROLE, address(this));
```

**Ondo:** Fixed in commit [`b13a651`](https://github.com/ondoprotocol/rwa-internal/pull/472/commits/b13a651ae927e972a5c1478080fbe37e85409071).  It's the comment that is incorrect here - we only want to grant the default admin role, as it is temporarily used by the deployment EOA to configure the contract properly. Once configured, the default admin is renounced. If the pauser was also granted to the EOA on deployment it would just require another call to renounce

**Cyfrin:** Verified. Comment removed.


### Compliance check discrepancy between `onUSDManager` and `onUSD` transfers

**Description:** When minting or redeeming `onUSD` via `onUSDManager`, the contract extends `BaseRWAManager`, which performs a compliance check using the `onUSD` token address (`address(onUSD)`) as the `rwaToken` identifier. This happens in [`BaseRWAManager::_processSubscription`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/xManager/rwaManagers/BaseRWAManager.sol#L171-L172):

```solidity
// Reverts if user address is not compliant
ondoCompliance.checkIsCompliant(rwaToken, _msgSender());
```

The same check occurs during redemptions via [`BaseRWAManager::_processRedemption`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/xManager/rwaManagers/BaseRWAManager.sol#L243-L244).

Separately, the `onUSD` token contract itself performs compliance checks inside [`onUSD::_beforeTokenTransfer`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSD.sol#L168-L180), which is invoked during transfers, minting, and burning. This function calls the inherited [`OndoComplianceGMClientUpgradeable::_checkIsCompliant`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/gmTokenCompliance/OndoComplianceGMClientUpgradeable.sol#L86-L88), which delegates to [`OndoComplianceGMView::checkIsCompliant`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/gmTokenCompliance/OndoComplianceGMView.sol#L75-L81):

```solidity
function checkIsCompliant(address user) external override {
  compliance.checkIsCompliant(gmIdentifier, user);
}
```

Here, [`OndoComplianceGMViewgmIdentifier`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/gmTokenCompliance/OndoComplianceGMView.sol#L34-L36) is a hardcoded address derived from the string `"global_markets"` and used as the `rwaToken` identifier:

```solidity
address public gmIdentifier =
  address(uint160(uint256(keccak256(abi.encodePacked("global_markets")))));
```

As a result, minting and redeeming will trigger two compliance checks with different identifiers:

* `address(onUSD)` via the manager logic
* `gmIdentifier` via the token's `_beforeTokenTransfer`

**Impact:** Although `_beforeTokenTransfer` runs during minting and burning, meaning both compliance checks still occur, the use of two different `rwaToken` identifiers introduces an unnecessary inconsistency. If the two compliance lists are not aligned, minting or redeeming could revert unexpectedly, despite the user being compliant under one identifier.

**Recommended Mitigation:** There are two possible mitigation approaches, depending on which compliance identifier is intended as canonical for `onUSD`.

1) Update `OnUSD::_beforeTokenTransfer` to explicitly use `address(this)` as the `rwaToken` in all compliance checks. This aligns the transfer/mint/burn logic with the identifier used in the manager’s mint/redeem flow, ensuring consistency and eliminating the need to maintain two separate compliance lists.

   ```solidity
   if (from != msg.sender && to != msg.sender) {
     compliance.checkIsCompliant(address(this), msg.sender);
   }

   if (from != address(0)) {
     // If not minting
     compliance.checkIsCompliant(address(this), from);
   }

   if (to != address(0)) {
     // If not burning
     compliance.checkIsCompliant(address(this), to);
   }
   ```

2) If `gmIdentifier` is intended to serve as a shared compliance identity for global markets assets (including `onUSD`), consider using `gmIdentifier` in the `onUSDManager` mint/redeem flow as well. This would unify all compliance checks under a single identifier, reducing operational fragmentation.


**Ondo:** Acknowledged. The `OndoCompliance` check in the `USDonManager` only exists due to the `USDonManager` inheriting the `BaseRWAManager` - since the check already exists in `USDon` transfers themselves it would be completely redundant if used. Knowing this, we will leave the sanctions and blocklist unset for `USDon` in `OndoCompliance` so that the checks coming from the `USDonManager` are effectively bypassed, and we instead rely on checks stemming from `USDon` transfers themselves and keyed on the `gmIdentifier`.

\clearpage
## Informational


### `OndoSanityCheckOracle::setAllowedDeviationBps` is not checking zero value as input which will introduce problems using it

**Description:** In `OndoSanityCheckOracle`, there are two types of deviation values: a default deviation applied to all tokens by default, and a token-specific deviation set per asset via `setAllowedDeviationBps()`.

The default deviation value is validated to be non-zero, while token-specific deviations can be set to zero:

[OndoSanityCheckOracle.sol#L222-L245](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/sanityCheckOracle/OndoSanityCheckOracle.sol#L222-L245)

```solidity
function setAllowedDeviationBps(...) external onlyRole(CONFIGURER_ROLE) {
  if (bps >= BPS_DENOMINATOR) revert InvalidDeviationBps();
  prices[token].allowedDeviationBps = bps;
  emit AllowedDeviationSet(token, bps);
}

function setDefaultAllowedDeviationBps(...) public onlyRole(CONFIGURER_ROLE) {
  if (bps == 0) revert InvalidDeviationBps(); // enforced here
  if (bps >= BPS_DENOMINATOR) revert InvalidDeviationBps();
  emit DefaultAllowedDeviationSet(defaultDeviationBps, bps);
  defaultDeviationBps = bps;
}
```

Setting a token deviation to zero is functionally meaningless, however, because zero is interpreted as “use the default” during price posting:

[OndoSanityCheckOracle.sol#L189-L192](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/sanityCheckOracle/OndoSanityCheckOracle.sol#L189-L192)

```solidity
if (priceData.allowedDeviationBps == 0) {
  priceData.allowedDeviationBps = defaultDeviationBps;
  emit AllowedDeviationSet(token, priceData.allowedDeviationBps);
}
```

This creates a subtle inconsistency: the contract accepts `0` as a valid input for per-token deviations, but the value will be ignored and overridden when posting a price. If zero deviation is considered too strict or unsupported, enforce a `bps > 0` check in `setAllowedDeviationBps()`, mirroring the validation in `setDefaultAllowedDeviationBps()`.

Alternatively, if `0` is meant to indicate “use default,” consider introducing an explicit boolean field to track whether a token’s deviation has been explicitly set, rather than relying on `0` as a sentinel value.

**Ondo:** Fixed in commit [`6a33346`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/6a333464ee54fe04957331c270ce185a44e5e528)

**Cyfrin:** Verified. `allowedDeviationBps` is not allowed to be 0.


### Inconsistent unpause role in `onUSD`

**Description:** [`onUSD::unpause`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSD.sol#L200-L202) is restricted to `DEFAULT_ADMIN_ROLE`, unlike other contracts in the system that use a dedicated `UNPAUSER_ROLE`. This breaks consistency in access control design and limits flexibility in delegating unpause authority:
```solidity
function unpause() public override onlyRole(DEFAULT_ADMIN_ROLE) {
  _unpause();
}
```

Consider using `UNPAUSER_ROLE` for `onUSD::unpause` to align with the pattern used across other contracts.

**Ondo:** Fixed in commit [`650c527`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/650c527100dbb655e9a485a5568c7796fdde3cc1)

**Cyfrin:** Verified.`UNPAUSER_ROLE` used in `USDon::unpause` (renamed)


### `GMTokenManager::mintWithAttestation` breaks Check-Effects-Interactions pattern

**Description:** In [`GMTokenManager::mintWithAttestation`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L196-L231), the function transfers tokens from the user before performing internal accounting operations such as rate limiting, burning, and minting. This violates the check-effects-interactions pattern, where external calls (like token transfers) should typically come after all internal state updates to reduce risk.

While the token being transferred is assumed to be a trusted stablecoin, this ordering increases the surface area for unexpected behavior if any integrated token misbehaves (e.g., via callback hooks, pausable logic, or fee-on-transfer behavior).

Consider reordering operations in `mintWithAttestation` to follow the check-effects-interactions pattern—performing rate limiting, burns, and mints **before** calling `token.transferFrom()`.

**Ondo:** Fixed in commit [`29bdeb9`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/29bdeb92b8de97be3de6a60d78bf91449be90827)

**Cyfrin:** Verified. rate limiting now done before external calls.


### Inconsistent role for `GMTokenManager::setIssuanceHours`

**Description:** The [`GMTokenManager::setIssuanceHours`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L400-L410) function is restricted to `CONFIGURER_ROLE`, whereas other configuration and role assignment functions across the system are typically restricted to `DEFAULT_ADMIN_ROLE`. This inconsistency may cause confusion about which roles are responsible for governance and configuration actions.

Consider aligning access control by restricting `setIssuanceHours` to `DEFAULT_ADMIN_ROLE`, consistent with similar configuration functions elsewhere.

**Ondo:** Fixed in commit [`3d18299`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/3d18299bab888ef204073581d92ffbc3de13ad30)

**Cyfrin:** Verified. `DEFAULT_ADMIN_ROLE` is now used for `GMTokenManager::setIssuanceHours`.


### Unnecessary boolean comparisons in `GMTokenManager`

**Description:** Both in [`GMTokenManager::_verifyQuote#L329`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L329) and [`GMTokenManager::adminProcessMint#L389`](http://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L389) there's a boolean comparison:
```solidity
if (gmTokenAccepted[gmToken] == false) revert GMTokenNotRegistered();
```
This is redundant. Consider simplifying it to:
```solidity
if (!gmTokenAccepted[gmToken]) revert GMTokenNotRegistered();
```

**Ondo:** Fixed in commit [`1877211`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/1877211865727c6ae6e1587550266a43973d722c)

**Cyfrin:** Verified.


### Inconsistent type usage for `IssuanceHours.HOUR_IN_SECONDS`

**Description:** In `IssuanceHours` the constant [`IssuanceHours.HOUR_IN_SECONDS`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/issuanceHours/IssuanceHours.sol#L38) field is declared as `uint`, while the rest of the codebase consistently uses `uint256`:
```solidity
/// Constant for the number of seconds in an hour
uint constant HOUR_IN_SECONDS = 3_600;
```

Consider updating the field to use `uint256` to align with the project's standard type declarations.

**Ondo:** Fixed in commit [`fe452a1`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/fe452a120f8afde757d19736c44b26d4b07fbca3)

**Cyfrin:** Verified. `HOUR_IN_SECONDS` uses type `int256` (since that removes a cast in `_validateTimezoneOffset`)


### Confusing field name `minimumLiveness` in `PriceData` struct

**Description:** The [`PriceData`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/sanityCheckOracle/OndoSanityCheckOracle.sol#L37-L49) struct in `OndoSanityCheckOracle` includes a field named `minimumLiveness`, which actually represents the maximum age a price can be before it's considered stale. The current name may be misleading, as "minimum liveness" implies a lower bound on freshness rather than an upper bound on staleness.

Consider renaming the field to something clearer like `maxPriceAge` or `staleThreshold` to better reflect its purpose and improve code readability.

**Ondo:** Fixed in commits [`b453b57`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/b453b57a8785ee7905d8dc46bee47694f43f152c) and [`9af9735`](https://github.com/ondoprotocol/rwa-internal/pull/470/commits/9af9735587341a0c97a04ce00ace905406b87e8c)

**Cyfrin:** Verified. Renamed to `maxTimeDelay`.


### Test enhancements

**Description:** * `GMIntegrationTest_GM_ETH`: Both tests [`test_hitRateLimits_onUSDInGMFlow_Subscribe`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/GM_IntegrationTest.t.sol#L1209-L1210) and [`test_hitRateLimits_onUSDInGMFlow_Redeem`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/GM_IntegrationTest.t.sol#L1254-L1255) have empty `expectReverts`:
   ```solidity
   // Should fail due to onUSD rate limit
   vm.expectRevert();
   gmTokenManager.mintWithAttestation(
     quote,
     signature,
     address(USDC),
     usdcAmount
   );
   ```
   Accepting any revert could hide unexpected errors allowing bugs to still pass the tests. Consider catching the expected revert:
   ```diff
       // Should fail due to onUSD rate limit
   -   vm.expectRevert();
   +   vm.expectRevert(OndoRateLimiter.RateLimitExceeded.selector);
       gmTokenManager.mintWithAttestation(
         quote,
         signature,
         address(USDC),
         usdcAmount
       );
   ```

* `GmTokenManagerSanityCheckOracleTest`: The test [`testPostPricesWithInvalidInput`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/tokenManager/GmTokenManagerSanityCheckOracleTest.t.sol#L563-L577) also has an empty `expectRevert()`. This test should ideally be split into two, `...WithInvalidToken`, `...WithInvalidPrice` and expect the correct errors: `InvalidAddress` and `PriceNotSet`.

* `error TokenPauseManagerClientUpgradeable.TokenPauseManagerCantBeZero` lacks a test. Consider adding one for assigning an invalid `TokenPauseManager`.

* `GMTokenManagerTest_ETH`: The test [`testMintFromNonKYCdSender`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/tokenManager/GmTokenManagerTest.t.sol#L587-L629) mentions a "KYC role" which doesn't exist. It also catches an empty revert on [L626](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/tokenManager/GmTokenManagerTest.t.sol#L626). This catch does not catch the correct error, it catches a `OneRateLimiter.RateLimitExceeded` error since the user has no rate limit config. Since the user is added to the registry on [L601](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/forge-tests/globalMarkets/tokenManager/GmTokenManagerTest.t.sol#L601), effectively saying it's KYC'd. Thus it passes the KYC check. Consider removing mentions of a KYC role, catching the correct revert (`IGMTokenManagerErrors.UserNotRegistered`) and remove the addition of the user to the registry.

**Cyfrin:** Fixed by Cyfrin in commit [`d3155d0`](https://github.com/ondoprotocol/rwa-internal/pull/469/commits/d3155d09d8bb0ed48b7975d758830fc60c36e525)


### Natspec enhancements

**Description:** * [`onUSD_Factory::deployonUSD`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSDFactory.sol#L54-L76) is missing the `complianceView` parameter in its natspec.
* [`onUSD_Factory.onUSDDeployed`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/onUSDFactory.sol#L113-L126) event is missing parameters `name`, `ticker`, and `complianceView`
* [`GMTokenManager::constructor`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L140-L156) is missing `_onUsd` parameter
* [`GMTokenManager::adminProcessMint`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L376-L398) is missing `gmToken` parameter
* [`TokenPauseManager::unpauseAllTokens`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenPauseManager/TokenPauseManager.sol#L105-L113): the text `Only affects tokens paused by the pauseAllTokens function` could be worded better as this is _all_ tokens.

**Ondo:** Fixed in commit [`d7dc414`](https://github.com/ondoprotocol/rwa-internal/pull/471/commits/d7dc4144d42a5edb04a25814f42a677c8b798723)

**Cyfrin:** Verified.


### Missing `nonReentrant` modifier on `GMTokenManager` mint/redeem

**Description:** The [`GMTokenManager::mintWithAttestation`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L170-L175) and [`GMTokenManager::redeemWithAttestation`](https://github.com/ondoprotocol/rwa-internal/blob/a74d03f4a71bd9cac09e8223377b47f7d64ca8d4/contracts/globalMarkets/tokenManager/GMTokenManager.sol#L248-L253) functions  perform external token transfers and internal state updates but do not use the `nonReentrant` modifier. While `GMTokenManager` inherits from OpenZeppelin's `ReentrancyGuard`, which is currently unused, the modifier is not applied to these functions.

Consider adding the `nonReentrant` modifier to `mintWithAttestation` and `redeemWithAttestation`.

**Ondo:** Fixed in commit [`d7dc414`](https://github.com/ondoprotocol/rwa-internal/pull/471/commits/d7dc4144d42a5edb04a25814f42a677c8b798723)

**Cyfrin:** Verified.

\clearpage