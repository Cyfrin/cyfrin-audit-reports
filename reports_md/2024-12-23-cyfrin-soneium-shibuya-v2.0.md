**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**



---

# Findings
## Low Risk


### Lack of validation for default admin revocation during initialization

**Description:** In `ShibuyaToken::initializeV3()`, the contract attempts to revoke `DEFAULT_ADMIN_ROLE` from the provided `defaultAdmin` parameter. Based on the deployed contract on testnet and team communication, the intention was to remove the role from the original default admin address during the upgrade process.

However, the current implementation has two issues:
1. It revokes the role without first verifying if the address actually possesses the role in the previous version
2. The accompanying comments are misleading, stating "this is to make sure that the default admin is the owner and remove the default admin role from the deployer". This implies the deployer always has the default admin role, which isn't necessarily true.

```solidity
Shibuya.sol
36:         // this is to make sure that the default admin is the owner and remove the default admin role from the deployer
37:         // so this means that the deployer will not have any role in the contract
38:         // the the DEFAULT_ADMIN_ROLE will not have any role in the contract
39:         // and the owner will be performing the role of the admin
40:         _revokeRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
```

Additionally, there's a typographical error in the comments at line 38 where "the" is repeated.

**Recommended Mitigation:**
- Add an explicit check if `defaultAdmin` has `DEFAULT_ADMIN_ROLE` before revoking
- Document clearly in the upgrade guide about role requirements
- Fix minor mistakes in comments

**Startale:** Fixed in commit [01789b](https://github.com/StartaleLabs/ccip-contracts-registration/commit/01789b01cb654607c91f011a3ea768ebfc486a14).

**Cyfrin:** Verified.

\clearpage
## Informational


### Incorrect documentation for mint function

**Description:** The `mint` function's documentation incorrectly states it "disallows burning from address(0)" when it should be "disallows minting to address(0)".

**Recommended Mitigation:** Update the documentation to correctly reflect the function's behavior

**Startale:** Fixed in PR [8](https://github.com/StartaleLabs/ccip-contracts-registration/pull/8).

**Cyfrin:** Verified.


### Redundant owner-based access control implementation

**Description:** The contract implements a custom ownership system alongside `AccessControlUpgradeable`, but fails to utilize the latter's built-in access control mechanisms effectively. Since the owner is not granted the `DEFAULT_ADMIN_ROLE`, the contract is forced to override several public functions from `AccessControlUpgradeable` to maintain proper access control.

This design choice implies potential issues:
1. Unnecessarily duplicates access control functionality that already exists in `AccessControlUpgradeable`
2. Requires overriding `grantRole()` and `revokeRole()` functions
3. Inconsistently handles role management by missing the override for `renounceRole()`
4. Increases code complexity and potential for access control confusion

While the current implementation is functional, it introduces unnecessary complexity and potential maintenance challenges.

**Recommended Mitigation:** Instead of implementing a separate ownership system we recommend the team to consider:
1. Grant the `DEFAULT_ADMIN_ROLE` to the owner during initialization
2. Remove custom ownership implementation
3. Utilize `AccessControlUpgradeable`'s built-in role management functions
4. Remove unnecessary function overrides

**Startale:** Acknowledged.

**Cyfrin:** Acknowledged.


### Missing zero amount validation in crosschain operations

**Description:** The `crosschainMint()` and `crosschainBurn()` functions don't validate for zero amounts, which could lead to unnecessary event emissions.

**Recommended Mitigation:** Add zero amount checks and revert if amount is zero.

**Startale:** Fixed in commit [fa77e9](https://github.com/StartaleLabs/ccip-contracts-registration/commit/fa77e9745ed943ba940a6523b441a67111355c1c).

**Cyfrin:** Verified.


### Incomplete ERC20 interface support

**Description:** The `supportsInterface()` function doesn't declare support for `IERC20` interface ID despite implementing ERC20 functionality.
This could cause issues with interface detection in some integration scenarios.

**Recommended Mitigation:** Add support for `type(IERC20).interfaceId` in the `supportsInterface` function.

**Startale:** Fixed in commit [cb5b05](https://github.com/StartaleLabs/ccip-contracts-registration/commit/cb5b05c4f09b449aa46b5e6290456f9f94cdb09f).

**Cyfrin:** Verified.



### Parameter naming inconsistency

**Description:** The parameter name 'minAndBurner' in the `grantMintAndBurnRoles()` function has a typo.

```solidity
function grantMintAndBurnRoles(address minAndBurner)
```

**Recommended Mitigation:** Correct the parameter name to 'mintAndBurner'.

**Startale:** Fixed in commit [669197](https://github.com/StartaleLabs/ccip-contracts-registration/commit/669197f945405f9805e90cc6fe49552c5f6e037a).

**Cyfrin:** Verified.


\clearpage