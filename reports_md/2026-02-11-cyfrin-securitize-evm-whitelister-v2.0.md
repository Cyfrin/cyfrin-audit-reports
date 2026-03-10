**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Stalin](https://x.com/0xStalin)

**Assisting Auditors**

 

---

# Findings
## Informational


### Incorrect pragma as support for defining operators on user-defined value types was added in Solidity 0.8.19

**Description:** These files have the following pragma:
* `contracts/uniswap/permissionedPools/libraries/PermissionFlags.sol`
* `contracts/uniswap/permissionedPools/BaseAllowListChecker.sol`
```solidity
pragma solidity ^0.8.0;
```

However this is incorrect as support for defining operators on user-defined value types was [added](https://www.soliditylang.org/blog/2023/02/22/user-defined-operators/) in Solidity 0.8.19.

**Recommended Mitigation:** Use the correct pragma:
```diff
- pragma solidity ^0.8.0;
+ pragma solidity ^0.8.19;
```

**Securitize:** Fixed in commit [f938341](https://github.com/securitize-io/bc-allowlist-checker-sc/commit/f9383415cfab4a1de5372212cd131ef0d1b9fb22) by using 0.8.22 consistent with the other contracts.

**Cyfrin:** Verified.


### `PermissionFlags::hasFlag` can't be used to check for `PermissionFlag::NONE`

**Description:** `PermissionFlags.sol` defines some operator functions, constants and a `hasFlag` function; examining these last two:
```solidity
    PermissionFlag constant NONE = PermissionFlag.wrap(0x0000);
    PermissionFlag constant SWAP_ALLOWED = PermissionFlag.wrap(0x0001);
    PermissionFlag constant LIQUIDITY_ALLOWED = PermissionFlag.wrap(0x0002);
    PermissionFlag constant ALL_ALLOWED = PermissionFlag.wrap(0xFFFF);

    function hasFlag(PermissionFlag permissions, PermissionFlag flag) internal pure returns (bool) {
        return PermissionFlag.unwrap(and(permissions, flag)) != 0;
    }
```

One side-effect of this implementation is that `hasFlag(ANY_VALUE, PermissionFlags.NONE)` always returns `false` since:
```solidity
hasFlag(ANY_VALUE, PermissionFlags.NONE)
// return ANY_VALUE & 0x0000 = 0x0000
// return 0x0000 != 0 → false
```

**Recommended Mitigation:** * Add a separate function in `PermissionFlags` to check this using direct equality:
```solidity
function hasNoPermissions(PermissionFlag permissions) internal pure returns (bool) {
    return permissions == NONE;
}
```

* Revert in `hasFlag` if the input `flag` is `NONE` to prevent this erroneous use case:
```diff
+ error InvalidFlagCheck();

function hasFlag(PermissionFlag permissions, PermissionFlag flag) internal pure returns (bool) {
+   if (flag == NONE) revert InvalidFlagCheck();
    return PermissionFlag.unwrap(and(permissions, flag)) != 0;
}
```

**Securitize:** Remove this functionality in commit [0b8d506](https://github.com/securitize-io/bc-allowlist-checker-sc/commit/0b8d5061582f9dcac3b3eb2e24d37aba1de5e5bf) as it was not being used.

**Cyfrin:** Verified.


### `PermissionFlags::hasFlag` incorrectly grants `ALL_PERMISSIONS` to `PermissionFlag::LIQUIDITY_ALLOWED` and `PermissionFlag::SWAP_ALLOWED`

**Description:** `PermissionFlags::hasFlag` returns true when checking the flag `LIQUIDITY_ALLOWED` against the flag `ALL_ALLOWED`; This means, when checking if an account allowed ONLY to add liquidity has permissions to do any operation (ALL_ALLOWED), `PermissionFlags::hasFlag` would incorrectly signal that the account indeed has permissions to do any operation.
- The same affects the `SWAP_ALLOWED` flag.
- The same affects validating the combination of `SWAP_ALLOWED` or `LIQUIDITY_ALLOWED`, `hasFlag` signals this combination as if it would be the `ALL_ALLOWED` flag.

**Impact:** Accounts flagged only to add liquidity or do swaps would receive ALL permissions, allowing them to perform operations they should not be allowed to.

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {PermissionFlag, PermissionFlags} from "../../contracts/uniswap/permissionedPools/libraries/PermissionFlags.sol";

contract PermissionFlagsTest is Test {
    using PermissionFlags for PermissionFlag;

    // Helper to make tests more readable
    function _has(PermissionFlag permissions, PermissionFlag flag) internal pure returns (bool) {
        return permissions.hasFlag(flag);
    }

    function test_hasFlag_SWAP_ALLOWED() public pure {
        PermissionFlag p = PermissionFlags.SWAP_ALLOWED;
        // assertFalse(_has(p, PermissionFlags.NONE));
        // assertTrue(_has(p, PermissionFlags.SWAP_ALLOWED));
        // assertFalse(_has(p, PermissionFlags.LIQUIDITY_ALLOWED));

        //@audit-issue => SWAP_ALLOWED flag is given ALL_ALLOWED permissions!
        assertTrue(_has(p, PermissionFlags.ALL_ALLOWED)); // single flag != ALL
    }

    function test_hasFlag_LIQUIDITY_ALLOWED() public pure {
        PermissionFlag p;

        p = PermissionFlags.LIQUIDITY_ALLOWED;
        // assertFalse(_has(p, PermissionFlags.NONE));
        // assertFalse(_has(p, PermissionFlags.SWAP_ALLOWED));
        // assertTrue(_has(p, PermissionFlags.LIQUIDITY_ALLOWED));

        //@audit-issue => LIQUIDITY_ALLOWED flag is given ALL_ALLOWED permissions!
        assertTrue(_has(p, PermissionFlags.ALL_ALLOWED));
    }

    // Combined Flags //
    function test_hasFlag_SWAP_or_LIQUIDITY() public pure {
        PermissionFlag p = PermissionFlags.SWAP_ALLOWED | PermissionFlags.LIQUIDITY_ALLOWED;
        assertFalse(_has(p, PermissionFlags.NONE));
        assertTrue(_has(p, PermissionFlags.SWAP_ALLOWED));
        assertTrue(_has(p, PermissionFlags.LIQUIDITY_ALLOWED));

        //@audit-issue => returns true as if it had ALL_ALLOWED permissions
        assertTrue_has(p, PermissionFlags.ALL_ALLOWED));

    }
}
```

**Recommended Mitigation:** Consider refactoring the `hasFlag` function as follows:
```solidity
    function hasFlag(PermissionFlag permissions, PermissionFlag flag) internal pure returns (bool) {
        if (PermissionFlag.unwrap(flag) == 0) return false;

        return and(permissions, flag) == flag;
    }
}
```

The fix accounts for the case when the provided flag is `NONE`, and also correctly decodes the provided `permissions` to verify the specified `flag` is a subset of the `permissions`.

**Securitize:** Remove this functionality in commit [0b8d506](https://github.com/securitize-io/bc-allowlist-checker-sc/commit/0b8d5061582f9dcac3b3eb2e24d37aba1de5e5bf) as it was not being used.

**Cyfrin:** Verified.


### `PermissionFlags::hasFlag` inconsistent validation for combined flags

**Description:** `PermissionFlags` allows checking for multiple combinations of flags and verifying whether an account has at least one (OR), or all of them (ALL).

The problem is that `PermissionFlags::hasFlag` doesn't correctly verify the combination of `SWAP_ALLOWED` and `LIQUIDITY_ALLOWED`, it returns false when should return true.

**Impact:** Using `PermissionFlags::hasFlag` to validate combined flags can lead to incorrect validation, allowing execution when it should not.

**Proof of Concept:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {PermissionFlag, PermissionFlags} from "../../contracts/uniswap/permissionedPools/libraries/PermissionFlags.sol";

contract PermissionFlagsTest is Test {
    using PermissionFlags for PermissionFlag;

    // Helper to make tests more readable
    function _has(PermissionFlag permissions, PermissionFlag flag) internal pure returns (bool) {
        return permissions.hasFlag(flag);
    }

    function test_hasFlag_SWAP_and_LIQUIDITY() public pure {
        PermissionFlag p = PermissionFlags.SWAP_ALLOWED & PermissionFlags.LIQUIDITY_ALLOWED;
        assertFalse(_has(p, PermissionFlags.NONE));
        assertFalse(_has(p, PermissionFlags.SWAP_ALLOWED));
        assertFalse(_has(p, PermissionFlags.LIQUIDITY_ALLOWED));
        assertFalse(_has(p, PermissionFlags.ALL_ALLOWED));

        assertTrue(p == p);
        //@audit-issue => hasFlag incapable of validating combined flags using AND
        assertTrue(_has(p, p));
    }
}
```

**Recommended Mitigation:** Consider restricting the use of `PermissionFlags::hasFlag` to validate individual flags; that is, revert execution when the value of the first parameter (`PermissionFlag permissions`) doesn't match any of the expected individual flags.

**Securitize:** Remove this functionality in commit [0b8d506](https://github.com/securitize-io/bc-allowlist-checker-sc/commit/0b8d5061582f9dcac3b3eb2e24d37aba1de5e5bf) as it was not being used.

**Cyfrin:** Verified.


### `PermissionFlags::and` function will encode the permission for `SWAP_ALLOWED` AND `LIQUIDITY_ALLOWED` as if the account would have `NONE` permissions

**Description:** Using `PermissionFlags::and` function to compute the combined permission for an account expecting to enforce that the account must have BOTH permissions incorrectly encodes the bits corresponding to the `NONE` permission.

```
`SWAP_ALLOWED` & `LIQUIDITY_ALLOWED` => `NONE`
0x0001 & 0x0002 => 0x0000
```

**Recommended Mitigation:** Taking into consideration the recommendation to fix issue [*`PermissionFlags::hasFlag` incorrectly grants `ALL_PERMISSIONS` to `PermissionFlag::LIQUIDITY_ALLOWED` and `PermissionFlag::SWAP_ALLOWED` *](#permissionflagshasflag-incorrectly-grants-allpermissions-to-permissionflagliquidityallowed-and-permissionflagswapallowed-) . Consider avoiding `and` when combining flags to assign permissions to an account. Instead, if the wanted result is to verify if an account has both permissions, then do it as follows:
```solidity
    function test_hasFlag_LIQUIDITY_or_SWAP() public pure {
        PermissionFlag p = PermissionFlags.LIQUIDITY_ALLOWED | PermissionFlags.SWAP_ALLOWED;
        // 0x0002          | 0x0001           = 0x0003
        assertTrue(_has(p, p));        // "Does the permission set p contain ALL the bits that are set in p?"
    }
```
So when we call `p.hasFlag(p)`:
- `permissions = p = 0x0003`
- `flag       = p = 0x0003`

Compute:
```
(permissions & flag) == flag
(0x0003 & 0x0003)    == 0x0003
0x0003               == 0x0003   → true!
```

**Securitize:** Remove this functionality in commit [0b8d506](https://github.com/securitize-io/bc-allowlist-checker-sc/commit/0b8d5061582f9dcac3b3eb2e24d37aba1de5e5bf) as it was not being used.

**Cyfrin:** Verified.


### Implement recommended changes to proposed vault whitelister standard

**Description:** Implement recommended [changes](https://ethereum-magicians.org/t/erc-proposal-vault-whitelister-interface-for-permissioned-erc-20-vaults/27627/2?u=dacian) to proposed vault whitelister standard.

**Securitize:** Fixed in commits [28ce1f8](https://github.com/securitize-io/bc-vault-whitelister/commit/28ce1f8fcdbaa0cbee26373ff6409e06222a8a02), [5ceab6d](https://github.com/securitize-io/bc-vault-whitelister/commit/5ceab6d815cc907fcc3b3fe372366ac4a92a560e).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### `BaseWhitelister::addOperator, removeOperator` should use `_grantRole` and `_revokeRole` directly and only emit events when they return `true`

**Description:** `BaseWhitelister::addOperator, removeOperator` use public functions `grantRole, revokeRole`; this is not ideal as these functions:
1) use [modifier](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L141) `onlyRole(getRoleAdmin(role))` but the access control has already been applied via modifier `onlyRole(DEFAULT_ADMIN_ROLE)`

2) call `_grantRole, _revokeRole` which [return](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L203) `bool` - if the returned `bool` is `false, the `ProtocolAuthorized, ProtocolRevoked` event would still be emitted even though no access was granted or revoked

**Recommended Mitigation:** `BaseWhitelister::addOperator, removeOperator` should directly call `_grantRole, _revokeRole` and only emit the events if the returned `bool` is `true`:
```solidity
    function addOperator(address operator) external onlyRole(DEFAULT_ADMIN_ROLE) notZeroAddress(operator) {
        if(_grantRole(OPERATOR_ROLE, operator)) emit ProtocolAuthorized(operator);
    }

    function removeOperator(address operator) external onlyRole(DEFAULT_ADMIN_ROLE) notZeroAddress(operator) {
        if(_revokeRole(OPERATOR_ROLE, operator)) emit ProtocolRevoked(operator);
    }
```

**Securitize:** Fixed in commit [c0bd66b](https://github.com/securitize-io/bc-vault-whitelister/commit/c0bd66b144d45a281b672d69eac0cc3c3c4c7dc8).

**Cyfrin:** Verified.


### `Whitelister::whitelist` duplicates checks already performed in `RegistryService::addWallet`

**Description:** `Whitelister::whitelist`  checks that the investor has a valid investor id, and that the given `vaultAddress` is not already a registered wallet.

However the function it calls `RegistryService::addWallet` already [performs](https://github.com/securitize-io/bc-vault-whitelister/blob/main/3-dstoken-reference/contracts/registry/RegistryService.sol#L163) these checks via the modifiers `investorExists(_id) newWallet(_address)`.

**Recommended Mitigation:** The modifier checks return the older-style text message errors while the new checks return typed errors. If the textual errors are sufficient, consider removing the duplicate checks. Otherwise if the typed errors are desired the existing code can be kept, it will just have slightly higher gas costs.

**Securitize:** Acknowledged; the duplicate checks are intentional and were kept for readability and explicitness at the call site.

\clearpage