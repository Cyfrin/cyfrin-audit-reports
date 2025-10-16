**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

---

# Findings
## Low Risk


### Native HYPE transfers to HyperCore will not work

**Description:** `Hype_Module::hyper_depositSpot` always calls `IERC20(token).transfer(assetAddress(uint64(asset)), _wei)`, including when `asset == 150` (native HYPE). Per HyperCore [docs](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers#transferring-hype), HYPE (id `150`) must be transferred as native value to the special system address `0x2222…2222`, not via ERC-20. In addition, when transferring native HYPE the `token` parameter should be a placeholder (the zero address) to avoid ambiguity and accidental ERC-20 paths.

**Impact:** Native HYPE transfers will likely not work as the token parameter will either be a placeholder or, worst case a wrapped version where the transfer might succeed but the crediting of tokens on HyperCore will fail (as the asset id is wrong) resulting in lost tokens. It can also create ambiguity around the `token` parameter for native deposits can lead to misconfiguration or silent misrouting of funds.

**Recommended mitigation:**

* Make `hyper_depositSpot` `payable` and branch on `asset`:

  * If `asset == 150` (HYPE/native): require `token == address(0)` and `msg.value == _wei`, then send native value to `0x2222…2222`:

    ```diff
      function hyper_depositSpot(
          address token,
          uint32 asset,
          uint64 _wei
    - ) external onlyRole(EXECUTOR_ROLE) nonReentrant {
    + ) external payable onlyRole(EXECUTOR_ROLE) nonReentrant {
    +     if (asset == 150) {
    +         require(token == address(0), "token must be zero for HYPE");
    + 	      require(msg.value == _wei, "msg.value mismatch");
    +         (bool ok, ) = address(0x2222222222222222222222222222222222222222).call{value: _wei}("");
    + 	      require(ok, "native HYPE transfer failed");
    +         return;
    +     }

          IERC20(token).transfer(assetAddress(uint64(asset)), _wei);
      }
    ```
* Optionally overload or split the API (`hyper_depositSpotHype(uint64 _wei)` vs `hyper_depositSpotERC20(address token, uint32 asset, uint256 amount)`) to remove ambiguity.


**D2:** Fixed in commit [`134a2b1`](https://github.com/d2sd2s/d2-contracts/commit/134a2b1c4d40de852b60a3124f8e8ded9a025668) except for the part where we make it payable and check the msg.value as it's meant to transfer funds IN the strategy contract, not funds owned by the sender / operator.

**Cyfrin:** Verified. If `asset == 150` the Hype module now calls `0x22...22` with `value: _wei`.


### Unsafe ERC20 transfers

**Description:** `Hype_Module::hyper_depositSpot` uses `IERC20(token).transfer(...)` directly and ignores the return value. Many ERC-20s are non-standard (e.g., USDT) and either don’t return `bool` or revert on failure in non-obvious ways, making bare `transfer`/`transferFrom` unsafe.

**Impact:** Token transfers can silently fail or behave inconsistently across tokens, causing deposits not to be credited on Core and potentially leaving funds stranded in the caller.

**Recommended mitigation:**
Use OpenZeppelin’s `SafeERC20` for all token interactions:

```solidity
using SafeERC20 for IERC20;

IERC20(token).safeTransfer(assetAddress(uint64(asset)), amount);
```

**D2:** Acknowledged. We're not on mainnet and all tokens most likely use proper compliant ERC20 implementations, so we're skipping on adding SafeERC20 in. We will vet tokens we support in vaults before whitelisting and using.

\clearpage
## Informational


### `nonReentrant` not the first modifier

**Description**
Across `Hype_Module`, `nonReentrant` is listed after `onlyRole(EXECUTOR_ROLE)` on external functions. In Solidity, modifiers are applied left-to-right, and the first modifier becomes the outermost wrapper. For consistent defense-in-depth, `nonReentrant` should be first so it also guards any logic within subsequent modifiers (present or future), minimizing the risk that a modifier could perform state changes or external calls before the reentrancy guard is set.

Consider changing the functions to have `nonReentrant` as the first modifier.

**D2:** Fixed in commit [`c5aeb40`](https://github.com/d2sd2s/d2-contracts/commit/c5aeb405bc5c9b4cd2a173eacf6b8ebbd8890ea8)

**Cyfrin:** Verified.


### Consider using constants instead of magic numbers for action IDs

**Description:** The action IDs that are used to interact with HyperCore are currently hardcoded in Hype.sol module's functions.

For example, action ID = 6 represents the `spotSend` action:
```solidity
function hyper_sendSpot(
        uint64 asset,
        uint64 _wei
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant {
        sendAction(6, abi.encode(assetAddress(asset), asset, _wei));
    }
```

**Impact:** While this poses no risk, using constants instead of magic numbers improve code maintainability and readability to explain the magic number's intended purpose.

**Recommended Mitigation:** Consider implementing constants for each action ID hardcoded currently. For example, an action ID of 1 can be named as constant `LIMIT_ORDER_ACTION_ID`

**D2:** Fixed in commit [`41470c6`](https://github.com/d2sd2s/d2-contracts/commit/41470c60bd928fb6e67d0db285ef32f0b6490197)

**Cyfrin:** Verified.


### Parameter name mismatch between interface and implementation may be misleading

**Description:** In `IHype_Module`, the parameter names differ from the implementation:

* `hyper_sendSpot(uint64 token, uint64 _wei)` vs implementation uses `asset` for the first `uint64`
* `hyper_addApiWallet(address wallet, string calldata apiKey)` vs implementation uses `name` for the `string calldata`

The `apiKey` name is especially risky as it may lead someone to submit a secret API key on-chain, which would be permanently public.

Consider aligning interface and implementation parameter names (e.g., use `asset` and `name/label`).

**D2:** Fixed in commit [`5c5cec4`](https://github.com/d2sd2s/d2-contracts/commit/5c5cec46325b7ac061d49d8035c4901ed5db4ed4)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Remove loop when sending actions

**Description:** `Hype_Module::sendAction` manually allocates and copies a 4-byte header plus payload in a loop. Use packed encoding to avoid the loop and shrink bytecode, e.g.:

```solidity
bytes memory data = abi.encodePacked(bytes4(uint32(0x01000000) | uint32(actionIndex)), action);
```

This builds the prefix + payload in one go with lower gas and less code.

**D2:** Fixed in commit [`c5d3193`](https://github.com/d2sd2s/d2-contracts/commit/c5d319387671e889e1d1c6aaf5097b5653af6809)

**Cyfrin:** Verified.


### `Hype_module::assetAddress` can be `pure`

**Description:** `Hype_module::assetAddress` neither reads nor writes state. Mark it `internal pure` to enable compiler optimizations, allow static analysis/staticcall-style usage, and slightly reduce gas/bytecode size while preventing accidental state access.

**D2:** Fixed in commit [`a217930`](https://github.com/d2sd2s/d2-contracts/commit/a2179308e7ecef2247cd51af52ddb90f4507d896)

**Cyfrin:** Verified.

\clearpage