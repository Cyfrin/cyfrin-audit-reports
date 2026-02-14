**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

[BengalCatBalu](https://x.com/BengalCatBalu)

**Assisting Auditors**



---

# Findings
## Medium Risk


### `BasisTradeTailor` withdrawal request overwrite enables race conditions

**Description:** The `BasisTradeTailor::requestWithdrawal` function unconditionally overwrites any existing withdrawal request:

```solidity
// BasisTradeTailor.sol:556-560
function requestWithdrawal(address pocket, uint256 amount) external onlyPocketUser(pocket) {
    withdrawalRequests[pocket] = amount;  // Overwrites existing request
    emit WithdrawalRequested(pocket, amount);
}
```

There is no validation to prevent overwrites or explicit cancellation mechanism. Users attempting to modify their withdrawal amount create race conditions with the agent's `processWithdrawal()` calls.

**Impact:** Transaction ordering between user's `requestWithdrawal()` and agent's `processWithdrawal()` determines whether the request is replaced or accumulated, leading to users withdrawing more than intended.

When users call `requestWithdrawal()` to modify an existing request, they expect the new amount to **replace** the old amount. However, if the agent processes the original request first, the user's second call creates a **new** request instead of replacing the original, resulting in both amounts being withdrawn.

**Proof of Concept:**
```
Block N:
  User: requestWithdrawal(pocket, 100 baseAsset)
  withdrawalRequests[pocket] = 100

User realizes they want only 50 total, submits modification:

Block N+1 (both transactions in same block):
  User: requestWithdrawal(pocket, 50)    // User wants to REPLACE 100 with 50
  Agent: processWithdrawal(pocket, 100)  // Agent processes original request

Outcome depends on transaction order within block:

Case 1 - User tx executes first:
  1. withdrawalRequests[pocket] = 50 (replaced)
  2. Agent processes 50 baseAsset
  3. withdrawalRequests[pocket] = 0
  4. Result: User withdraws 50 total

Case 2 - Agent tx executes first:
  1. Agent processes 100 baseAsset, sets withdrawalRequests[pocket] = 0
  2. User sets withdrawalRequests[pocket] = 50 (creates NEW request)
  3. Agent later processes this 50 baseAsset request
  4. Result: User withdraws 150 total (100 + 50)

In Case 2, the user wanted to reduce their total withdrawal to 50 but received 150 due to transaction ordering.
```

Similar issue occurs when users call `requestWithdrawal(0)` to cancel - if the agent processes first, the full amount is withdrawn before cancellation takes effect.

**Recommended Mitigation:** Prevent changing from non-zero to non-zero by requiring explicit cancellation first. Add a separate `cancelWithdrawal()` function to set the request to zero:

```solidity
function requestWithdrawal(address pocket, uint256 amount) external onlyPocketUser(pocket) {
    require(amount > 0, "Amount must be positive");
    require(withdrawalRequests[pocket] == 0, "Cancel existing request first");

    withdrawalRequests[pocket] = amount;
    emit WithdrawalRequested(pocket, amount);
}

function cancelWithdrawal(address pocket) external onlyPocketUser(pocket) {
    uint256 currentRequest = withdrawalRequests[pocket];
    require(currentRequest > 0, "No pending request");

    withdrawalRequests[pocket] = 0;
    emit WithdrawalCancelled(pocket, currentRequest);
}
```

This prevents overwrites (cannot go from 100 → 50 directly) and makes cancellation explicit (must call `cancelWithdrawal()` to set to zero, cannot use `requestWithdrawal(0)`).

**Button:** FIxed in commit [`2aa92eb`](https://github.com/buttonxyz/button-protocol/commit/2aa92ebd0912eac61451767364cc31fd2671d8fc)

**Cyfrin:** Verified. Recommendation implemented.


\clearpage
## Low Risk


### `PoketFactory` is ERC-165 non compilant

**Description:** `PocketFactory` implements `IPocketFactory` but `supportsInterface()` doesn't check for it:

```solidity
// PocketFactory.sol:93-100
function supportsInterface(bytes4 interfaceId)
    public view override(AccessControlEnumerable) returns (bool)
{
    return super.supportsInterface(interfaceId);  // doesn't check IPocketFactory
}
```

This violates ERC-165 standard. Calling `pocketFactory.supportsInterface(type(IPocketFactory).interfaceId)` returns `false` even though the contract implements the interface.

**Recommended Mitigation:** Check for `IPocketFactory` interface explicitly:

```diff
function supportsInterface(bytes4 interfaceId)
    public view override(AccessControlEnumerable) returns (bool)
{
-   return super.supportsInterface(interfaceId);
+   return
+       interfaceId == type(IPocketFactory).interfaceId ||
+       super.supportsInterface(interfaceId);
}
```

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.


### First USDC transfer to unactivated HyperCore account loses 1 USDC to activation fee

**Description:** HyperCore accounts must be activated before they can receive spot transfers without fees. According to [HyperLiquid documentation](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/activation-gas-fee), the first inbound transfer to an unactivated account triggers activation, which charges a ~1 USDC fee automatically deducted from the transferred amount.

The `BasisTradeTailor::transferAssetToCore` function transfers USDC from pocket to HyperCore via CCTP without verifying the pocket's Core account is activated:

```solidity
// BasisTradeTailor.sol:295-312
function transferAssetToCore(address pocket, uint64 tokenIndex, uint256 amount) external onlyAgent {
    require(pocketUser[pocket] != address(0), "Pocket does not exist");
    require(amount > 0, "Amount must be positive");

    AssetConfig memory assetConfig = supportedAssets[tokenIndex];
    require(assetConfig.tokenAddress != address(0), "Asset not supported");

    if (tokenIndex == USDC_TOKEN_INDEX) {
        _transferUsdcToCore(pocket, amount);  // No activation check
    } else {
        address systemAddress = CoreWriterEncoder.getTokenSystemAddress(tokenIndex);
        IPocket(pocket).transfer(assetConfig.tokenAddress, systemAddress, amount);
    }
    // ...
}
```

Within `_transferUsdcToCore()`:

```solidity
// BasisTradeTailor.sol:319-335
function _transferUsdcToCore(address pocket, uint256 amount) internal {
    // Approve CoreDepositWallet
    bytes memory approveData = abi.encodeWithSelector(
        IERC20.approve.selector,
        coreDepositWallet,
        amount
    );
    IPocket(pocket).exec(usdcAddress, approveData);

    // Deposit to HyperCore via CCTP - no activation check!
    bytes memory depositData = abi.encodeWithSelector(
        ICoreDepositWallet.depositFor.selector,
        pocket,
        amount,
        uint32(type(uint32).max)
    );
    IPocket(pocket).exec(coreDepositWallet, depositData);
}
```

The [`L1Read`](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore) provides a `coreUserExists(address user)` method to check activation status, but this is not used. Additionally, deployment scripts (`script/TransferAssetToCore.s.sol`) also do not verify activation before initiating transfers.

**Impact:** If a newly created pocket's Core account is not activated before the first USDC transfer:

1. Agent calls `transferAssetToCore(pocket, USDC_TOKEN_INDEX, 100e6)` expecting 100 USDC to arrive on Core
2. CCTP transfer via `coreDepositWallet.depositFor()` is initiated
3. HyperLiquid detects unactivated account and deducts ~1 USDC activation fee
4. Only ~99 USDC arrives in the pocket's Core spot account
5. No event or error indicates this fee was charged

Which could result in an unexpected 1 USDC loss on first transfer to each new pocket, with no on-chain indication this occurred. Only trusted `AGENT_ROLE` addresses can trigger transfers, and the fee amount is small (1 USDC per pocket). Operators can activate accounts off-chain before first production deposit to avoid the fee. However, there is no on-chain enforcement or script-based check, relying entirely on operational discipline.

**Recommended Mitigation:** Add `coreUserExists` precompile check in `transferAssetToCore()` or `_transferUsdcToCore()` to verify account activation before the first transfer. Either revert with a clear error message directing operators to activate the account off-chain first, or create a script that handles activation separately (sending 1.1 USDC to cover the fee) before production deposits begin.

Additionally, update `script/TransferAssetToCore.s.sol` to check activation status and warn operators if transferring to an unactivated account.

**Button:** Fixed in [`8ca2df0`](https://github.com/buttonxyz/button-protocol/commit/8ca2df0164d8aea99bc34dd8a5e0e3ca5ec2234c)

**Cyfrin:** Verified. A call `activateCoreAccount` was added to `BasisTradeTailor` to send an amount `> 1 USDC`.


### Decimal mismatch in `BasisTradeTailor:transferHypeToCore` causes precision loss

**Description:** The `BasisTradeTailor::transferHypeToCore` function accepts `uint256 amount` with 18 decimals (HyperEVM standard), but when bridging to HyperCore, the amount is truncated to 8 decimals. Any precision beyond 8 decimals is permanently lost.

```solidity
// BasisTradeTailor.sol:400-412
function transferHypeToCore(address pocket, uint256 amount) external onlyOperator {
    require(pocketUser[pocket] != address(0), "Pocket does not exist");
    require(amount > 0, "Amount must be positive");

    IPocket(pocket).transferNative(
        CoreWriterEncoder.HYPE_SYSTEM_ADDRESS,  // Bridges to Core with 8 decimals
        amount  // uint256 with 18 decimals - precision beyond 8 decimals lost
    );

    lastCoreActionBlock[pocket] = block.number;
    emit LastCoreActionBlockUpdated(pocket, block.number);
    emit HypeTransferredToCore(pocket, amount);  // Emits full 18-decimal amount
}
```

Per [HyperLiquid documentation](https://hyperliquid.gitbook.io/hyperliquid-docs), HYPE uses 18 decimals on HyperEVM but only 8 decimals on HyperCore. The bridge automatically truncates any precision beyond 8 decimals.

**Impact:** Each bridge transaction loses the fractional amount beyond 8 decimal precision. While individual losses are small (~9e-10 HYPE per transaction in worst case), they accumulate over time and represent permanent fund loss.

**Recommended Mitigation:** Add validation requiring amounts to be multiples of `1e10` (8 decimal precision):

```solidity
function transferHypeToCore(address pocket, uint256 amount) external onlyOperator {
    require(pocketUser[pocket] != address(0), "Pocket does not exist");
    require(amount > 0, "Amount must be positive");
    require(amount % 1e10 == 0, "Amount must be multiple of 1e10 for 8-decimal precision");

    IPocket(pocket).transferNative(CoreWriterEncoder.HYPE_SYSTEM_ADDRESS, amount);

    lastCoreActionBlock[pocket] = block.number;
    emit LastCoreActionBlockUpdated(pocket, block.number);
    emit HypeTransferredToCore(pocket, amount);
}
```

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified. Amount verified to be a multiple of `1e10`.



### Morpho Blue Market Rewards Cannot Be Claimed by Pocket Owners

**Description:** Morpho Blue implements external reward distribution through [Merkl](https://docs.merkl.xyz/), a third-party reward distribution service. Per Merkl documentation, rewards are distributed manually - users must call claim functions to receive their rewards.

Pocket owners have no mechanism to claim Morpho rewards earned by their pockets:

```solidity
// Pocket.sol:92-110
function exec(address target, bytes calldata data)
    external
    onlyOwner
    returns (bytes memory result)
{
// Restricted only to interaction with CoreWriter
}
```

The MorphoBlueAdapter only supports core Morpho operations (supply, withdraw, borrow, repay) and does not include reward claiming.

**Impact:** Rewards earned through Morpho Blue market participation accumulate in Merkl's distribution contract but remain inaccessible to pocket users. According to [Merkl documentation](https://docs.merkl.xyz/earn-with-merkl/earning-with-merkl), some reward campaigns have claiming deadlines - unclaimed rewards may disappear if not processed before the deadline.

While Merkl offers [address remapping](https://docs.merkl.xyz/earn-with-merkl/earning-with-merkl#address-remapping) as a workaround (allowing smart contracts that cannot claim to forward rewards to an EOA), this requires manual intervention: pocket owners must contact the Merkl team, provide proof of ownership, and request remapping for each pocket individually.

Additionally, the protocol could upgrade `BasisTradeTailor` to add reward claiming functionality, but this leaves existing rewards unclaimed until the upgrade is deployed and executed.

**Recommended Mitigation:** There are two viable approaches to address this issue:

Approach 1: Add Operator-Controlled Reward Claiming (Requires Contract Changes)

Implement a restricted function that allows OPERATOR or AGENT roles to claim rewards on behalf of pockets and transfer them to the pocket owner.

Approach 2: Merkl Address Remapping Monitoring (No Contract Changes)

As a simpler alternative that requires no contract modifications, the protocol team can:

1. Monitor Merkl reward distributions for all Morpho campaigns
2. Proactively use Merkl's [address remapping feature](https://docs.merkl.xyz/earn-with-merkl/earning-with-merkl#address-remapping) to redirect rewards from pocket addresses (smart contracts) to the corresponding pocket owner EOAs
3. Automate this monitoring and remapping process as part of protocol operations

**Button:** Acknowledged, will not be addressing this. our current plans for this codebase is to have an external vault contract own an underlying pocket via tailor, unlikely that we have an immediate future for many retail pockets. if there are rewards to coordinate for the vault, we can take it on with the rewarding teams directly



### Dual-Purpose mapping forces permissions intersections

**Description:** The `BasisTradeTailor::addAsset` function sets both `registeredAssets` (used for adapter approvals in `executeAdapter()`) and `supportedAssets` (used for Core transfers in `transferAssetToCore/FromCore`) simultaneously:

```solidity
// BasisTradeTailor.sol:652-672
function addAsset(address asset, uint64 tokenIndex) external onlyOperator {
    registeredAssets[asset] = true;  // Used for executeAdapter approvals (line 796)
    supportedAssets[tokenIndex] = AssetConfig({
        asset: asset,
        tokenIndex: tokenIndex
    });  // Used for Core transfers
}
```

When using MorphoBlueAdapter, both loanToken and collateralToken must be approved via `executeAdapter()`, which requires them to be in `registeredAssets`. Since `addAsset()` sets both mappings together, enabling MorphoBlueAdapter automatically enables `transferAssetToCore()` and `transferAssetFromCore()` for those tokens.

**Impact:** The protocol cannot use MorphoBlueAdapter without enabling Core transfer operations for loanToken and collateralToken. This forced functionality addition means the OPERATOR cannot selectively enable Morpho lending without also allowing direct bridge transfers for those assets.

For example, the protocol might want to support USDC lending via Morpho but disable direct USDC transfers to Core. This configuration is impossible because `addAsset()` couples both permissions. The protocol loses granular control over which operations are permitted for each asset.

**Recommended Mitigation:** Separate the mappings to allow independent control for bridge and adapter functionality.

**Button:** Fixed in [`9a1ad0a`](https://github.com/buttonxyz/button-protocol/commit/9a1ad0a07694d1366cbf300db140e8d785fd2e7d)

**Cyfrin:** Verified. Mappings now separated.

\clearpage
## Informational


### `Pocket::execWithValue` does not emit native transfer event

**Description:** The `Pocket::execWithValue` function sends native tokens via the `value` parameter but only emits `Executed(target, selector)`, not `NativeTransferred(to, amount)`:

```solidity
// Pocket.sol:107
result = target.functionCallWithValue(data, value);  // sends native tokens

emit Executed(target, selector);  // doesn't include value amount
```

This differs from `transferNative()` which properly emits `NativeTransferred(to, amount)` (line 130). Off-chain systems tracking native token movements through events will miss transfers made via `execWithValue()`, since the `Executed` event doesn't include the `value` parameter.

**Recommended Mitigation:** Emit `NativeTransferred` when value is sent to maintain consistency with `transferNative()`

```diff
function execWithValue(...) external onlyOwner returns (bytes memory result) {
    require(target != address(0), "Invalid target");
    result = target.functionCallWithValue(data, value);

    bytes4 selector;
    if (data.length >= 4) {
        selector = bytes4(data[:4]);
    }

+   if (value > 0) {
+       emit NativeTransferred(target, value);
+   }
    emit Executed(target, selector);
}
```

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.


### `BasisTradeTailor::transferPerp` comment mismatch

**Description:** `BasisTradeTailor::transferPerp` NatSpec comment states "(agent only)" but the function uses `onlyEngine` modifier:

```solidity
// BasisTradeTailor.sol:373-378
/**
 * @notice Transfer funds between spot and perp accounts on HyperCore (agent only)
 */
function transferPerp(address pocket, uint64 amount, bool toPerp) external onlyEngine {
    // Comment says "agent only" but modifier is onlyEngine
```

The code implementation is likely correct since `ENGINE_ROLE` can call only this function, making the comment misleading.

**Recommended Mitigation:** Update the comment to match the implementation:

```diff
/**
- * @notice Transfer funds between spot and perp accounts on HyperCore (agent only)
+ * @notice Transfer funds between spot and perp accounts on HyperCore (engine only)
 * @param pocket Address of the pocket
 * @param amount Amount to transfer
 * @param toPerp True to transfer to perp, false to transfer to spot
 */
function transferPerp(address pocket, uint64 amount, bool toPerp) external onlyEngine {
```

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.



### `BasisTradeTailor::coreDepositWallet` is not blocked for adapters calls

**Description:** `BasisTradeTailor::executeAdapter` blocks `coreWriter` but not `coreDepositWallet`:

```solidity
// BasisTradeTailor.sol:781
require(target != coreWriter, "Adapter cannot call coreWriter");
// No check for coreDepositWallet
```

`CoreDepositWallet.depositFor(address user, ...)` can send pocket USDC to arbitrary Core addresses. While adapters are trusted, this creates inconsistency in Core contract restrictions - if `coreWriter` is blocked for defense-in-depth, `coreDepositWallet` (which also interacts with Core) should be blocked too.

**Recommended Mitigation:**
```diff
-require(target != coreWriter, "Adapter cannot call coreWriter");
+require(target != coreWriter && target != coreDepositWallet, "Adapter cannot call Core contracts");
```

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.



### `MorphoBlueAdapter::validateCalls` does not enforce `receiver == pocket`

**Description**
`MorphoBlueAdapter` constructs Morpho calls with `receiver = pocket` (e.g., `borrow(..., receiver)` and `withdrawCollateral(..., receiver)`), but `validateCalls` only validates `onBehalf == pocket` and does not check that the decoded `receiver` parameter also equals `pocket`. This weakens the adapter’s intended “calls are safe and self-contained to the Pocket” guarantee.

Consider require `receiver == pocket` in addition to `onBehalf == pocket` for applicable calls.

**Button:** Fixed in [`877074a`](https://github.com/buttonxyz/button-protocol/commit/877074a243524a6856c39a1d1fda803cdf927f3d).

**Cyfrin:** Verified. Also added some validation of additional market params.


### `PocketFactory::approveTailor` doesn't verify `ITailor` interface implementation

**Description:** The `PocketFactory.approveTailor()` function only validates that the tailor address is non-zero and has code, but doesn't verify it implements the `ITailor` interface required for pocket management operations. There is also no such check in `ApproveTailorInFactory.s.sol`

```solidity
// PocketFactory.sol:56-62
function approveTailor(address tailor) external onlyRole(OPERATOR_ROLE) {
    require(tailor != address(0), "Invalid tailor address");
    require(tailor.code.length > 0, "Tailor must be a contract");  // Only checks has code

    approvedTailors[tailor] = true;
    emit TailorApproved(tailor);
}
```

**Recommended Mitigation:** Add an ERC-165 interface check in `approveTailor()`. Also consider adding this check to the `ApproveTailorInFactory.s.sol` deployment script as an additional safety layer.

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.



### Upgrade script deploys implementation but doesn't execute upgrade

**Description:** The `UpgradeBasisTradeTailor.s.sol` script deploys a new implementation but doesn't execute the actual upgrade - line 44 is commented out.

```solidity
// UpgradeBasisTradeTailor.s.sol:38-48
// Deploy new implementation
BasisTradeTailor newImpl = new BasisTradeTailor(hypeTokenIndex, usdcAddress, coreDepositWallet);
console.log("New implementation deployed at:", address(newImpl));
console.log("HYPE Token Index:", hypeTokenIndex);
console.log("USDC Address:", usdcAddress);
console.log("CoreDepositWallet:", coreDepositWallet);

//tailor.upgradeToAndCall(address(newImpl), "");  // Commented out

vm.stopBroadcast();

console.log("\n=== Tailor Upgraded ===");  // Misleading - upgrade didn't happen
```

The script logs "Tailor Upgraded" but the proxy still points to the old implementation. The `runSafe()` function (lines 60-83) suggests upgrades are meant for Gnosis Safe, but the `run()` function's behavior could confuse operators expecting a complete upgrade.

**Recommended Mitigation:** Either uncomment line 44 to execute the upgrade, or update documentation and console logs to clarify this is "deploy-only" mode and upgrade must be executed separately via Safe or manual `upgradeToAndCall()`.

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.


### Adapter removal script lacks Safe-mode calldata output

**Description**
`RemoveAdapterFromBasisTradeTailor.s.sol` does not follow the `SAFE_MODE` pattern used in other operational scripts (i.e., printing `to/value/data` calldata for multisig execution) and instead relies on direct execution flow.

Consider add a `SAFE_MODE` path that prints the encoded calldata (`to`, `value`, `data`) for `removeAdapter(adapter)`.

**Button:** Fixed in commit [`b74a07d`](https://github.com/buttonxyz/button-protocol/commit/b74a07db825a07098bf83e06f9467308d9f0a211)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Batch pocket calls in `BasisTradeTailor::_transferUsdcToCore`

**Description**
`BasisTradeTailor::_transferUsdcToCore` currently performs three separate `IPocket.exec(...)` calls: approve USDC, call `depositFor`, then reset approval back to `0`. Each `exec` incurs repeated external-call overhead.

Consider adding a batched call function to `Pocket` (e.g., `call(Call[] calldata calls)`), and update `_transferUsdcToCore` to perform the approve, depositFor, reset sequence via a single Pocket call:

* `IPocket.sol`:
  ```solidity
  struct Call {
      address target;
      bytes data;
      uint256 value;
  }

  function exec(Call[] calldata calls) external returns (bytes[] memory results);
  ```

* `Pocket.sol`:

  ```solidity
  function exec(Call[] calldata calls) external onlyOwner returns (bytes[] memory results) {
      uint256 len = calls.length;
      results = new bytes[](len);

      for (uint256 i = 0; i < len; ++i) {
          Call memory call = calls[i];
          if (call.value == 0) {
              results[i] = exec(call.target, call.data);
          } else {
              results[i] = execWithValue(call.target, call.data, call.value);
          }
      }
  }
  ```
* `BasisTradeTailor._transferUsdcToCore`:
  ```solidity
  IPocket.Call calls = new IPocket.Call[3];
  calls[0] = IPocket.Call({ target: usdcAddress, data: approveData, value: 0 });
  calls[1] = IPocket.Call({ target: coreDepositWallet, data: depositData, value: 0 });
  calls[2] = IPocket.Call({ target: usdcAddress, data: resetApproveData, value: 0 });

  IPocket(pocket).call(calls);
  ```

**Button:** Fixed in [`4122fe7`](https://github.com/buttonxyz/button-protocol/commit/4122fe757d1db5cf0575379157357d65e23d1eab)

**Cyfrin:** Verified.

\clearpage