**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Jorge](https://x.com/TamayoNft)

**Assisting Auditors**



---

# Findings
## Medium Risk


### `PrivateChainBridge, PublicBridge::lockTokens` allows locking tokens to unconfigured destination chains, permanently losing user funds

**Description:** `PrivateChainBridge::lockTokens` only validates that the destination chain is not `Private`:

```solidity
// PrivateChainBridge.sol:425-426
require(msg.value > 0, "Amount required");
require(destinationChain != DestinationChain.Private, "Cannot bridge to self");
```

The `DestinationChain` enum includes `Reserved4` through `Reserved8` (values 4-8) intended for future chain expansion via `setChainId`. However, a user can call `lockTokens` with any of these Reserved values before the owner configures them. The tokens are locked in the vault, the `TokensLocked` event emits with `chainId = 0` (unconfigured default), and relayers have no corresponding destination bridge to process the release.

```solidity
// PrivateChainBridge.sol:443-461
uint256 chainId = getChainId(destinationChain); // returns 0 for unconfigured chains

emit TokensLocked(
    msg.sender,
    bridgeAmount,
    uniqueHash,
    destinationChain,
    chainId  // 0 — relayers cannot route this
);
```

The locked tokens cannot be recovered — the `TokenVault` has no sweep function and only releases tokens via the bridge's `_releaseTokens` path, which requires relayer signatures from the non-existent destination chain.

**Impact:** Native tokens locked to unconfigured destination chains are irrecoverable; users permanently lose their funds.

**Recommended Mitigation:** Validate that the destination chain has a configured chain ID:

```solidity
function lockTokens(DestinationChain destinationChain) external payable nonReentrant whenNotPaused {
    require(msg.value > 0, "Amount required");
    require(destinationChain != DestinationChain.Private, "Cannot bridge to self");
    uint256 destChainId = getChainId(destinationChain);
    require(destChainId != 0, "Destination chain not configured");
    // ... use destChainId instead of calling getChainId again
}
```

The same fix is required for `PublicBridge::lockTokens`, or alternatively just emit 0 for the chainId if 0 is valid value for the private chain.

**BridgeX:**
Fixed in commits [ab40545](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/ab405453d0cbd92b0ea4bbb6817c7c46659fac58), [3320c2b](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/3320c2b6d4fd4abba83e40b81a66c6687285c034), [32882e0](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/32882e07d78a39d435db99c46950ca286687dca1).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Use low-level call to send ETH if return data is unimportant to avoid return bomb DoS and for gas efficiency

**Description:** Use low-level call to send ETH if return data is unimportant, for example in `PublicBridge::payReleaseFee`:
```diff
-               (bool success, ) = payable(releasers[i]).call{value: feePerReleaser}("");
+               bool success;
+               address feeReceiver = releasers[i];

+               assembly {
+                   success := call(gas(), feeReceiver, feePerReleaser, 0, 0, 0, 0)
+               }
```

This avoids the "return-bomb" DoS attack and is also more gas efficient. All affected places:
```solidity
PublicBridge.sol
392:                (bool success, ) = payable(releasers[i]).call{value: feePerReleaser}("");
402:            (bool success, ) = payable(releasers[0]).call{value: remainingWei}("");
414:            (bool success, ) = payable(msg.sender).call{value: refundAmount}("");

PrivateChainBridge.sol
390:                (bool success, ) = payable(releasers[i]).call{value: feePerReleaser}("");
400:            (bool success, ) = payable(releasers[0]).call{value: remainingWei}("");
412:            (bool success, ) = payable(msg.sender).call{value: refundAmount}("");
```

**BridgeX:**
Fixed in commit [efb6843](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/efb6843d02d675cb869aa916bcfceceae24a831b).

**Cyfrin:** Verified.


### `PublicBridge, PrivateChainBridge::payReleaseFee` will revert from out-of-gas if too many releasers are added

**Description:** `PublicBridge, PrivateChainBridge::payReleaseFee` uses a push-based pattern to distribute fees, iterating over the entire `releasers` array and sending native tokens to each releaser individually:

```solidity
// PublicBridge.sol:390-397 (same pattern in PrivateChainBridge.sol:388-395)
uint256 distributed = 0;
for (uint i = 0; i < releasers.length; i++) {
    if (feePerReleaser > 0) {
        (bool success, ) = payable(releasers[i]).call{value: feePerReleaser}("");
        if (success) {
            distributed += feePerReleaser;
        }
    }
}
```

As acknowledged in the `README.md` (Known Issue 1 — releasers are trusted, Known Issue 7 — failed transfers are refunded to sender rather than held), this design intentionally skips failed transfers and refunds undistributed portions. However, the push pattern has two inherent drawbacks:

1. **Unbounded iteration:** Every call to `payReleaseFee` iterates the full `releasers` array. With the addition of Reserved enum values for future chain expansion, the number of releasers may grow. Gas cost scales linearly with the number of releasers, and at sufficient scale, `payReleaseFee` could exceed the block gas limit

2. **Partial failure discounts:** When some (but not all) releaser transfers fail, the undistributed portion is refunded to the caller while the full release credits are retained. For example, with 2 releasers and 1 failing, the user pays 50% of the intended fee but receives full release eligibility. The affected releaser receives no compensation for that release

A pull-based (withdrawal) pattern would address both concerns:

```solidity
// Pull-based alternative
mapping(address releaserAddr => uint256 feeBalance) public releaserFeeBalance;

function payReleaseFee() external payable nonReentrant whenNotPaused {
    require(msg.value >= releaseFee, "Insufficient fee");
    require(releasers.length > 0, "No releasers available");

    uint256 eligibleReleases = msg.value / releaseFee;
    uint256 totalFee = eligibleReleases * releaseFee;

    // O(1) — no iteration over releasers
    uint256 feePerReleaser = totalFee / releasers.length;
    uint256 remainingWei = totalFee - (feePerReleaser * releasers.length);
    for (uint256 i; i < releasers.length; i++) {
        releaserFeeBalance[releasers[i]] += feePerReleaser;
    }
    if (remainingWei > 0) {
        releaserFeeBalance[releasers[0]] += remainingWei;
    }

    eligibleBridgeReleases[msg.sender] += eligibleReleases;

    // Refund only the excess beyond full release fees
    uint256 refundAmount = msg.value - totalFee;
    if (refundAmount > 0) {
        (bool success, ) = payable(msg.sender).call{value: refundAmount}("");
        require(success, "Refund failed");
    }

    _processPendingReleases(msg.sender);
}

function claimReleaserFees() external {
    uint256 amount = releaserFeeBalance[msg.sender];
    require(amount > 0, "No fees to claim");
    releaserFeeBalance[msg.sender] = 0;
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Transfer failed");
}
```

This eliminates partial refund complexity, ensures full fee accounting regardless of individual releaser transfer success, and makes `payReleaseFee` O(1) for the fee acceptance path (the releaser iteration for balance updates remains but involves no external calls).

**BridgeX:**
Acknowledged; we may implement a pull-based pattern in a subsequent version. For now the expected releaser set is small (2-5 addresses) so we will keep the current simple implementation.


### `PublicBridge, PrivateChainBridge::removeReleaser` can reduce releasers below `requiredSignatures`, making all release unprocessable

**Description:** `PublicBridge, PrivateChainBridge::removeReleaser` does not validate that `releasers.length` remains at or above `requiredSignatures` after removal:

```solidity
function removeReleaser(address _releaser) external onlyOwner {
    require(isReleaser[_releaser], "Not a releaser");
    isReleaser[_releaser] = false;
    for (uint i = 0; i < releasers.length; i++) {
        if (releasers[i] == _releaser) {
            releasers[i] = releasers[releasers.length - 1];
            releasers.pop();
            break;
        }
    }
    // missing: require(releasers.length >= requiredSignatures)
}
```

While `setRequiredSignatures` validates `_requiredSignatures <= releasers.length`, the reverse check is absent from `removeReleaser`. If the owner removes releasers to bring the count below `requiredSignatures`, the `signatureCount[txHash] >= requiredSignatures` condition in `signRelease` can never be met, making all in-progress and future releases unprocessable.

**Impact:**
- All releases become stuck until the owner either adds releasers back or calls `setRequiredSignatures` with a lower value
- In-progress releases that already have some signatures collected cannot reach the threshold
- Recoverable by the owner, but creates a window where the bridge is non-functional

**Recommended Mitigation:** Add a bounds check to `removeReleaser` in both bridges:

```solidity
function removeReleaser(address _releaser) external onlyOwner {
    require(isReleaser[_releaser], "Not a releaser");
    uint256 releasersLength = releasers.length;
    require(releasersLength > requiredSignatures, "Would break signature threshold");
    // ... existing removal logic ...
}
```

**BridgeX:**
Acknowledged; the owner role is trusted and would typically pause the bridge during relayer rotation. Adding a hard block on removal could hinder emergency response if a relayer is compromised. The owner can adjust `requiredSignatures` as needed.


### Constructors don't validate `releaseFee > 0`, causing `payReleaseFee` to panic with division by zero

**Description:** Both bridge constructors accept `_releaseFee` without validating it is greater than zero:

```solidity
// PublicBridge.sol:302-312
constructor(address _token, uint256 _releaseFee, uint256 _bridgeFee, address _bridgeFeeReceiver) {
    token = IERC20(_token);
    owner = msg.sender;
    releaseFee = _releaseFee; // no validation — allows 0
    // ...
}

// PrivateChainBridge.sol:282-296
constructor(uint256 _releaseFee, uint256 _bridgeFee, address _bridgeFeeReceiver) {
    owner = msg.sender;
    releaseFee = _releaseFee; // no validation — allows 0
    // ...
}
```

While `setReleaseFee` enforces `require(_newFee > 0, "Fee must be positive")`, the constructor has no equivalent check. If deployed with `releaseFee = 0`, the `payReleaseFee` function panics with a division by zero on its first line of computation:

```solidity
// Both bridges: payReleaseFee()
uint256 eligibleReleases = msg.value / releaseFee; // Panic(0x12) when releaseFee == 0
```

**Impact:**
- `payReleaseFee` always panics with an opaque `Panic(0x12)` error instead of a meaningful revert message
- All releases go to pending state since no user can pay the release fee
- Only `forceProcessPendingRelease` (owner-only) can process releases
- Recoverable via `setReleaseFee`, but creates a confusing failure mode at deployment

**Recommended Mitigation:** Add validation in both constructors:

```solidity
require(_releaseFee > 0, "Fee must be positive");
```

**BridgeX:**
Fixed in commit [69b0e8e](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/69b0e8e2e0421df80c7a3501090f1380cfef4b94).

**Cyfrin:** Verified.


### Use Foundry's encrypted secure private key storage instead of plaintext environment variables

**Description:** Both deployment scripts read the deployer's private key from a plaintext environment variable:

```solidity
// DeployPrivateBridge.s.sol:10
uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

// DeployPublicBridge.s.sol:11
uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
```

This requires the private key to be stored in a `.env` file or shell environment as unencrypted plaintext. Plaintext private keys are exposed through version control leaks (accidental `.env` commits), shell history, misconfigured backups, compromised developer machines, or CI/CD logs. The deployer key is particularly sensitive as it becomes the `owner` of both bridge contracts with full admin privileges (pause, set fees, add/remove releasers, force-process releases).

**Impact:**
- Deployer private key exposure compromises the owner role on all deployed bridge contracts
- Attacker with the key can pause bridges, drain fees, manipulate releasers, or force-process releases
- Risk persists after deployment since the deployer key remains the owner

**Recommended Mitigation:** Use Foundry's encrypted keystore instead of plaintext environment variables:

```bash
# Import key once (encrypted with password, stored in ~/.foundry/keystores/)
cast wallet import deployer --interactive

# Use in deployment scripts (prompts for password, key never in plaintext)
forge script script/DeployPublicBridge.s.sol --account deployer --broadcast
```

Update deployment scripts to remove the private key parameter:

```solidity
function run() external {
    // No private key in environment — Foundry decrypts from keystore at runtime
    vm.startBroadcast();
    // ... deployment logic ...
    vm.stopBroadcast();
}
```

See this Updraft [lesson](https://updraft.NerdUnited-NodeGovernance.io/courses/foundry/foundry-simple-storage/never-use-a-env-file) on using Foundry's encrypted secure private key storage.

**BridgeX:**
Fixed in commit [caf269f](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/caf269f05feaff8b9c6ee8003b871d3d70e0ffc4).

**Cyfrin:** Verified.


### Pending Releases in `PrivateChainBridge` could be stuck

**Description:** In `PrivateChainBridge`, pending releases are processed via `PrivateChainBridge::_processPendingReleases`, which calls `PrivateChainBridge::_releaseTokens` that reverts when the vault does not have enough native tokens (or the receiver can not receive native tokens because is an smart contract). Because `PrivateChainBridge::_releaseTokens` has no return value and uses a require on vault balance, any insufficient balance condition (or revert inside `vault::release`) will revert the entire transaction, blocking processing of that user’s pending releases and reverting their fee payment, in case that the loop already processed successfull payment it will revert all of them.  This contrasts with `PublicBridge`, where `PublicBridge::_releaseTokens` returns a bool and `PublicBridge::_processPendingReleases` handles failures gracefully by keeping the failing release pending and breaking the loop without reverting the whole transaction.

Private bridge release and processing:
```solidity
    function _processPendingReleases(address recipient) internal {
        PendingRelease[] storage releases = pendingReleasesByRecipient[recipient];

        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
            if (releases[i].exists) {
                eligibleBridgeReleases[recipient]--;

                _releaseTokens(//@audit ok if a single token fail here then the rest of the releases will be stuck
                    payable(releases[i].recipient),
                    releases[i].amount,
                    releases[i].destinationChain
                );
```

```solidity
  function _releaseTokens(
        address payable to,
        uint256 amount,
        DestinationChain destinationChain
    ) internal {
        require(address(vault).balance >= amount, "Insufficient vault balance");

        vault.release(to, amount);

        uint256 chainId = getChainId(destinationChain);

        emit TokensReleased(to, amount, destinationChain, chainId);
    }
```


**Impact:** If `address(vault).balance < amount` for any pending release in `PrivateChainBridge`, `PrivateChainBridge::_releaseTokens` reverts, causing the entire `PrivateChainBridge::_processPendingReleases` call  to revert. The user’s pending releases cannot be processed until the vault is fully funded for the first failing release, effectively blocking all the user’s queued releases behind it.


**Recommended Mitigation:** Align `PrivateChainBridge` behavior with `PublicBridge` non-reverting pattern.

**BridgeX:**
Fixed in commit [e390a56](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/e390a56203b64f7a56b0c2e7b91850e2418bb1e2).

**Cyfrin:** Verified.


### No way to recover or refund unused eligible releases in the bridges

**Description:** In the bridge contracts, users prepay the release fee via `Bridge::payReleaseFee` and receive a credit in `eligibleBridgeReleases[msg.sender]`. That credit is only consumed when pending releases are actually processed in  `Bridge::_processPendingReleases`.

There is no function or flow that allows users to recover, refund, or transfer unused eligibility. If a user pays for more releases than they have pending the extra eligibility remains in the contract forever and cannot be turned back into value or given to someone else. Eligibility is only decremented when a pending release is processed (and incremented again only when that single release fails):
```solidity
        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
            if (releases[i].exists) {
                eligibleBridgeReleases[recipient]--;

                if (_releaseTokens(
                    releases[i].recipient,
                    releases[i].amount,
                    releases[i].destinationChain
                )) {
                    emit PendingReleaseProcessed(
                        releases[i].recipient,
                        releases[i].amount,
                        releases[i].sourceChainTxHash
                    );
                    releases[i].exists = false;
                } else {
                    eligibleBridgeReleases[recipient]++;
                    break;
                }
```
There is no other code path that decreases or refunds `eligibleBridgeReleases` for unused slots.

**Impact:** Users who overpay or never get pending releases end up with unused eligibility that cannot be refunded, transferred, or otherwise used.

**Recommended Mitigation:** Add a function (e.g. `refundUnusedEligibility` or `refundEligibleReleases(uint256 count)`) that lets users surrender unused `eligibleBridgeReleases` to have their remaining fees refunded.

**BridgeX:**
Acknowledged; a user's unused credits are consumed on future releases and refunds are impossible since fees are paid to relayers immediately. Adding a refund path would require the contract to hold funds introducing extra complexity and potential drain vectors.

\clearpage
## Informational


### Use named imports

**Description:** Use named imports:
```diff
PublicBridge.sol
- import "./Token.sol";
+ import {IERC20, Token} from "./Token.sol";
```

**BridgeX:**
Fixed in commit [5b5523c](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/5b5523c72792d61b9c3ba11a32af246838ac9a04).

**Cyfrin:** Verified.


### Use named mapping parameters to explicitly denote the purpose of keys and values

**Description:** Use named mapping parameters to explicitly denote the purpose of keys and values:
```solidity
PublicBridge.sol
79:    mapping(address => bool) public isReleaser;
100:    mapping(DestinationChain => uint256) public chainIds;
103:    mapping(bytes32 => bool) public processedHashes;
106:    mapping(address => uint256) public eligibleBridgeReleases;
109:    mapping(bytes32 => mapping(address => bool)) public signatures;
112:    mapping(bytes32 => uint256) public signatureCount;
129:    mapping(address => PendingRelease[]) public pendingReleasesByRecipient;
135:    mapping(address => bool) public hasPendingReleases;

PrivateChainBridge.sol
62:    mapping(DestinationChain => uint256) public chainIds;
65:    mapping(address => bool) public isReleaser;
94:    mapping(bytes32 => bool) public processedHashes;
97:    mapping(address => uint256) public eligibleBridgeReleases;
100:    mapping(bytes32 => mapping(address => bool)) public signatures;
103:    mapping(bytes32 => uint256) public signatureCount;
120:    mapping(address => PendingRelease[]) public pendingReleasesByRecipient;
126:    mapping(address => bool) public hasPendingReleases;

Token.sol
25:    mapping (address => uint256) public override balanceOf;
26:    mapping (address => mapping (address => uint256)) public override allowance;
```

**BridgeX:**
Fixed in commit [43b99ff](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/43b99ff62021c64bf214a6bf213ec8a8b9d19314).

**Cyfrin:** Verified.


### Emit missing events for important state changes

**Description:** Emit missing events for important state changes:
* `PublicBridge, PrivateChainBridge::addReleaser, removeReleaser, setRequiredSignatures, setChainId`

**BridgeX:**
Fixed in commit [5899b57](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/5899b573f7c4f57aa27b358b3f3c9932a1699db5).

**Cyfrin:** Verified.


### Implement a reasonable hard-coded limit on maximum fees

**Description:** Implement a reasonable hard-coded limit on maximum fees:
* `PublicBridge, PrivateChainBridge::constructor, setReleaseFee, setBridgeFee`

At the moment the contract owner could change the release fee to something unreasonable which would prevent users from releasing their tokens.

**BridgeX:**
Acknowledged; may implement in a future version.


### Prefix `private, internal` function names with `_` character

**Description:** Prefix `private, internal` function names with `_` character:
* `Token::updateBalance`

**BridgeX:**
Fixed in commit [c2d98c6](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/c2d98c6df7abdb3d99105ddde6d8ae5d7ed77ada).

**Cyfrin:** Verified.


### Use explicit `uint256` instead of `uint`

**Description:** Use explicit `uint256` instead of `uint`:
```solidity
PublicBridge.sol
332:        for (uint i = 0; i < releasers.length; i++) {
374:        for (uint i = 0; i < releasers.length; i++) {
560:        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
591:        for (uint i = 0; i < releases.length; i++) {
601:            for (uint i = 0; i < pendingRecipients.length; i++) {
612:            for (uint i = 0; i < releases.length; i++) {
620:            for (uint i = 0; i < newReleases.length; i++) {

PrivateChainBridge.sol
320:        for (uint i = 0; i < releasers.length; i++) {
376:        for (uint i = 0; i < releasers.length; i++) {
541:        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
570:        for (uint i = 0; i < releases.length; i++) {
580:            for (uint i = 0; i < pendingRecipients.length; i++) {
591:            for (uint i = 0; i < releases.length; i++) {
599:            for (uint i = 0; i < newReleases.length; i++) {

Token.sol
7:    function transfer(address recipient, uint amount) external returns (bool);
8:    function transferFrom(address sender, address recipient, uint amount) external returns (bool);
9:    function approve(address spender, uint amount) external returns (bool);
12:    event Transfer(address indexed from, address indexed to, uint value);
13:    event Approval(address indexed owner, address indexed spender, uint value);
```

**BridgeX:**
Fixed in commit [97b6c65](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/97b6c6589301b2f662d66e25a22a87a3f4627897) for `PublicBridge, PrivateChainBridge`.

**Cyfrin:** Verified.


### `Token::setIssuer` allows setting issuer to `address(0)`, disabling minting

**Description:** `Token::constructor` validates that the issuer is non-zero, but `setIssuer` has no such check:

```solidity
// Token.sol:51 — constructor validates
require(tokenIssuer != address(0)); // dev: invalid issuer

// Token.sol:92-98 — setIssuer does not
function setIssuer(address newIssuer)
external
only(owner) {
    issuer = newIssuer; // no zero-address check
    emit NewIssuer(issuer);
}
```

Setting `issuer` to `address(0)` disables minting since `msg.sender` can never equal `address(0)`, and only the owner (not the issuer) can call `setIssuer` to recover. The Certora spec `mintAlwaysRevertsAfterZeroIssuer` in `Token.spec` confirms this behavior.

**Impact:** If the owner accidentally calls `setIssuer` with `address(0)`, minting is permanently disabled. The `PublicBridge::_releaseTokens` mint fallback would also break, forcing all releases to depend entirely on vault balance. This may be intentional to disable minting post-distribution, but the inconsistency with the constructor check suggests an oversight.

**Recommended Mitigation:** If this behavior is not desired, add a zero-address check consistent with the constructor:

```solidity
function setIssuer(address newIssuer) external only(owner) {
    require(newIssuer != address(0)); // dev: invalid issuer
    issuer = newIssuer;
    emit NewIssuer(issuer);
}
```

**BridgeX:**
Fixed in commit [c0c2f38](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/c0c2f38eb6731acf2d6ebfca252dcba33a26c0fe).

**Cyfrin:** Verified.


### `PublicBridge::lockTokens` allows zero-amount bridge operations when bridge fee is zero

**Description:** When `bridgeFee == 0`, calling `lockTokens` with `amount = 0` succeeds because the fee check is skipped entirely:

```solidity
uint256 bridgeAmount = amount; // 0
if (bridgeFee > 0) { // false, skipped
    // ...
}
require(token.transferFrom(msg.sender, address(vault), bridgeAmount), "Transfer to vault failed");
// transferFrom with 0 amount succeeds on this Token
```

This emits a `TokensLocked` event with zero amount and increments `_nonce`, which could create misleading events for relayer nodes that monitor lock events.

**Recommended Mitigation:** Add a minimum amount check:

```solidity
require(amount > 0, "Amount required");
```

**BridgeX:**
Fixed in commit [a460520](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/a4605205cabafdec3fd9f30147c87d1c4b4dd612).

**Cyfrin:** Verified.


### Removed releaser sign still count

**Description:** When `Bridge::removeReleaser` is called, the contract only sets `isReleaser[_releaser] = false` and removes the address from the releasers array. It does not clear or adjust any existing signature state. So for every release that the removed releaser had already signed, `signatures[txHash][_releaser]` stays true and `signatureCount[txHash]` is unchanged. Those past signatures remain valid and still count toward the threshold when other releasers call `Bridge::signRelease`.

**Recommended Mitigation:** When removing a releaser, do not change past signatures/signatureCount but document that removed releasers’ existing signatures still count and that `requiredSignatures` / releaser set should be managed with that in mind, or introduce a way to invalidate in-progress releases that include the removed releaser’s signature

**BridgeX:**
Acknowledged; generally releasers will only be rotated when there are emergencies and the bridge is paused. Addressing this would add a degree of complexity for little gain so we will not implement at this time.


### Sanity check correct `chainId` matches current chain in `PublicBridge, PrivateChainBridge::_releaseTokens`

**Description:** `PublicBridge::_releaseTokens` fetches the `chainId` for the input `destinationChain` but never verifies that the `chainId` matches the current chain. Consider adding in this validation to prevent a scenario where the releasers sign for the incorrect `destinationChain`:
```diff

  function _releaseTokens(
      address to,
      uint256 amount,
      DestinationChain destinationChain
  ) internal returns (bool) {
+     uint256 chainId = getChainId(destinationChain);
+     require(chainId == block.chainid, "Invalid destination chain for this bridge");

      uint256 vaultBalance = token.balanceOf(address(vault));
      // ... rest unchanged but use `chainId` instead of calling `getChainId`
```

A similar fix should be implemented in `PrivateChainBridge::_releaseTokens` to enforce that `destinationChain == DestinationChain.Private`.

**BridgeX:**
Fixed in commit [f9686e8](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/f9686e850067e5deaae6ca97077a666539086821).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Use `immutable` variables for non-upgradeable contracts whose storage is only set once in the constructor

**Description:** Use `immutable` variables for non-upgradeable contracts whose storage is only set once in the constructor:
* `PublicBridge::TokenVault::bridge, token`
* `PublicBridge::token, vault`
* `PrivateChainBridge::TokenVault::bridge`
* `PrivateChainBridge::vault`
* `Token::maxSupply, decimals`

**BridgeX:**
Fixed in commits [0917ee5](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/0917ee5359db3171c9bd4a4518f0bb3b52e8c5cd), [32882e0](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/32882e07d78a39d435db99c46950ca286687dca1).

**Cyfrin:** Verified.


### In Solidity don't initialize to default values

**Description:** In Solidity don't initialize to default values:
```solidity
PublicBridge.sol
73:    bool public paused = false;
348:        for (uint i = 0; i < releasers.length; i++) {
389:        uint256 distributed = 0;
390:        for (uint i = 0; i < releasers.length; i++) {
576:        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
606:        uint256 remainingCount = 0;
607:        for (uint i = 0; i < releases.length; i++) {
617:            for (uint i = 0; i < pendingRecipients.length; i++) {
626:            uint256 index = 0;
628:            for (uint i = 0; i < releases.length; i++) {
636:            for (uint i = 0; i < newReleases.length; i++) {

PrivateChainBridge.sol
74:    bool public paused = false;
332:        for (uint i = 0; i < releasers.length; i++) {
387:        uint256 distributed = 0;
388:        for (uint i = 0; i < releasers.length; i++) {
553:        for (uint i = 0; i < releases.length && eligibleBridgeReleases[recipient] > 0; i++) {
581:        uint256 remainingCount = 0;
582:        for (uint i = 0; i < releases.length; i++) {
592:            for (uint i = 0; i < pendingRecipients.length; i++) {
601:            uint256 index = 0;
603:            for (uint i = 0; i < releases.length; i++) {
611:            for (uint i = 0; i < newReleases.length; i++) {
```

**BridgeX:**
Fixed in commit [bd98983](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/bd989836069abbd3958c35a350f07ef4e6ea78b2).

**Cyfrin:** Verified.


### Better storage packing

**Description:** In Solidity:
* reading and writing from `storage` is expensive
* the order of storage declaration is important as it results in more or less `storage` slots being used to store the same data

Achieve better storage packing by:
* struct `PendingRelease` - declare `destinationChain, exists` after `recipient`
```solidity
PublicBridge.sol
112:    struct PendingRelease {

PrivateChainBridge.sol
103:    struct PendingRelease {
```

**BridgeX:**
Fixed in commit [937ba7c](https://github.com/NerdUnited-NodeGovernance/bridge-x-contracts/commit/937ba7cfe338d80b004dc7dbe9bc811aaab31db4).

**Cyfrin:** Verified.


### For reentrancy protection use `transient` keyword or `ReentrancyGuardTransient` instead of declaring a `storage` variable

**Description:** For reentrancy protection use `transient` keyword or [ReentrancyGuardTransient](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) instead of declaring a `storage` variable:
```solidity
PublicBridge.sol
67:    uint256 private _locked = 1;

PrivateChainBridge.sol
71:    uint256 private _locked = 1;
```

Both solutions require increasing the solidity version but this should be fine as the current version 0.8.18 is relatively old.

**BridgeX:**
Acknowledged; some of our chains are a bit older and don't have TSTORE and other modern opcodes like that. We'll make a note of it because the chain we will be deploying this on first is more modern, but we tend to like to keep these contracts as consistent as possible for all brands.


### Cache storage to avoid identical storage reads

**Description:** In Solidity reading from storage is expensive; cache storage to avoid identical storage reads when the value can't change:
* `PublicBridge, PrivateChainBridge::removeReleaser` - cache `releasers.length`
* `PublicBridge, PrivateChainBridge::payReleaseFee` - cache `releaseFee, releasers.length`
* `PublicBridge, PrivateChainBridge::lockTokens` - cache `bridgeFee` prior to the `if` check and use cached value, cache `bridgeFeeReceiver` inside the `if` check
* `PublicBridge, PrivateChainBridge::signRelease` - cache `signatureCount[txHash]++`
* `PublicBridge::_releaseTokens` - cache `token, vault`
* `PrivateChainBridge::_releaseTokens` - cache `vault`
* `PublicBridge, PrivateChainBridge::_processPendingReleases` - cache `releases.length`
* `PublicBridge, PrivateChainBridge::_cleanPendingReleases` - cache `releases.length, pendingRecipients.length`
* `PublicBridge, PrivateChainBridge::forceProcessPendingRelease` - cache `release.recipient, release.amount`
* `PublicBridge, PrivateChainBridge::acceptOwnership` - cache `pendingOwner`
* `Token::confirmOwnership` - instead of modifier `only(pendingOwner)`, use an internal function that returns `pendingOwner`, then use that cached return value to set `owner` and emit event `TransferOwnership`

**BridgeX:**
Fixed in commit [57230de](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/57230de56c6d0b1f5c23e2c2042985dee9029abe).

**Cyfrin:** Verified.


### In `PublicBridge, PrivateChainBridge::payReleaseFee` don't interate over `releasers` array when `feePerReleaser` is zero

**Description:** In `PublicBridge, PrivateChainBridge::payReleaseFee` don't interate over `releasers` array when `feePerReleaser` is zero:
```solidity
        // Distribute fees directly to releasers (skip failures to prevent DoS)
        uint256 distributed = 0;

        if(feePerReleaser > 0) {
            for (uint i = 0; i < releasers.length; i++) {
                (bool success, ) = payable(releasers[i]).call{value: feePerReleaser}("");
                if (success) {
                    distributed += feePerReleaser;
                }
            }
        }
```

Since reading from `storage` is expensive, there's no need to iterate over the entire `releasers` array in storage when `feePerReleaser == 0`.

**BridgeX:**
Fixed in commit [cef83f7](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/cef83f75c36c6bbe39e6ccc26501d4885a725331).

**Cyfrin:** Verified.


### Use input value instead of defining additional variable when original input value doesn't need to be preserved

**Description:** Use input value instead of defining additional variable when original input value doesn't need to be preserved:
* `PublicBridge::lockTokens` - remove `bridgeAmount` and just use/modify `amount`

**BridgeX:**
Fixed in commit [521ff55](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/521ff55a00ef1d3aca64250371e903635fe7611e).

**Cyfrin:** Verified.


### Use `msg.sender` instead of `owner` inside `onlyOwner` functions

**Description:** Use `msg.sender` instead of `owner` inside `onlyOwner` functions:
* `PublicBridge, PrivateChainBridge::transferOwnership`

**BridgeX:**
Fixed in commit [cb04abb](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/cb04abb3aa1cf82f24d500c9a8e8f8774ad8ce54).

**Cyfrin:** Verified.


### Use input parameter when emitting events instead of reading `storage` when value already known

**Description:** Use input parameter when emitting events instead of reading storage when value already known:
* `Token::transferOwnership` - `emit TransferOwnership(newOwner, false);`
* `Token::setIssuer` - `emit NewIssuer(newIssuer);`

**BridgeX:**
Fixed in commit [a372b10](https://github.com/NerdUnited-NodeGovernance/audit-2026-03-bridgex/commit/a372b106f6fbc91d051df37f05ad0e46ff648751).

**Cyfrin:** Verified.

\clearpage