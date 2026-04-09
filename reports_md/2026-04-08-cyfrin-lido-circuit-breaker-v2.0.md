**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[SBSecurity](https://x.com/SBSecurity_) ([Blckhv](https://x.com/blckhv), [Slavcheww](https://x.com/Slavcheww))

**Assisting Auditors**



---

# Findings
## Informational


### Missing named mapping value parameters in `Registry.Storage`

**Description:** Three mappings in `Registry.Storage` declare named keys but omit names for their value types, reducing readability and ABI clarity:

```solidity
// Registry.sol lines 18-21
mapping(address pausable => address) pauser;
mapping(address pausable => uint256) oneBasedIndex;
mapping(address pauser => uint256) pausableCount;
```

**Recommended Mitigation:**
```diff
-mapping(address pausable => address) pauser;
-mapping(address pausable => uint256) oneBasedIndex;
-mapping(address pauser => uint256) pausableCount;
+mapping(address pausable => address pauser) pauser;
+mapping(address pausable => uint256 oneBasedIndex) oneBasedIndex;
+mapping(address pauser => uint256 pausableCount) pausableCount;
```

**Lido:** Fixed in commit [cabcfec](https://github.com/lidofinance/circuit-breaker/commit/cabcfec9f22380a8905435102dad94d829231abd).

**Cyfrin:** Verified.


### Single pauser per pausable combined with heartbeat expiry lockout leaves zero emergency coverage during liveness gaps

**Description:** Each pausable contract can only have one configured pauser in `CircuitBreaker`. If that pauser's heartbeat expires, they are completely locked out — both `CircuitBreaker::heartbeat` and `CircuitBreaker::pause` require `isPauserLive` to return true (via `_updateHeartbeat` with `_requireActive = true`):

```solidity
// CircuitBreaker.sol
246:    function heartbeat() external {
247:        require(registry.isRegistered(msg.sender), SenderNotPauser());
248:        _updateHeartbeat(msg.sender, true);  // requires live
249:    }

255:    function pause(address _pausable) external nonReentrant {
256:        require(msg.sender == registry.getPauser(_pausable), SenderNotPauser());
257:        _updateHeartbeat(msg.sender, true);  // requires live

276:    function _updateHeartbeat(address _pauser, bool _requireActive) internal {
277:        if (_requireActive) require(isPauserLive(_pauser), HeartbeatExpired());
```

The only way to restore an expired pauser is the [admin](https://etherscan.io/address/0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c) calling `CircuitBreaker::registerPauser` to re-register them — this calls `_updateHeartbeat(_newPauser, false)` which bypasses the liveness check.

This creates a gap: between heartbeat expiry and admin re-registration, the pausable contract has zero emergency pause coverage through `CircuitBreaker`. If an emergency occurs during this window, the slow governance path is the only option — exactly the scenario `CircuitBreaker` was built to prevent.

The design rationale is sound ("A committee that cannot prove its liveness should not be trusted to respond in an emergency"), but the single-pauser-per-pausable constraint means there is no fallback. Consider whether the `Registry` contract used by `CircuitBreaker` should support multiple pausers for each pausable contract.

**Lido:** Acknowledged as:
* Single pauser keeps accountability clear
* Expiry is the enforcement mechanism; a committee that can't send one heartbeat transaction once per year (for example) shouldn't hold pause authority
* Heartbeat expiry is fully trackable; off-chain monitoring can alert pausers months in advance before expiry
* the tradeoff of having no fallback is accepted

\clearpage
## Gas Optimization


### Emit before state change to eliminate temporary variable

**Description:** `CircuitBreaker::_setPauseDuration` and `CircuitBreaker::_setHeartbeatInterval` each declare a `previous*` local variable solely to capture the old storage value for the event. Emitting the event before the state change lets the event read the current storage value directly, eliminating the temporary:

```solidity
// CircuitBreaker.sol lines 289-292
uint256 previousPauseDuration = pauseDuration;
pauseDuration = _newPauseDuration;
emit PauseDurationUpdated(previousPauseDuration, _newPauseDuration);

// CircuitBreaker.sol lines 300-303
uint256 previousHeartbeatInterval = heartbeatInterval;
heartbeatInterval = _newHeartbeatInterval;
emit HeartbeatIntervalUpdated(previousHeartbeatInterval, _newHeartbeatInterval);
```

**Recommended Mitigation:**
```diff
 function _setPauseDuration(uint256 _newPauseDuration) internal {
     require(_newPauseDuration >= MIN_PAUSE_DURATION, PauseDurationBelowMin());
     require(_newPauseDuration <= MAX_PAUSE_DURATION, PauseDurationAboveMax());
-    uint256 previousPauseDuration = pauseDuration;
+    emit PauseDurationUpdated(pauseDuration, _newPauseDuration);
     pauseDuration = _newPauseDuration;
-    emit PauseDurationUpdated(previousPauseDuration, _newPauseDuration);
 }
```

Same pattern for `CircuitBreaker::_setHeartbeatInterval`.

**Lido:** Fixed in commit [11aea85](https://github.com/lidofinance/circuit-breaker/commit/11aea853b83408c4f7902ee2289e77034aa87638).

**Cyfrin:** Verified.



### Solidity optimizer is not enabled

**Description:** The Foundry configuration does not enable the Solidity optimizer:

```toml
foundry.toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.34"
```

No `optimizer` or `optimizer_runs` keys are present. Foundry disables the optimizer by default when these are absent. Even at the default 200 runs, the optimizer eliminates dead code, simplifies constant expressions, and reduces both deployment and runtime gas.

**Recommended Mitigation:** Add optimizer settings to `foundry.toml`:

```diff
 [profile.default]
 src = "src"
 out = "out"
 libs = ["lib"]
 solc = "0.8.34"
+optimizer = true
+optimizer_runs = 10000
```

`optimizer_runs` controls the trade-off between deployment cost and runtime call cost. Lower values (e.g., 1) produce smaller bytecode that is cheaper to deploy but slightly more expensive per call. Higher values (e.g., 10,000+) produce larger bytecode optimized for cheaper calls at the cost of more expensive deployment.

Factory-deployed contracts benefit from lower values because deployment cost is paid every time the factory creates a new instance — with hundreds of deployments the cumulative savings outweigh the marginal per-call increase.

Core protocol contracts deployed once but called millions of times benefit from higher values since deployment is a one-time expense. `CircuitBreaker` falls into the latter category — it is deployed once and called repeatedly — so a higher `optimizer_runs` value (e.g., 10,000) is appropriate. The default 200 is a reasonable starting point if unsure.

**Lido:** Fixed in commit [30b01f1](https://github.com/lidofinance/circuit-breaker/commit/30b01f13792e73b4dfc50e4aa093ab4dbf36802a).

**Cyfrin:** Verified.



### Redundant storage read of `registry.pauser[_pausable]` in `CircuitBreaker::pause`

**Description:** In `CircuitBreaker::pause`, the storage slot `registry.pauser[_pausable]` is read twice via separate library calls:

```solidity
CircuitBreaker.sol
255:    function pause(address _pausable) external nonReentrant {
256:        require(msg.sender == registry.getPauser(_pausable), SenderNotPauser());  // SLOAD 1
257:        _updateHeartbeat(msg.sender, true);
258:
259:        uint256 duration = pauseDuration;
260:        IPausable target = IPausable(_pausable);
261:
262:        registry.setPauser(_pausable, address(0));  // SLOAD 2 (re-reads pauser[_pausable] at Registry.sol:85)
```

`Registry::getPauser` reads `_self.pauser[_pausable]` (Registry.sol:44) for the authorization check. Then `Registry::setPauser` reads the same slot again (Registry.sol:85: `address previousPauser = _self.pauser[_pausable]`) to determine the previous pauser for count management. The value has not changed between reads, so the second SLOAD (100 gas warm) is redundant.

**Recommended Mitigation:** `Registry::setPauser` already reads `previousPauser` — return it via a named return value and use it in `CircuitBreaker::pause` to combine the authorization check with the unregistration:

```diff
 // Registry.sol
-function setPauser(Storage storage _self, address _pausable, address _newPauser) internal {
+function setPauser(Storage storage _self, address _pausable, address _newPauser) internal returns (address previousPauser) {
     require(_pausable != address(0), PausableZero());

-    address previousPauser = _self.pauser[_pausable];
+    previousPauser = _self.pauser[_pausable];

     // ... existing logic unchanged ...
 }
```

```diff
 // CircuitBreaker.sol
 function pause(address _pausable) external nonReentrant {
-    require(msg.sender == registry.getPauser(_pausable), SenderNotPauser());
+    require(msg.sender == registry.setPauser(_pausable, address(0)), SenderNotPauser());
     _updateHeartbeat(msg.sender, true);

     uint256 duration = pauseDuration;
     IPausable target = IPausable(_pausable);

-    registry.setPauser(_pausable, address(0));
     target.pauseFor(duration);
     require(target.isPaused(), PauseFailed());

     emit PauseTriggered(_pausable, msg.sender, duration);
 }
```

**Lido:** Acknowledged; 100 gas saved is negligible compared to the decreased readability for a function call that we hope will never be called. The proposed fix:
* hides state mutation inside an auth check
* returns the previous pauser from `setPauser`, which breaks the standard convention where a setter usually returns the new value (or a success boolean)

\clearpage