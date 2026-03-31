**Lead Auditors**

[Stalin](https://x.com/0xStalin)

[Blckhv](https://x.com/blckhv)

[Slavcheww](https://x.com/Slavcheww)

**Assisting Auditors**



---

# Findings
## Low Risk


### Permissionless `withdrawAll` allows frontrunning a pending destination change

**Description:** `withdrawAll` is permissionless, meaning anyone can call it at any time to pull ETH from all registrars and forward the full contract balance to `destination`. If the owner needs to change `destination` via `setDestination` (e.g. because the Endowment Safe is compromised or its signers have lost access), a frontrunner can observe the pending `setDestination` transaction and call `withdrawAll` first, sending all accumulated ETH to the old `destination`.

Since the owner is the ENS DAO Timelock, the `setDestination` call goes through a governance delay. During that entire window, funds keep accumulating in the registrars and anyone can repeatedly call `withdrawAll` to drain them to the stale address.

[RegistrarManager.sol#L176-L184](https://github.com/blockful/dao-proposals/blob/6eaea8c/RegistrarManager/src/ens/proposals/ep-registrar-manager-endowment/contracts/RegistrarManager.sol#L176-L184)

```solidity
function withdrawAll() external {
    address registrar = _next[_HEAD];
    while (registrar != _HEAD) {
        bool success = _withdrawRegistrar(registrar);
        emit RegistrarWithdrawn(registrar, success);
        registrar = _next[registrar];
    }
    _forwardBalance();
}
```

**Impact:** If the Endowment Safe (`0x4F2083f5fBede34C2714aFfb3105539775f7FE64`) is compromised or its signers lose access, all ETH held across managed registrars can be forwarded there before the DAO can update `destination` through governance. The loss is the full balance at the time of the frontrun, and repeated calls can keep draining any newly accumulated ETH until the governance proposal finalizes.

**Recommended Mitigation:** Add an owner-only pause mechanism that stops `withdrawAll` from executing while a `destination` change is pending. Alternatively, bundle the `setDestination` call atomically with a `withdrawAll` in the same governance proposal so the old destination is never used after the decision to change it.

```solidity
bool public paused;

function setPaused(bool _paused) external onlyOwner {
    paused = _paused;
}

function withdrawAll() external {
    require(!paused, "paused");
    // ...existing logic
}
```

**Blockful:**
Acknowledged. The risk is conditional on the Endowment Safe being compromised, and the current destination being DAO-controlled mitigates the concern.


### ETH-forwarding call via `execOnRegistrar` can be griefed by front-running with `withdrawAll`

**Description:** `execOnRegistrar` allows the owner to make arbitrary calls to a managed registrar, optionally attaching ETH from the RegistrarManager's own balance via the `value` parameter:

```solidity
// RegistrarManager.sol line 199–213
function execOnRegistrar(
    address registrar,
    uint256 value,       // ← ETH drawn from address(this).balance
    bytes calldata data
)
    external onlyOwner returns (bool success, bytes memory result)
{
    if (!isRegistrar(registrar)) revert RegistrarNotFound(registrar);
    (success, result) = registrar.call{ value: value }(data);  // ← silent failure if balance < value
    emit RegistrarCall(registrar, value, data, success);
}
```

Because `withdrawAll` is **permissionless**, a griefer can front-run the owner's pending `execOnRegistrar` transaction with a `withdrawAll()` call, draining the RegistrarManager's ETH balance to `destination` before the governance transaction lands. When `execOnRegistrar` then executes, `address(this).balance < value` and the low-level call silently fails — returning `success = false` without reverting.

**Attack Scenario:**

1. The DAO passes a governance proposal calling `execOnRegistrar(registrar, 5 ether, data)` to fund or interact with a registrar with ETH
2. The RegistrarManager holds 5 ETH (accumulated from prior registrar withdrawals)
3. A griefer sees the pending governance transaction in the mempool and front-runs with `withdrawAll()`
4. `withdrawAll()` drains the 5 ETH from RegistrarManager to the Endowment Safe
5. `execOnRegistrar` executes — `address(this).balance == 0`, the call to the registrar fails silently with `success = false`
6. The governance action is wasted; a new proposal must be created and wait through the full governance delay


**Impact:** No ETH is stolen — funds are forwarded to the Endowment Safe (the intended long-term destination). However, the Timelock's intended governance action fails silently, and recovery requires creating and waiting through a full new governance proposal cycle. This attack can be repeated indefinitely at near-zero cost to the griefer (only gas).

**Recommended Mitigation:** There are a couple of alternatives to mitigate this issue:

1. When the owner intends to send ETH to a registrar via `execOnRegistrar`, the ETH should be included directly as `msg.value` in the governance transaction rather than relying on the contract's accumulated balance. Add a `payable` modifier to `execOnRegistrar` and use `msg.value` for the call.
2. Similar recommendation as in [*Permissionless `withdrawAll` allows frontrunning a pending destination change*](#permissionless-withdrawall-allows-frontrunning-a-pending-destination-change) . Add a pauser modifier that in case of facing a DoS, the `withdrawAll` function can be paused.
3. Add an access modifier to `withdrawAll` to allow only authorized entities, fully preventing any possibilities of frontrun.

**Blockful:**
Fixed in commit [e2f7584](https://github.com/blockful/dao-proposals/commit/e2f7584).

**Cyfrin:** Verified. `execOnRegistrar ` function no longer forwards ETH — calls registrar with zero value.

\clearpage