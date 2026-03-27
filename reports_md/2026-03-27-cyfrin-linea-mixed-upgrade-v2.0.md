**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Stalin](https://x.com/0xStalin)

**Assisting Auditors**



---

# Findings
## Critical Risk


### After the upgrade permissionless attacker can fully drain the L1 `TokenBridge` of `ERC20` tokens currently valued around $29M USD

**Description:** Using `forge inspect -R "@openzeppelin/=contracts/node_modules/@openzeppelin/" --hardhat TokenBridge storageLayout` on both the new and old `TokenBridge` contracts to carefully examine their exact storage layout showed that:
* slot 0 which used to be initialization slot becomes a gap
* slot 50 which used to be a gap becomes the new initialization slot

**Impact:** Immediately following the upgrade, the `TokenBridge` contract will believe it is not initialized allowing a permissionless attacker to initialize it. An attacker can weaponize this to completely drain the L1 `TokenBridge` contract of ERC20 tokens which at the time of this audit are [valued around $29M USD](https://etherscan.io/address/0x051F1D88f0aF5763fB888eC4378b4D8B29ea3319).

**Proof of Concept:** Immediately following the upgrade:
1. Attacker calls `TokenBridge::initialize` to set themselves as default admin
2. Attacker calls `TokenBridge::grantRole(SET_MESSAGE_SERVICE_ROLE, attacker)` to give themselves permission to set messaging service address
3. Attacker deploys a malicious messaging service contract such as:
```solidity
contract MaliciousMessageService {
    address public targetRemoteSender;

    constructor(address _remoteSender) {
        targetRemoteSender = _remoteSender;
    }

    // Spoofs the remoteSender check
    function sender() external view returns (address) {
        return targetRemoteSender;
    }

    // Calls TokenBridge as msg.sender to pass onlyMessagingService
    function drain(
        ITokenBridge bridge,
        address token,
        uint256 amount,
        address recipient,
        uint256 chainId
    ) external {
        bridge.completeBridging(token, amount, recipient, chainId, "");
    }
}
```
4. Attacker sets it by calling `TokenBridge::setMessageService(maliciousMessageService)`
5. Attacker calls the `drain` function on their malicious messaging service for every token locked in the L1 `TokenBridge`
6. `TokenBridge::_completeBridging` calls `IERC20Upgradeable(_nativeToken).safeTransfer(_recipient, _amount)` to send the attacker the locked tokens

This attack can be executed atomically and via a private mempool such as flashbots (to prevent front-running) making it unstoppable and completely draining the L1 `TokenBridge`.

**Recommended Mitigation:** `TokenBridgeBase` should inherit from `Initializable`. In an older version `TokenBridge` inherited from `Initializable` but this was later changed to inherit from OZ `ReentrancyGuardUpgradeable`, which itself inherits from `Initializable` so everything was still OK.

The bug appears to have been introduced on Nov 7th 2025 in commit [0c8bee7](https://github.com/Consensys/linea-monorepo/commit/0c8bee77311c694ba9c8643356f9703b9c88394b#diff-aff2d4ab7e0847d160464ca3171cd9a427be1e9503a4feffaaa6207fc83237efL31-R31) which swapped out OZ `ReentrancyGuardUpgradeable` for the new custom `TransientStorageReentrancyGuardUpgradeable`. This new contract doesn't inherit from `Initializable` which changed the `TokenBridge` inheritance hierarchy and hence storage slots.

**Linea:** Fixed in commit [4882f33](https://github.com/Consensys/linea-monorepo/pull/2007/commits/4882f33de707085f01e54c89d090c6fba76f33a4).

**Cyfrin:** Verified; the fix results in the initialization slot being preserved at slot 0. Slot 1 which used to be `_status` now becomes a gap and using `cast storage 0x051F1D88f0aF5763fB888eC4378b4D8B29ea3319 1` shows that on Mainnet L1 `TokenBridge`, slot 1 (currently `_status`) is already set to 1. Consider using a `reinitializer` to wipe slot 1 "clean" as it becomes a gap.

**Linea:** Added the wiping of slot 1 in commit [d99f590](https://github.com/Consensys/linea-monorepo/pull/2007/commits/d99f5906ec95102cdc67fb27039b26d15ef52a1e).

\clearpage
## Low Risk


### `SECURITY_COUNCIL_ROLE` unpausing a type leads to automatically marking as expired any other pause types, whether they were enacted by the `SECURITY_COUNCIL_ROLE` or not

**Description:** `PauseManager` enables the handling of the pausing/unpausing of different `PauseTypes`, targeting specific system functionalities (as well as a `GENERAL` pause). There are two main types of pausers:
1. Pausers with the`SECURITY_COUNCIL_ROLE`
2. Pausers without the `SECURITY_COUNCIL_ROLE`

The main difference between the two is that pausers with `SECURITY_COUNCIL_ROLE` can pause without cooldown or expiry restrictions, and when they unpause, the `pauseExpiryTimestamp` is reset to enable non-`SECURITY_COUNCIL_ROLE` pausing.

There is an edge case that allows for immediately unpause of any active pause after the `SECURITY_COUNCIL_ROLE` unpauses one type. Whether the `SECURITY_COUNCIL_ROLE` unpauses a pause enacted by themselves or by a non-`SECURITY_COUNCIL_ROLE`, the result is the same; any other active pause can be immediately unpaused.

**Impact:** When the `SECURITY_COUNCIL_ROLE` unpauses a type, all the other active pause types will be immediately marked as expired, regardless of whether they were enacted by the `SECURITY_COUNCIL_ROLE` or a `non-SECURITY_COUNCIL_ROLE` account.

**Proof of Concept:** Add the next PoC to `PauseManager.ts`:
```js
    it.only("Non-SECURITY_COUNCIL_ROLE pause L1_L2_PAUSE_TYPE -> SECURITY_COUNCIL_ROLE pause GENERAL_PAUSE_TYPE -> SECURITY_COUNCIL_ROLE unpause L1_L2_PAUSE_TYPE => GENERAL_PAUSE can be unpaused even though it had not been actually unpaused", async () => {
      await pauseByType(L1_L2_PAUSE_TYPE);
      await pauseByType(GENERAL_PAUSE_TYPE, securityCouncil);
      await unPauseByType(L1_L2_PAUSE_TYPE, securityCouncil);
      //@audit-info => GENERAL_PAUSE can be immediately unpaused even though it had not been actually unpaused
      await unPauseByExpiredType(GENERAL_PAUSE_TYPE, nonManager);
      expect(await pauseManager.isPaused(GENERAL_PAUSE_TYPE)).to.be.false;
      expect(await pauseManager.isPaused(L1_L2_PAUSE_TYPE)).to.be.false;
    });
```

**Recommended Mitigation:** Consider not resetting the `pauseExpiryTimestamp` below the `block.timestamp`, potentially add 1 hour cooldown period from the current `block.timestamp`, this will prevent immediately marking other pauses as expired.

Alternatively, consider adding a bool flag to `unpauseByType` flag that can allow the `SECURITY_COUNCIL_ROLE` to select dynamically whether they want to reset the `pauseExpiryTimestamp` or not.
- A more elaborate alternative would be to track the active pauses and reset the `pauseExpiryTimestamp` only when the last active pause is unpaused by the `SECURITY_COUNCIL_ROLE`.

**Linea:** Fixed in [PR 2335](https://github.com/Consensys/linea-monorepo/pull/2335/changes).

**Cyfrin:** Verified. Pause expirations are now tracked per pause type. Non-SecurityCouncil can't pause a pause type already paused by the SecurityCouncil, but the SecurityCouncil can pause a pause type already paused by a non-SecurityCouncil. Pauses enacted by the SecurityCouncil can only be unpaused by them. Unpausing a type only resets the expiry timestamp for that specific type.

\clearpage
## Informational


### `LineaRollup, LivenessRecovery::renounceRole` prevents liveness recovery operator from renouncing all roles

**Description:** The intention appears to be that the liveness recovery operator shouldn't be able to renounce the `OPERATOR_ROLE` they are granted, however `LivenessRecovery::renounceRole` called by `LineaRollup::renounceRole` prevents the liveness recovery operator from renouncing *all* roles:
```solidity
function renounceRole(bytes32 _role, address _account) public virtual override {
  // @audit only checks address, not role being renounced
  if (_account == livenessRecoveryOperator) {
    revert OnlyNonLivenessRecoveryOperator();
  }

  super.renounceRole(_role, _account);
}
```

**Impact:** If the liveness recovery operator has other legitimate roles they wish to renounce, they will be unable to do so.

**Recommended Mitigation:** `LivenessRecovery::renounceRole` should only revert if `OPERATOR_ROLE` is being renounced:
```diff
function renounceRole(bytes32 _role, address _account) public virtual override {
- if (_account == livenessRecoveryOperator) {
+ if (_account == livenessRecoveryOperator && _role == OPERATOR_ROLE) {
    revert OnlyNonLivenessRecoveryOperator();
  }
  super.renounceRole(_role, _account);
}
```

**Linea:** Acknowledged; the liveness operator role should never and would never be granted anything other than the operator role.


### `LivenessRecovery::setLivenessRecoveryOperator` will emit misleading event when role is not granted

**Description:** `LivenessRecovery::setLivenessRecoveryOperator` can be called multiple times as long as the first two preconditions are met.

However if `OPERATOR_ROLE` has already been granted to `livenessRecoveryOperator` then `AccessControlUpgradeable::_grantRole` [returns](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/AccessControlUpgradeable.sol#L205-L211) `false`.

But the boolean return value of `_grantRole` is not checked so the misleading event will still be emitted.

**Recommended Mitigation:** Only emit the event if `_grantRole` returned true:
```diff
-   _grantRole(OPERATOR_ROLE, livenessRecoveryOperatorAddress);
+   if(_grantRole(OPERATOR_ROLE, livenessRecoveryOperatorAddress))
    emit LivenessRecoveryOperatorRoleGranted(msg.sender, livenessRecoveryOperatorAddress);
```

**Linea:** Fixed in commit [66050d2](https://github.com/Consensys/linea-monorepo/pull/2007/commits/66050d2689a6b817b29f2de6b0a3fda2c69c42d9).

**Cyfrin:** Verified.


### Inconsistent handling of update/set transactions which don't actually change values

**Description:** `PauseManager::updatePauseTypeRole` reverts if the previous and new roles are identical, and only writes to storage and emits an event if the value was actually changed:
```solidity
function updatePauseTypeRole(
  PauseType _pauseType,
  bytes32 _newRole
) external onlyUsedPausedTypes(_pauseType) onlyRole(SECURITY_COUNCIL_ROLE) {
  bytes32 previousRole = _pauseTypeRoles[_pauseType];
  if (previousRole == _newRole) {
    revert RolesNotDifferent();
  }

  _pauseTypeRoles[_pauseType] = _newRole;
  emit PauseTypeRoleUpdated(_pauseType, _newRole, previousRole);
}
```

In contrast the following places don't revert on "no change" transactions, writing to storage and emitting events even if no change occurred:

* `LineaRollupBase::setVerifierAddress`
```solidity
function setVerifierAddress(address _newVerifierAddress, uint256 _proofType) external onlyRole(VERIFIER_SETTER_ROLE) {
    if (_newVerifierAddress == address(0)) {
      revert ZeroAddressNotAllowed();
    }
    // no revert if _newVerifierAddress == verifiers[_proofType]
    emit VerifierAddressChanged(_newVerifierAddress, _proofType, msg.sender, verifiers[_proofType]);
    verifiers[_proofType] = _newVerifierAddress;
}
```

* `LineaRollupBase::unsetVerifierAddress`
```solidity
function unsetVerifierAddress(uint256 _proofType) external onlyRole(VERIFIER_UNSETTER_ROLE) {
    // no revert if verifiers[_proofType] == address(0)
    emit VerifierAddressChanged(address(0), _proofType, msg.sender, verifiers[_proofType]);
    delete verifiers[_proofType];
}
```

* `L2MessageServiceV1::setMinimumFee`
```solidity
function setMinimumFee(uint256 _feeInWei) external onlyRole(MINIMUM_FEE_SETTER_ROLE) {
    // no revert if _feeInWei == previousMinimumFee
    uint256 previousMinimumFee = minimumFeeInWei;
    minimumFeeInWei = _feeInWei;
    emit MinimumFeeChanged(previousMinimumFee, _feeInWei, msg.sender);
}
```

* `TokenBridgeBase::setMessageService`
```solidity
function setMessageService(address _messageService) external ... {
    // no revert if _messageService == oldMessageService
    address oldMessageService = address(messageService);
    messageService = IMessageService(_messageService);
    emit MessageServiceUpdated(_messageService, oldMessageService, msg.sender);
}
```

* `RateLimiter::resetAmountUsedInPeriod`
```solidity
function resetAmountUsedInPeriod() external onlyRole(USED_RATE_LIMIT_RESETTER_ROLE) {
    // no revert if currentPeriodAmountInWei == 0
    currentPeriodAmountInWei = 0;
    emit AmountUsedInPeriodReset(_msgSender());
}
```

**Recommended Mitigation:** This can be acknowledged or behavior can be harmonized if there is no specific reasons for one function to differ in behavior from others.

**Linea:** Acknowledged.


### Not emitting event to log the version's change when reinitializing the `LineaRollup` contract

**Description:** When `LineaRollup` gets upgraded, [`LineaRollup::reinitializeV8`](https://github.com/Consensys/linea-monorepo/blob/main/contracts/src/rollup/LineaRollup.sol#L52-L67) is called to reinitialize permissions, roles, set the `shnarfProvider`, and bump up the `initialized` version, but `LineaRollupVersionChanged` event is not emitted to log the version's change.

**Recommended Mitigation:** Emit the event `LineaRollupVersionChanged` with the respective `previousVersion` and `newVersion` for the `LineaRollup`.

**Linea:** Fixed in [PR2020](https://github.com/Consensys/linea-monorepo/pull/2020).

**Cyfrin:** Verified.


### Missing `onlyInitializing` modifier on initialization functions for abstract contracts

**Description:** The `onlyInitializing` modifier is the established standard for protecting internal initialization functions in abstract contracts against unintended calls post-initialization. These new initialization functions introduced here do not include this modifier, which deviates from common security patterns:
* `L2MessageServiceBase::__L2MessageService_init`
* `LineaRollupBase::__LineaRollup_init`
* `TokenBridgeBase::__TokenBridge_init`

**Recommended Mitigation:** Consider adding the `onlyInitializing` modifier to those functions.

**Linea:** Fixed in commits [802cf72](https://github.com/Consensys/linea-monorepo/pull/2007/commits/802cf7239754526861e1e8777380619e8bc39cf2), [2d63895](https://github.com/Consensys/linea-monorepo/commit/2d638959adec0c13f66d72bb6c44b16f7df4bea1).

**Cyfrin:** Verified.


### Consider wiping slot 177 on Linea `L2MessageService` after upgrade

**Description:** After the upgrade, `L2MessageService` repurposes slot 177 for `__gap_ReentrancyGuardUpgradeable` but previously this was used for `_status`.

Using `cast storage 0x508Ca82Df566dCD1B0DE8296e70a96332cD644ec 177 --rpc-url https://rpc.linea.build` shows that slot 177 has a value of 1, so ideally this would be wiped to clean it when changing the usage of this slot into a gap.

**Linea:** Fixed in commit [c462da0](https://github.com/Consensys/linea-monorepo/pull/2007/commits/c462da0574f4f60667c3c357a2be61443fc0ab7a).

**Cyfrin:** Verified.

\clearpage