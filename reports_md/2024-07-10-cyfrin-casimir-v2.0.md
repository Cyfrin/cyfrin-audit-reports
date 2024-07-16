**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## Critical Risk


### Attacker can cause a DOS during unstaking by intentionally reverting the transaction when receiving ETH

**Description:** The function `fulfillUnstake()` is used internally to fulfill unstake requests for users. It performs a low-level call to the `userAddress` to transfer ETH and reverses the transaction if the transfer fails. Moreover, the contract processes all unstake requests in a First-In-First-Out (FIFO) queue, meaning it must process earlier requests before handling later ones.

An attacker could exploit this by intentionally triggering a revert on the `receive()` function. This action would cause `fulfillUnstake()` to revert and block the entire unstake queue.
```solidity
function fulfillUnstake(address userAddress, uint256 amount) private {
    (bool success,) = userAddress.call{value: amount}(""); // @audit DOS by reverting on `receive()`
    if (!success) {
        revert TransferFailed();
    }
    emit UnstakeFulfilled(userAddress, amount);
}
```

**Impact:** This can result in a Denial of Service for all unstake requests, thereby locking users’ funds.

**Recommended Mitigation:** Consider using the Pull-over-Push pattern.
Reference: https://fravoll.github.io/solidity-patterns/pull_over_push.html

**Casimir:**
Fixed in [cdbe7b1](https://github.com/casimirlabs/casimir-contracts/commit/cdbe7b1ed9e61a58d7971087e9b6e582eb36a55b)

**Cyfrin:** Verified.


### Function `claimEffectiveBalance()` may consistently revert, making it impossible to complete queue withdrawals

**Description:** The function attempts to remove the withdrawal at index `0`, while it uses the withdrawal at index `i` to call `completeQueuedWithdrawal()`. Since each withdrawal can only be completed once, the `delayedEffectiveBalanceQueue[]` list will eventually contain withdrawals that have already been completed. When the function tries to complete a withdrawal that has already been completed, it invariably reverts.

```solidity
for (uint256 i; i < delayedEffectiveBalanceQueue.length; i++) {
    IDelegationManager.Withdrawal memory withdrawal = delayedEffectiveBalanceQueue[i];
    if (uint32(block.number) - withdrawal.startBlock > withdrawalDelay) {
        delayedEffectiveBalanceQueue.remove(0); // @audit Remove withdrawal at index 0
        claimedEffectiveBalance += withdrawal.shares[0];
        eigenDelegationManager.completeQueuedWithdrawal(withdrawal, tokens, 0, true); // @audit Complete withdrawal of index i
    } else {
        break;
    }
}
```

**Impact:** The `claimEffectiveBalance()` function consistently reverts, making it impossible to complete queue withdrawals and therefore locking ETH.

**Proof of Concept:** Consider the following scenario:

1. Initially, the `delayedEffectiveBalanceQueue[]` list includes five withdrawals `[a, b, c, d, e]`.
2. The `claimEffectiveBalance()` function is called.
    - In the first loop iteration `i = 0`, withdrawal `a` is removed and completed. The list now becomes `[b, c, d, e]`.
    - In the second loop iteration `i = 1`, withdrawal `b` is removed, but withdrawal `c` is completed. The list now becomes `[c, d, e]`.
    - In the third loop iteration `i = 2`, the function checks withdrawal `e` and assumes the withdrawal delay has not yet been reached. The loop breaks at this point and the function stops.
3. The next time the `claimEffectiveBalance()` function is called.
    - In the first loop iteration `i = 0`, the function tries to remove and complete withdrawal `c`. However, since withdrawal `c` has already been completed, the call to `completeQueuedWithdrawal()` will revert.

**Recommended Mitigation:** Consider using a consistent index for checking, removing and completing withdrawals.

**Casimir:**
Fixed in [35fdf1e](https://github.com/casimirlabs/casimir-contracts/commit/35fdf1e42ad2a38f47028a8468efc0e78e6e7f67)

**Cyfrin:** Verified.


### Delayed rewards can be claimed without updating internal accounting

**Description:** The `claimRewards()` function is designed to claim delayed withdrawals from the EigenLayer Delayed Withdrawal Router and to update accounting variables such as `delayedRewards` and `reservedFeeBalance`.

```solidity
function claimRewards() external {
    onlyReporter();

    uint256 initialWithdrawalsBalance = address(eigenWithdrawals).balance;
    eigenWithdrawals.claimDelayedWithdrawals(
        eigenWithdrawals.getClaimableUserDelayedWithdrawals(address(this)).length
    );
    uint256 claimedAmount = initialWithdrawalsBalance - address(eigenWithdrawals).balance;
    delayedRewards -= claimedAmount;

    uint256 rewardsAfterFee = subtractRewardFee(claimedAmount);
    reservedFeeBalance += claimedAmount - rewardsAfterFee;
    distributeStake(rewardsAfterFee);

    emit RewardsClaimed(rewardsAfterFee);
}
```

However, this function can be bypassed by directly executing the claim on the EigenLayer side via the `DelayedWithdrawalRouter::claimDelayedWithdrawals()` function. This function allows the caller to claim withdrawals for a specified recipient, with the recipient's address provided as an input. If the `CasimirManager` contract address is used as the `recipient`, the claim is made on its behalf.

**Impact:** This process does not update the accounting variables, leading to inaccurate accounting within the contract. Even though the rewards have been claimed, they are still accounted for in the `delayedRewards`, resulting in an incorrect total stake value.

**Proof of Concept:** EigenLayer contract that handles delayed withdrawal claims can be found [here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/0139d6213927c0a7812578899ddd3dda58051928/src/contracts/pods/DelayedWithdrawalRouter.sol#L80)

**Recommended Mitigation:** Consider altering the way the contract manages rewards claims. This could be achieved by moving the accounting for claimed reward amounts to the `receive()` function, and by only filtering funds received from the `eigenWithdrawals` contract.

**Casimir:**
Fixed in [4adef64](https://github.com/casimirlabs/casimir-contracts/commit/4adef6482238c3d0926f72ffdff04e7a49886045)

**Cyfrin:** Verified.


### Anyone can submit proofs via  EigenPod `verifyAndProcessWithdrawals` to break the accounting of `withdrawRewards`

**Description:** `CasimirManager::withdrawRewards` is an `onlyReporter` operation that performs the key tasks below:

1. Submits proofs related to the partial withdrawal of a validator at a given index.
2. Updates the `delayedRewards` based on the last element in the array of `userDelayedWithdrawalByIndex`.

Note that anyone, not just the pod owner, can submit proofs directly to `EigenPod::verifyAndProcessWithdrawals`. In such a case, the `delayedRewards` will not be updated, and the subsequent accounting during report finalization will be broken.

Any attempt to withdraw rewards by calling `CasimirManager::withdrawRewards` will revert because the withdrawal has already been processed. Consequently, `delayedRewards` will never be updated.

This same issue is applicable when submitting proofs for processing a full withdrawal. Critical accounting parameters that are updated in `CasimirManager::withdrawValidator` are effectively bypassed when proofs are directly submitted to EigenLayer.

**Impact:** If `delayedRewards` is not updated, the `rewardStakeRatioSum` and `latestActiveBalanceAfterFee` accounting will be broken.

**Recommended Mitigation:** EigenLayer does not restrict access to process withdrawals only to the pod owner. To that extent, access control to `CasimirManager::withdrawRewards` can always be bypassed. Assuming that all withdrawals will happen only through a reporter, consider adding logic that directly tracks the `eigenWithdrawals.delayedWithdrawals` and `eigenWithdrawals.delayedWithdrawalsCompleted` on EigenLayer to calculate delayedRewards.

**Casimir:**
Fixed in [eb31b43](https://github.com/casimirlabs/casimir-contracts/commit/eb31b4349e69eb401615e0eca253e9ab8cc0999d)

**Cyfrin:** Verified.


### Front-run withdrawValidator by submitting proofs can permanently DOS validator unstaking on EigenLayer

**Description:** An attacker can observe the mempool and front-run the `CasimirManager::withdrawValidator` transaction by submitting the same proofs directly on Eigen Layer.

Since the proof is already verified, the `CasimirManager::withdrawValidator` transaction will revert when it tries to submit the same proofs. Submitting an empty proof to bypass proof verification also does not work because the `finalEffectiveBalance` will always be 0, preventing the queuing of withdrawals.

````solidity
function withdrawValidator(
    uint256 stakedValidatorIndex,
    WithdrawalProofs memory proofs,
    ISSVClusters.Cluster memory cluster
) external {
    onlyReporter();

   // ..code...

    uint256 initialDelayedRewardsLength = eigenWithdrawals.userWithdrawalsLength(address(this)); //@note this holds the rewards
    uint64 initialDelayedEffectiveBalanceGwei = eigenPod.withdrawableRestakedExecutionLayerGwei(); //@note this has the current ETH balance

>   eigenPod.verifyAndProcessWithdrawals(
        proofs.oracleTimestamp,
        proofs.stateRootProof,
        proofs.withdrawalProofs,
        proofs.validatorFieldsProofs,
        proofs.validatorFields,
        proofs.withdrawalFields
    ); //@audit reverts if proof is already verified

    {
        uint256 updatedDelayedRewardsLength = eigenWithdrawals.userWithdrawalsLength(address(this));
        if (updatedDelayedRewardsLength > initialDelayedRewardsLength) {
            IDelayedWithdrawalRouter.DelayedWithdrawal memory withdrawal =
                eigenWithdrawals.userDelayedWithdrawalByIndex(address(this), updatedDelayedRewardsLength - 1);
            if (withdrawal.blockCreated == block.number) {
                delayedRewards += withdrawal.amount;
                emit RewardsDelayed(withdrawal.amount);
            }
        }
    }

    uint64 updatedDelayedEffectiveBalanceGwei = eigenPod.withdrawableRestakedExecutionLayerGwei();
>   uint256 finalEffectiveBalance =
        (updatedDelayedEffectiveBalanceGwei - initialDelayedEffectiveBalanceGwei) * GWEI_TO_WEI; //@audit if no proofs submitted, this will be 0
    delayedEffectiveBalance += finalEffectiveBalance;
    reportWithdrawnEffectiveBalance += finalEffectiveBalance;
}

//... code
````

**Impact:** At a negligible cost, an attacker can prevent validator withdrawals on EigenLayer, creating an insolvency risk for Casimir.

**Recommended Mitigation:** Consider making the following changes to `CasimirManager::withdrawValidators`:

- Split the function into two separate functions, one for full-withdrawal verifications and another for queuing verified withdrawals.
- Listen to the following event emission in `EigenPod::_processFullWithdrawal` and filter the events emitted with the recipient as `CasimirManager`.
````solidity
event FullWithdrawalRedeemed(
    uint40 validatorIndex,
    uint64 withdrawalTimestamp,
    address indexed recipient,
    uint64 withdrawalAmountGwei
);
````
- Introduce a try-catch while verifying withdrawal for each applicable validator index. If a proof is already verified, update the `stakedValidatorIds` array and reduce `requestedExits` in the catch section.
- Once all withdrawals are verified, use the event emissions to create a `QueuedWithdrawalParams` array that will be sent to the second function that internally calls `eigenDelegationManager.queueWithdrawals(params)`.
- Update the `delayedEffectiveBalance` and `reportWithdrawnEffectiveBalance` at this stage.

Note: This assumes that the `reporter` is protocol-controlled.

**Casimir:**
Fixed in [eb31b43](https://github.com/casimirlabs/casimir-contracts/commit/eb31b4349e69eb401615e0eca253e9ab8cc0999d)

**Cyfrin:** Verified. Withdrawal proofs are decoupled from queuing withdrawals on EigenLayer. This successfully mitigates the Denial of Service risk reported in this issue. It is noted however that the effective balance is hardcoded as 32 ether.

It is recommended that the effective balance is passed as a parameter by monitoring the full withdrawal event on EigenLayer.


### Incorrect accounting of `tipBalance` can indefinitely stall report execution

**Description:** The `receive` fallback function in `CasimirManager` increases `tip` balance if the sender is not the `DelayedWithdrawalRouter`. The implicit assumption here is that all withdrawals, full or partial, are routed via the `DelayedWithdrawalRouter`. While this assumption is true incase of partial withdrawals (rewards), this is an incorrect assumption for full withdrawals where the sender is not the `DelayedWithdrawalRouter` but the `EigenPod` itself.

```solidity
    receive() external payable {
        if (msg.sender != address(eigenWithdrawals)) {
            tipBalance += msg.value; //@audit tip balance increases even incase of full withdrawals

            emit TipsReceived(msg.value);
        }
    }

```

Note that the owner can fully withdraw any tips via the `CasimirManager:claimTips`

```solidity
    function claimTips() external {
        onlyReporter();

        uint256 tipsAfterFee = subtractRewardFee(tipBalance);
        reservedFeeBalance += tipBalance - tipsAfterFee;
        tipBalance = 0;
        distributeStake(tipsAfterFee);
        emit TipsClaimed(tipsAfterFee);
    }

```

When tips are claimed by owner, the `withdrawnEffectiveBalance` which was incremented while claiming full withdrawals via `CasimirManager::claimEffectiveBalance` will be out-of-sync with the actual ETH balance. Effectively, the key invariant here that `CasimirManager.balance >= withdrawnEffectiveBalance` can get violated.

```solidity
    function claimEffectiveBalance() external {
        onlyReporter();

        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IDelegationManagerViews(address(eigenDelegationManager)).beaconChainETHStrategy();
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(0));

        uint256 withdrawalDelay = eigenDelegationManager.strategyWithdrawalDelayBlocks(strategies[0]);
        uint256 claimedEffectiveBalance;
        for (uint256 i; i < delayedEffectiveBalanceQueue.length; i++) {
            IDelegationManager.Withdrawal memory withdrawal = delayedEffectiveBalanceQueue[i];
            if (uint32(block.number) - withdrawal.startBlock > withdrawalDelay) {
                delayedEffectiveBalanceQueue.remove(0);
                claimedEffectiveBalance += withdrawal.shares[0];
                eigenDelegationManager.completeQueuedWithdrawal(withdrawal, tokens, 0, true);
            } else {
                break;
            }
        }

        delayedEffectiveBalance -= claimedEffectiveBalance;
        withdrawnEffectiveBalance += claimedEffectiveBalance; //@audit this accounting entry should be backed by ETH balance at all times
    }

```

**Impact:** Accounting error in `tipBalance` calculation can cause failure of `fulfilUnstakes` as the `withdrawnEffectiveBalance` is out-of-sync with actual ETH balance in CasimirManager. This can potentially stall report execution from time to time.

**Recommended Mitigation:** Consider incrementing `tipBalance` only if the sender is neither the `DelayedWithdrawalRouter` nor the `EigenPod`

**Casimir:**
Fixed in [4adef64](https://github.com/casimirlabs/casimir-contracts/commit/4adef6482238c3d0926f72ffdff04e7a49886045)

**Cyfrin:** Verified.

\clearpage
## High Risk


### Function `getTotalStake()` fails to account for pending validators, leading to inaccurate accounting

**Description:** The `getTotalStake()` function is the core accounting function to calculate the total stake of the `CasimirManager`. It's used to compute the change for `rewardStakeRatioSum` within the `finalizeReport()` function.

```solidity
function getTotalStake() public view returns (uint256 totalStake) {
  // @audit Validators in pending state is not accounted for
  totalStake = unassignedBalance + readyValidatorIds.length * VALIDATOR_CAPACITY + latestActiveBalanceAfterFee
      + delayedEffectiveBalance + withdrawnEffectiveBalance + subtractRewardFee(delayedRewards) - unstakeQueueAmount;
}
```

This function aggregates the stakes from various sources, including the `32 ETH` from each "ready validator" (`readyValidatorIds.length * VALIDATOR_CAPACITY`) and the ETH staked in "staked validators" (`latestActiveBalanceAfterFee`).

However, it fails to account for the ETH in pending validators.

A validator must go through three steps to become active/staked:

1. Every time users make a deposit, the contract checks if the unassigned balance has reached `32 ETH`. If it has, the next validator ID is added to `readyValidatorIds`.
2. The reporter calls `depositValidator()` to deposit `32 ETH` from the validator into the beacon deposit contract. In this step, the validator ID moves from `readyValidatorIds` to `pendingValidatorIds`.
3. The reporter calls `activateValidator()`, which moves the validator ID from `pendingValidatorIds` to `stakedValidatorIds` and updates `latestActiveBalanceAfterFee` to reflect the total stake in the beacon chain.

As shown, the `getTotalStake()` function accounts for validators in steps 1 and 3, but ignores the stake of validators in the pending state (step 2). In the current design, there is nothing that stops report finalization if pending validators > 0.

**Impact:** Function getTotalStake() will return the value of total stake less than it should be. The result is rewardStakeRatioSum calculation will be incorrect in a scenario where all pending validators are not activated before report finalization.

```solidity
uint256 totalStake = getTotalStake();

rewardStakeRatioSum += Math.mulDiv(rewardStakeRatioSum, gainAfterFee, totalStake);

rewardStakeRatioSum += Math.mulDiv(rewardStakeRatioSum, gain, totalStake);

rewardStakeRatioSum -= Math.mulDiv(rewardStakeRatioSum, loss, totalStake);
```

**Recommended Mitigation:** Consider adding `pendingValidatorIds.length * VALIDATOR_CAPACITY` to function `getTotalStake()`.

**Casimir:**
Fixed in [10fe228](https://github.com/casimirlabs/casimir-contracts/commit/10fe228406dc3f889db42e8850add94561a7325e)

**Cyfrin:** Verified.


### Hardcoded cluster size in `withdrawValidator` can cause losses to operators or protocol for strategies with larger cluster sizes

**Description:** `CasimirManager::withdrawValidator` calculates the owed balance on withdrawal, ie. shortfall from the initial 32 ether. It then tries to recover the owed amount from the operators tagged to the validator. However, while calculating recovery amount, a hardcoded cluster size of `4` is used.

```solidity
function withdrawValidator(
    uint256 stakedValidatorIndex,
    WithdrawalProofs memory proofs,
    ISSVClusters.Cluster memory cluster
) external {
    onlyReporter();

    // ... more code

    uint256 owedAmount = VALIDATOR_CAPACITY - finalEffectiveBalance;
    if (owedAmount > 0) {
        uint256 availableCollateral = registry.collateralUnit() * 4;
        owedAmount = owedAmount > availableCollateral ? availableCollateral : owedAmount;
>       uint256 recoverAmount = owedAmount / 4; //@audit hardcoded operator size
        for (uint256 i; i < validator.operatorIds.length; i++) {
            registry.removeOperatorValidator(validator.operatorIds[i], validatorId, recoverAmount);
        }
    }

    // .... more code

```

**Impact:** This has 2 side effects:
1. Operators lose higher % of collateral balance in strategies with large cluster sizes
2. On the other hand, since `owedAmount` is capped to `4 * collateralUnit`, it is also likely that protocol ends up recovering less than it should.

**Recommended Mitigation:** Consider using the `clusterSize` of the strategy instead of a hardcoded number.

**Casimir:**
Fixed in [7497e8c](https://github.com/casimirlabs/casimir-contracts/commit/7497e8cefae018a46606b4722c9bc20d03d0d23c).

**Cyfrin:** Verified.


### A malicious staker can force validator withdrawals by instantly staking and unstaking

**Description:** When a user unstakes via `CasimirManager::requestUnstake`, the number of required validator exits is calculated using the prevailing expected withdrawable balance as follows:

```solidity
function requestUnstake(uint256 amount) external nonReentrant {
    // code ....
    uint256 expectedWithdrawableBalance =
        getWithdrawableBalance() + requestedExits * VALIDATOR_CAPACITY + delayedEffectiveBalance;
    if (unstakeQueueAmount > expectedWithdrawableBalance) {
        uint256 requiredAmount = unstakeQueueAmount - expectedWithdrawableBalance;
>       uint256 requiredExits = requiredAmount / VALIDATOR_CAPACITY; //@audit required exits calculated here
        if (requiredAmount % VALIDATOR_CAPACITY > 0) {
            requiredExits++;
        }
        exitValidators(requiredExits);
    }

    emit UnstakeRequested(msg.sender, amount);
}
```

Consider the following simplified scenario:

`unAssignedBalance = 31 ETH withdrawnBalance = 0 delayedEffectiveBalance = 0 requestedExits = 0`

Also, for simplicity, assume the `deposit fees = 0%`

Alice, a malicious validator, stakes 1 ETH. This allocates the unassigned balance to a new validator via `distributeStakes`. At this point, the state is:

`unAssignedBalance = 0 ETH withdrawnBalance = 0 delayedEffectiveBalance = 0 requestedExits = 0`

Alice instantly places an unstake request for 1 ETH via `requestUnstake`. Since there is not enough balance to fulfill unstakes, an existing validator will be forced to withdraw from the Beacon Chain. After this, the state will be:

`unAssignedBalance = 0 ETH withdrawnBalance = 0 delayedEffectiveBalance = 0 requestedExits = 1`

Now, Alice can repeat the attack, this time by instantly depositing and withdrawing 64 ETH. At the end of this, the state will be:

`unAssignedBalance = 0 ETH withdrawnBalance = 0 delayedEffectiveBalance = 0 requestedExits = 2`

Each time, Alice only has to lose the deposit fee & gas fee but can grief the genuine stakers who lose their potential rewards & the operators who are forcefully kicked out of the validator.

**Impact:** Unnecessary validator withdrawal requests grief stakers, operators and protocol itself. Exiting validators causes a loss of yield to stakers and is very gas intensive for protocol.

**Recommended Mitigation:**
- Consider an unstake lock period. A user cannot request unstaking until a minimum time/blocks have elapsed after deposit.
- Consider removing ETH from `readyValidators` instead of exiting validators first -> while active validators are already accruing rewards, ready Validators have not yet started the process. And the overhead related to removing operators, de-registering from the SSV cluster is not needed if ETH is deallocated from ready validators.

**Casimir:**
Fixed in [4a5cd14](https://github.com/casimirlabs/casimir-contracts/commit/4a5cd145c247d9274c3f21f9e9c1b5557a230a01)

**Cyfrin:** Verified.


### Operator is not removed in Registry when validator has `owedAmount == 0`

**Description:** `CasimirManager::withdrawValidator()` function is designed to remove a validator after a full withdrawal. It checks whether the final effective balance of the removed validator is sufficient to cover the initial 32 ETH deposit. If for some reason such as slashing, the final effective balance is less than 32 ETH, the operators must recover the missing portion by calling `registry.removeOperatorValidator()`.


```solidity
uint256 owedAmount = VALIDATOR_CAPACITY - finalEffectiveBalance;
if (owedAmount > 0) {
    uint256 availableCollateral = registry.collateralUnit() * 4;
    owedAmount = owedAmount > availableCollateral ? availableCollateral : owedAmount;
    uint256 recoverAmount = owedAmount / 4;
    for (uint256 i; i < validator.operatorIds.length; i++) {
        // @audit if owedAmount == 0, this function is not called
        registry.removeOperatorValidator(validator.operatorIds[i], validatorId, recoverAmount);
    }
}
```

However, the `removeOperatorValidator()` function also has the responsibility to update other operators' states, such as `operator.validatorCount`. If this function is only called when `owedAmount > 0`, the states of these operators will not be updated if the validator fully returns 32 ETH.

**Impact:** The `operator.validatorCount` will not decrease in the `CasimirRegistry` when a validator is removed. As a result, the operator cannot withdraw the collateral for this validator, and the collateral will remain locked in the `CasimirRegistry` contract.

**Recommended Mitigation:** The function `registry.removeOperatorValidator()` should also be called  with `recoverAmount = 0` when `owedAmount == 0`. This will free up collateral for operators.

**Casimir:**
Fixed in [d7b35fc](https://github.com/casimirlabs/casimir-contracts/commit/d7b35fce9925bfa2133fd4e16ae11e483ab4daa4)

**Cyfrin:** Verified.


### Accounting for `rewardStakeRatioSum` is incorrect when a delayed balance or rewards are unclaimed

**Description:** The current accounting incorrectly assumes that the delayed effective balance and delayed rewards will be claimed before any new report begins. This is inaccurate as these delayed funds require a few days before they can be claimed. If a new report starts before these funds are claimed, the `reportSweptBalance` will account for them again. This double accounting impacts the `rewardStakeRatioSum` calculation, leading to inaccuracies.

**Impact:** The accounting for `rewardStakeRatioSum` is incorrect, which leads to an inaccurate user stake. Consequently, users may receive more ETH than anticipated upon unstaking.

**Proof of Concept:** Consider the following scenario:

1. Initially, we assume that one validator (32 ETH) is staked and the beacon chain reward is 0.105 ETH. The report gets processed.
```solidity
// Before start
latestActiveBalanceAfterFee = 32 ETH
latestActiveRewards = 0

// startReport()
reportSweptBalance = 0 (rewards is in BeaconChain)

// syncValidators()
reportActiveBalance = 32.105 ETH

// finalizeReport()
rewards = 0.105 ETH
change = rewards - latestActiveRewards = 0.105 ETH
gainAfterFee = 0.1 ETH
=> rewardStakeRatioSum is increased
=> latestActiveBalanceAfterFee = 32.1

sweptRewards = 0
=> latestActiveRewards = 0.105
```

2. The beacon chain sweeps 0.105 ETH rewards. This is followed by processing another report.
```solidity
// Before start
latestActiveBalanceAfterFee = 32.1 ETH
latestActiveRewards = 0.105

// startReport()
reportSweptBalance = 0.105 (rewards is in EigenPod)

// syncValidators()
reportActiveBalance = 32 ETH

// finalizeReport()
rewards = 0.105 ETH
change = rewards - latestActiveRewards = 0
=> No update to rewardStakeRatioSum and latestActiveBalanceAfterFee

sweptRewards = 0.105
=> latestActiveBalanceAfterFee = 32 ETH (subtracted sweptReward without fee)
=> latestActiveRewards = rewards - sweptRewards = 0
```

3. Suppose no actions take place, which means the rewards is still in EigenPod and not claimed yet. The next report gets processed.
```solidity
// Before start
latestActiveBalanceAfterFee = 32 ETH
latestActiveRewards = 0

// startReport()
reportSweptBalance = 0.105 (No action happens so rewards is still in EigenPod)

// syncValidators()
reportActiveBalance = 32 ETH

// finalizeReport()
rewards = 0.105 ETH
change = rewards - latestActiveRewards = 0.105
=> rewardStakeRatioSum is increased
=> latestActiveBalanceAfterFee = 32.1

sweptRewards = 0.105
=> latestActiveBalanceAfterFee = 32 ETH (subtracted sweptReward without fee)
=> latestActiveRewards = rewards - sweptRewards = 0
```

Since no actions occur between the last report and the current one, the values of `latestActiveBalanceAfterFee` and `latestActiveReward` remain the same. However, the `rewardStakeRatioSum` value increased from nothing. If this reporting process continues, the `rewardStakeRatioSum` could infinitely increase. Consequently, the core accounting of user stakes becomes incorrect, and users could receive more ETH than expected when unstaking.

**Recommended Mitigation:** Review the accounting logic to ensure that the delayed effective balance and delayed reward are only accounted for once in the reports.

**Casimir**
Fixed in [eb31b43](https://github.com/casimirlabs/casimir-contracts/commit/eb31b4349e69eb401615e0eca253e9ab8cc0999d)

**Cyfrin**
Verified.


### Incorrect accounting of `reportRecoveredEffectiveBalance` can prevent report from being finalized when a validator is slashed

**Description:** When a validator is slashed, a loss is incurred. In the `finalizeReport()` function, the `rewardStakeRatioSum` and `latestActiveBalanceAfterFee` variables are reduced to reflect this loss. The change could be positive if the rewards are larger than the slashed amount, but for simplicity, we'll focus on the negative case. This is where the loss is accounted for.

```solidity
} else if (change < 0) {
    uint256 loss = uint256(-change);
    rewardStakeRatioSum -= Math.mulDiv(rewardStakeRatioSum, loss, totalStake);
    latestActiveBalanceAfterFee -= loss;
}
```

However, any loss will be recovered by the node operators' collateral in the `CasimirRegistry`. From the users' or pool's perspective, there is no loss if it is covered, and users will receive compensation in full. The missing accounting here is that `rewardStakeRatioSum` and `latestActiveBalanceAfterFee` need to be increased using the `reportRecoveredEffectiveBalance` variable.

**Impact:** Users or pools suffer a loss that should be covered by `reportRecoveredEffectiveBalance`. Incorrect accounting results in `latestActiveBalanceAfterFee` being less than expected. This in certain scenarios could lead to arithmetic underflow & prevent report from being finalized. Without report finalization, new validators cannot be activated & a new report period cannot be started.

**Proof of Concept:** Consider following scenario - there is an underflow when last validator is withdrawn that prevents report from being finalized.

_Report Period 0_
2 validators added

```State:
latestActiveBalanceAfterFee = 64
latestActiveRewards = 0
````

_Report Period 1_
Rewards: 0.1 per validator on BC.
Withdrawal: 32
Unstake request: 15

```
=> start
Eigenpod balance = 32.1
reportSweptBalance = 32.1

=> syncValidator
reportActiveBalance = 32.1
reportWithdrawableValidators = 1

=>withdrawValidator
delayedRewards = 0.1
Slashed = 0
Report Withdrawn Effective Balance = 32
Delayed Effective Balance = 32
Report Recovered Balance = 0

=> finalize
totalStake = 49
expectedWithdrawalEffectiveBalance = 32
expectedEffectiveBalance = 32

Rewards = 0.2

rewardStakeRatioSum = 1004.08
latestActiveBalanceAfterFee (reward adj.) = 64.2
swept rewards = 0.1

latestActiveBalanceAfterFee (swept reward adj) = 64.1
latestActiveBalanceAfterFee (withdrawals adj) = 32.1
latestActiveRewards = 0.1

```

_Report Period 2_
unstake request: 20
last validator exited with slashing of 0.2

```
=> start
Eigenpod balance = 63.9 (32.1 previous + 31.8 slashed)
Delayed effective balance = 32
Delayed rewards = 0.1

reportSweptBalance = 96

=> sync validator
reportActiveBalance = 0
reportWithdrawableValidators = 1

=> withdraw validator
Delayed Effective Balance = 63.8 (32+ 31.8)
Report Recovered Balance = 0.2
Report Withdrawn Effective Balance = 31.8 + 0.2 = 32
Delayed Rewards = 0.1



=> finalizeReport
Total Stake: 29.2
expectedWithdrawalEffectiveBalance = 32
expectedEffectiveBalance = 0
rewards = 64

Change = 63.9
rewardStakeRatioSum: 3201.369
latestActiveBalanceAfterFee (reward adj) = 96
Swept rewards = 64.2

latestActiveBalanceAfterFee (swept reward adj) = 31.8
latestActiveBalanceAfterFee (adj withdrawals) = -0.2 => underflow

latestActiveRewards = -0.2
````
Arithmetic underflow here. Correct adjustment is by including `reportRecoveredBalance` in rewards. On correction, the following state is achieved:

=> finalizeReport
````
Total Stake: 29.2
expectedWithdrawalEffectiveBalance = 32
expectedEffectiveBalance = 0
rewards = 64.2 (add 0.2 recoveredEffectiveBalance)

Change = 64.1
rewardStakeRatioSum: 3208.247
latestActiveBalanceAfterFee (reward adj) = 96.2
Swept rewards = 64.2

latestActiveBalanceAfterFee (swept reward adj) = 32
latestActiveBalanceAfterFee (adj withdrawals) = 0

latestActiveRewards = 0
````

**Recommended Mitigation:** Consider adding `reportRecoveredEffectiveBalance` to `rewards` calculation so that recovered ETH is accounted for in `rewardStakeRatioSum` and `latestActiveBalanceAfterFee` calculations.

**Casimir:**
Fixed in [eb31b43](https://github.com/casimirlabs/casimir-contracts/commit/eb31b4349e69eb401615e0eca253e9ab8cc0999d).

**Cyfrin:** Verified.

\clearpage
## Medium Risk


### Infinite loop in the `exitValidators()` prevents users from calling `requestUnstake()`

**Description:** When users call function `requestUnstake()` to request to unstake their ETH, the `CasimirManager` contract will calculate if the current expected withdrawable balance is enough to cover all the queued unstaking requests. If it is not enough, the function `exitValidators()` will be call to exit some active validators to have enough ETH to fulfill all the unstaking requests.

In the function `exitValidators()`, it will do a while loop through the `stakedValidatorIds` list. If it found an active validator, it will call the `ssvClusters` to exit this validator and also change the status from `ACTIVE` to `EXITING`. However, if the validator status is not `ACTIVE`, the loop `index` will not be updated as well, resulting in the loop keep running infinitely but not being able to reach the next validator in the `stakedValidatorIds` list.
```solidity
function exitValidators(uint256 count) private {
    uint256 index = 0;
    while (count > 0) {
        uint32 validatorId = stakedValidatorIds[index];
        Validator storage validator = validators[validatorId];

        // @audit if status != ACTIVE, count and index won't be updated => Infinite loop
        if (validator.status == ValidatorStatus.ACTIVE) {
            count--;
            index++;
            requestedExits++;
            validator.status = ValidatorStatus.EXITING;
            ssvClusters.exitValidator(validator.publicKey, validator.operatorIds);
            emit ValidatorExited(validatorId);
        }
    }
}
```

**Impact:**
- If the status of first validator in the `stakedValidatorIds` list is not active, the `requestUnstake()` function will consume the caller's entire gas limit and revert.

- Could also lead to griefing attacks where a small staker can delay unstake requests of a whale staker by front-running an unstake request. While `exitValidators` will run successfully the first time, it will revert due to infinite loop when called by whale staker

**Recommended Mitigation:** Consider updating `count` and `index` variables to ensure the loop will break in all scenarios.

**Casimir:**
Fixed in [2945695](https://github.com/casimirlabs/casimir-contracts/commit/29456956e383e48277d604ca54d8fd43d6f31d10)

**Cyfrin:** Verified.


### Multiple unstake requests can cause denial of service because withdrawn balance is not adjusted after every unstake request is fulfilled

**Description:** A `while` loop runs over a specific number of unstake requests, and in every iteration, it checks if an unstake request is fulfillable. If it is, the unstaked amount is transferred back to the staker who requested unstaking. Honoring every unstaking request reduces the effective ETH balance in the manager, however, the `getNextUnstake` function continues to use the stale `withdrawnEffectiveBalance` while checking if the next unstake request is fulfillable.

In fact, `withdrawnEffectiveBalance` is adjusted only after the completion of the `while` loop.
```solidity
function fulfillUnstakes(uint256 count) external {
    //@note called when report status is in fulfilling unstakes
    onlyReporter();

    if (reportStatus != ReportStatus.FULFILLING_UNSTAKES) {
        revert ReportNotFulfilling();
    } //@note ok => report has to be in this state

    uint256 unstakedAmount;
    while (count > 0) {
        count--;

>       (Unstake memory unstake, bool fulfillable) = getNextUnstake(); //@audit uses the stale withdrawn balance
        if (!fulfillable) {
            break;
        }

        unstakeQueue.remove(0);
>       unstakedAmount += unstake.amount; //@audit unstakedAmount is increased here
>       fulfillUnstake(unstake.userAddress, unstake.amount); //@audit even after ETH is transferred, withdrawn balance is same
    }

    (, bool nextFulfillable) = getNextUnstake();
    if (!nextFulfillable) {
        reportStatus = ReportStatus.FINALIZING;
    }

>   if (unstakedAmount <= withdrawnEffectiveBalance) { //@audit withdrawn balance and unassigned balance adjustment happens here
        withdrawnEffectiveBalance -= unstakedAmount;
    } else {
        uint256 remainder = unstakedAmount - withdrawnEffectiveBalance;
        withdrawnEffectiveBalance = 0;
        unassignedBalance -= remainder;
    }

    unstakeQueueAmount -= unstakedAmount;
}
```
**Impact:** The `fulfillUnstakes()` function may fulfill more requests than the allowable withdrawable balance. This could cause the function to overflow and revert at the end.

**Proof of Concept:** **Recommended Mitigation:**
Consider updating `withdrawnEffectiveBalance` after an unstake request has been fulfilled by the `fulfillUnstakes()` function.

**Casimir:**
Fixed in [9f8920f](https://github.com/casimirlabs/casimir-contracts/commit/9f8920f483e5505726e3011132246bfcbea2e629)

**Cyfrin:** Verified.


### Spamming `requestUnstake()` to cause a denial of service in the unstake queue

**Description:**
- The function `requestUnstake()` allows users to request any amount, even `amount = 0`.
- The contract processes all unstake requests in a First-In-First-Out (FIFO) queue, handling earlier requests before later ones.
- The `remove()` function has a time complexity of O(n), which consumes gas.

This means an attacker could repeatedly call `requestUnstake()` to enlarge the unstake queue, causing the gas consumption of `fulfillUnstake()` to exceed the block gas limit.

**Impact:** Excessive gas usage when calling `fulfillUnstake()` could exceed the block gas limit, causing a DOS.

**Recommended Mitigation:** Consider setting a minimum unstake amount for the `requestUnstake()` function that is substantial enough to make spamming impractical.

**Casimir:**
Fixed in [4a5cd14](https://github.com/casimirlabs/casimir-contracts/commit/4a5cd145c247d9274c3f21f9e9c1b5557a230a01)

**Cyfrin:** Verified.


### Users could avoid loss by frontrunning to request unstake

**Description:** A loss can occur when a validator is slashed, which is reflected in the `finalizeReport()` function. If the `change` is less than 0, this indicates that a loss has occurred. Consequently, the accounting updates the `rewardStakeRatioSum` to decrease the stake value of all users in the `CasimirManager`.

```solidity
} else if (change < 0) {
    uint256 loss = uint256(-change);
    rewardStakeRatioSum -= Math.mulDiv(rewardStakeRatioSum, loss, totalStake);
    latestActiveBalanceAfterFee -= loss;
}
```

However, users can avoid this loss by front-running an unstake request. This is because they can create and fulfill an unstake request within the same `reportPeriod`. If users anticipate a potential loss in the next report (by watching the mempool), they can avoid it by requesting to unstake. The contract processes all unstake requests in a First-In-First-Out (FIFO) queue, meaning reporters must fulfill earlier requests before later ones.

```solidity
function getNextUnstake() public view returns (Unstake memory unstake, bool fulfillable) {
    // @audit Allow to create and fulfill unstake within the same `reportPeriod`
    if (unstakeQueue.length > 0) {
        unstake = unstakeQueue[0];
        fulfillable = unstake.period <= reportPeriod && unstake.amount <= getWithdrawableBalance();
    }
}
```

**Impact:** This can lead to unfairness. The front-runner can avoid losses while retaining all profits.

**Recommended Mitigation:** Consider implementing a waiting or delay period for unstake requests before they can be fulfilled. Do not allow the unstake request to be fulfilled in the same `reportPeriod` in which it was created. Additionally, considering adding a small user fee for unstaking.

**Casimir:**
Fixed in [28baa81](https://github.com/casimirlabs/casimir-contracts/commit/28baa8191a1b5a27d3ee495dee0d993177bf7e5f)

**Cyfrin:** Verified.


### Centralization risks with a lot of power vested in the `Reporter` role

**Description:** In the current design, the `Reporter`, a protocol-controlled address, is responsible for executing a number of mission-critical operations. Only `Reporter` operations include starting & finalizing a report, selecting & replacing operators, syncing/activating/withdrawing and depositing validators, verifying & claiming rewards from EigenLayer, etc. Also noteworthy is the fact that the timing and sequence of these operations are crucial for the proper functioning of the Casimir protocol.

**Impact:** With so many operations controlled by a single address, a significant part of which are initiated off-chain, the protocol is exposed to all the risks associated with centralization. Some of the known risks include:

- Compromised/lost private keys that control the `Reporter` address
- Rogue admin
- Network downtime
- Human/Automation errors associated with the execution of multiple operations

**Recommended Mitigation:** While we understand that the protocol in the launch phase wants to retain control over mission-critical parameters, we strongly recommend implementing the following even at the launch phase:

- Continuous monitoring of off-chain processes
- Reporter automation via a multi-sig

In the long term, the protocol should consider a clear path towards decentralization.

**Casimir:**
Acknowledged. We plan to implement the expected EigenLayer checkpoint upgrade that significantly reduces the intervention of the reporter while syncing validator balances.

**Cyfrin:** Acknowledged.

\clearpage
## Low Risk


### Operator can set his operatorID status to active by transferring 0 Wei

**Description:** When withdrawing collateral, logic checks if collateral balance is 0 & makes the operator Id inactive.

```solidity
 function withdrawCollateral(uint64 operatorId, uint256 amount) external {
        onlyOperatorOwner(operatorId);

        Operator storage operator = operators[operatorId];
        uint256 availableCollateral = operator.collateralBalance - operator.validatorCount * collateralUnit; //@note can cause underflow here if validator count > 0
        if (availableCollateral < amount) {
            revert InvalidAmount();
        }

        operator.collateralBalance -= amount;
        if (operator.collateralBalance == 0) {
            operator.active = false;
        }

        (bool success,) = msg.sender.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }

        emit CollateralWithdrawn(operatorId, amount);
    }

```

However while depositing, there is no check on the amount deposited. An operator can deposit 0 Wei and set operatorID to active. Deposit and withdrawal states are inconsistent.

```solidity
     function depositCollateral(uint64 operatorId) external payable {
        onlyOperatorOwner(operatorId);

        Operator storage operator = operators[operatorId];
        if (!operator.registered) {
            operatorIds.push(operatorId);
            operator.registered = true;
            emit OperatorRegistered(operatorId);
        }
        if (!operator.active) {
>            operator.active = true; //@audit -> can make operator active even with 0 wei
        }
        operator.collateralBalance += msg.value;

        emit CollateralDeposited(operatorId, msg.value);
    }**
```

**Impact:** Inconsistent logic when adding and removing validators.

**Recommended Mitigation:** Consider checking that collateral amount in the `depositCollateral` function

**Casimir:**
Fixed in [109cf2a](https://github.com/casimirlabs/casimir-contracts/commit/109cf2af2c6009e4dfa483317f2f186c97ed9da3)

**Cyfrin:** Verified.


### Reporter trying to reshare a pending validator will lead to denial of service

**Description:** A validator can reshare an operator if its either in `PENDING` or `ACTIVE` status. When resharing is executed for a validtor in `PENDING` state , the existing operators are removed from the SSV cluster -> however,  no such operators are registered in the first place. This is because SSV registration does not happen when `depositStake` is called.

```solidity
 function reshareValidator(
        uint32 validatorId,
        uint64[] memory operatorIds,
        uint64 newOperatorId,
        uint64 oldOperatorId,
        bytes memory shares,
        ISSVClusters.Cluster memory cluster,
        ISSVClusters.Cluster memory oldCluster,
        uint256 feeAmount,
        uint256 minTokenAmount,
        bool processed
    ) external {
        onlyReporter();

        Validator storage validator = validators[validatorId];
        if (validator.status != ValidatorStatus.ACTIVE && validator.status != ValidatorStatus.PENDING) {
            revert ValidatorNotActive();
        }

       // ... code

        uint256 ssvAmount = retrieveFees(feeAmount, minTokenAmount, address(ssvToken), processed);
        ssvToken.approve(address(ssvClusters), ssvAmount);
>        ssvClusters.removeValidator(validator.publicKey, validator.operatorIds, oldCluster); //@audit validtor key is not registered when the validator is in pending state
       ssvClusters.registerValidator(validator.publicKey, operatorIds, shares, ssvAmount, cluster); //@audit new operators registered

        validator.operatorIds = operatorIds;
        validator.reshares++;

        registry.removeOperatorValidator(oldOperatorId, validatorId, 0);
        registry.addOperatorValidator(newOperatorId, validatorId);

        emit ValidatorReshared(validatorId);
    }
```



`SSVCluster::removeValidator` reverts when it can't find a validator data to remove.

```solidity
    function removeValidator(
        bytes calldata publicKey,
        uint64[] memory operatorIds,
        Cluster memory cluster
    ) external override {
        StorageData storage s = SSVStorage.load();

        bytes32 hashedCluster = cluster.validateHashedCluster(msg.sender, operatorIds, s);
        bytes32 hashedOperatorIds = ValidatorLib.hashOperatorIds(operatorIds);

        bytes32 hashedValidator = keccak256(abi.encodePacked(publicKey, msg.sender));
        bytes32 validatorData = s.validatorPKs[hashedValidator];

        if (validatorData == bytes32(0)) {
>            revert ISSVNetworkCore.ValidatorDoesNotExist(); //@audit reverts when no key exists
        }

        if (!ValidatorLib.validateCorrectState(validatorData, hashedOperatorIds))
            revert ISSVNetworkCore.IncorrectValidatorStateWithData(publicKey);

        delete s.validatorPKs[hashedValidator];

        if (cluster.active) {
            StorageProtocol storage sp = SSVStorageProtocol.load();
            (uint64 clusterIndex, ) = OperatorLib.updateClusterOperators(operatorIds, false, false, 1, s, sp);

            cluster.updateClusterData(clusterIndex, sp.currentNetworkFeeIndex());

            sp.updateDAO(false, 1);
        }

        --cluster.validatorCount;

        s.clusters[hashedCluster] = cluster.hashClusterData();

        emit ValidatorRemoved(msg.sender, operatorIds, publicKey, cluster);
    }
```

**Impact:** An operator requesting a deactivation after initial deposit cannot be reshared.

**Recommended Mitigation:** Consider either of the 2 options:
- If resharing at PENDING stage needs to be supported, then register operators in `depositStake`
- If resharing at PENDING stage should not be supported, disallow resharing for validators in `Status.PENDING` in the `reshareValidator`

**Casimir:**
Fixed in [cd03c74](https://github.com/casimirlabs/casimir-contracts/commit/cd03c740c457264e578945bb2a8cc8bcf2c875f8)

**Cyfrin:** Verified.


### Missing implementation for  EigenPod `withdrawNonBeaconChainETHBalanceWei` in CasimirManager

**Description:** EigenLayer has a function `EigenPod::withdrawNonBeaconChainETHBalanceWei` that is intended to be called by the pod owner to sweep any ETH donated to EigenPod. Currently, there seems to be no way to withdraw this balance from EigenPod.

**Impact:** Donations to EigenPod are essentially stuck while the pod is active.

**Recommended Mitigation:** Consider adding a function to `CasimirManager` that sweeps the `nonBeaconChainETH` balance and sends it to `distributeStakes`, similar to `CasimirManager::claimTips`.

**Casimir:**
Fixed in [790817a](https://github.com/casimirlabs/casimir-contracts/commit/790817a9ba615dbcd7c85d449fe7aa19c02371b7)

**Cyfrin:** Verified.


### Function `withdrawRewards()` may lead to inaccuracy in `delayedRewards` if there's no withdrawal to process

**Description:** In the `CasimirManager`, the `withdrawRewards()` function can be used by the reporter to process swept validator rewards. The reporter must provide `WithdrawalProofs`, which the function uses to call `eigenPod.verifyAndProcessWithdrawals()`.
```solidity
function withdrawRewards(WithdrawalProofs memory proofs) external {
    onlyReporter();

    eigenPod.verifyAndProcessWithdrawals(
        proofs.oracleTimestamp,
        proofs.stateRootProof,
        proofs.withdrawalProofs,
        proofs.validatorFieldsProofs,
        proofs.validatorFields,
        proofs.withdrawalFields
    );

    // @audit Not check if the delayed withdrawal length has changed or not
    uint256 delayedAmount = eigenWithdrawals.userDelayedWithdrawalByIndex(
        address(this), eigenWithdrawals.userWithdrawalsLength(address(this)) - 1
    ).amount;
    delayedRewards += delayedAmount;

    emit RewardsDelayed(delayedAmount);
}
```

The `verifyAndProcessWithdrawals()` function processes a list of withdrawals and sends them as one withdrawal to the delayed withdrawal router. However, it only creates a new withdrawal in the delayed router if the sum of the amount to send is non-zero.

```solidity
if (withdrawalSummary.amountToSendGwei != 0) {
    _sendETH_AsDelayedWithdrawal(podOwner, withdrawalSummary.amountToSendGwei * GWEI_TO_WEI);
}
```

So, if the reporter calls `withdrawRewards()` with no withdrawals, i.e., empty `withdrawalFields` and `validatorFields`, the delayed withdrawal router will not create a new entry. However, as `withdrawRewards()` always takes `delayedAmount` as the latest entry from the delayed withdrawal router, it actually retrieves an old amount that has already been accounted for.

**Impact:** If the reporter mistakenly calls `withdrawRewards()` with no withdrawals, `delayedRewards` will account for the previous delayed amount again, leading to incorrect accounting.

**Recommended Mitigation:** Consider following the pattern in the `withdrawValidator()` function. It checks if the length of `eigenWithdrawals.userWithdrawalsLength()` changes before adding the amount to `delayedRewards`.
```solidity
uint256 initialDelayedRewardsLength = eigenWithdrawals.userWithdrawalsLength(address(this));
uint64 initialDelayedEffectiveBalanceGwei = eigenPod.withdrawableRestakedExecutionLayerGwei();

eigenPod.verifyAndProcessWithdrawals(
    ...
);

{
    uint256 updatedDelayedRewardsLength = eigenWithdrawals.userWithdrawalsLength(address(this));
    if (updatedDelayedRewardsLength > initialDelayedRewardsLength) {
        IDelayedWithdrawalRouter.DelayedWithdrawal memory withdrawal =
            eigenWithdrawals.userDelayedWithdrawalByIndex(address(this), updatedDelayedRewardsLength - 1);
        if (withdrawal.blockCreated == block.number) {
            delayedRewards += withdrawal.amount;

            emit RewardsDelayed(withdrawal.amount);
        }
    }
}
```

**Casimir:**
Fixed in [81cb7f1](https://github.com/casimirlabs/casimir-contracts/commit/81cb7f19aaa0dfad5101bcfa8a233fe0fade9365)

**Cyfrin:** Verified.


### Incorrect test setup leads to false test outcomes

**Description:** `IntegrationTest.t.sol` includes an integrated test that verifies the entire staking lifecycle. However, the current test setup, in several places, advances the blocks using foundry's `vm.roll` but neglects to adjust the timestamp using `vm.warp`.

This allows the test setup to claim rewards without any time delay.

_IntegrationTest.t.sol Line 151_
```solidity
>       vm.roll(block.number + eigenWithdrawals.withdrawalDelayBlocks() + 1); //@audit changing block without changing timestamp
        vm.prank(reporterAddress);
>       manager.claimRewards(); //@audit claiming at the same timestamp

        // Reporter runs after the heartbeat duration
        vm.warp(block.timestamp + 24 hours);
        timeMachine.setProofGenStartTime(0.5 hours);
        beaconChain.setNextTimestamp(timeMachine.proofGenStartTime());
        vm.startPrank(reporterAddress);
        manager.startReport();
        manager.syncValidators(abi.encode(beaconChain.getActiveBalanceSum(), 0));
        manager.finalizeReport();
        vm.stopPrank();
````

Moving blocks without updating the timestamp is an unrealistic simulation of the blockchain. As of EigenLayer M2, `WithdrawDelayBlocks` are 50400, which is approximately 7 days. By advancing 50400 blocks without changing the timestamp, tests overlook several accounting edge cases related to delayed rewards. This is especially true because each reporting period lasts for 24 hours - this means there are 7 reporting periods before a pending reward can actually be claimed.

**Impact:** An incorrect setup can provide false assurance to the protocol that all edge cases are covered.

**Recommended Mitigation:** Consider modifying the test setup as follows:

- Run reports without instantly claiming rewards. This accurately reflects events on the real blockchain.
- Consider adjusting time whenever blocks are advanced.

**Casimir:**
Fixed in [290d8e1](https://github.com/casimirlabs/casimir-contracts/commit/290d8e11846c5d20ed6a059e32864c8227fb582d)

**Cyfrin:** Verified.

\clearpage
## Informational


### Missing validations when initializing CasimirRegistry

**Description:** During Beacon Proxy deployment, CasimirRegistry can be deployed with 0 cluster size and 0 collateral.

**Recommended Mitigation:** Consider validating inputs for cluster size and collateral.

**Casimir:**
Mitigated in [37f3d34](https://github.com/casimirlabs/casimir-contracts/commit/37f3d34a9102478a85f6791774d86488bf5eb08e).

**Cyfrin:** Verified.


### ReentrancyGuardUpgradeable is not used in CasimirFactory and CasimirRegistry

**Description:** CasimirRegistry and CasimirFactory inherit ReentrancyGuardUpgradeable but nonRentrant modifier is unused in bopth contracts.

**Recommended Mitigation:** Considering removing `ReentrancyGuardUpgradeable` inheritance in `CasimirRegistry` and `CasimirFactory`

**Casimir**
Fixed in [e403b8b](https://github.com/casimirlabs/casimir-contracts/commit/e403b8b86edbb96e02fd3f5e02e7f207890e1257)

**Cyfrin**
Verified.


### The period check in `getNextUnstake()` always returns true

**Description:** The function `getNextUnstake()` is used to get the next unstake request in the queue, while also verifying if the request can be fulfilled. One of the condition to make the request fulfillable is `unstake.period <= reportPeriod`.

```solidity
function getNextUnstake() public view returns (Unstake memory unstake, bool fulfillable) {
    if (unstakeQueue.length > 0) {
        unstake = unstakeQueue[0];
        fulfillable = unstake.period <= reportPeriod && unstake.amount <= getWithdrawableBalance();
    }
}
```

However, given the current codebase, the `unstake.period` will always less or equal to `reportPeriod`. This is because the ``unstake.period` will be assigned with `reportPeriod` when the unstake request is created/queued but the value of `reportPeriod` is intended to be only increasing overtime.

```solidity
unstakeQueue.push(Unstake({userAddress: msg.sender, amount: amount, period: reportPeriod}));
...
reportPeriod++;
```

**Impact:** The check `unstake.period <= reportPeriod` has no effect since it always returns true.

**Recommended Mitigation:** Consider reviewing the logic in function `getNextUnstake()` and removing the period check if it is unnecessary.

**Casimir:**
Mitigated in [28baa81](https://github.com/casimirlabs/casimir-contracts/commit/28baa8191a1b5a27d3ee495dee0d993177bf7e5f).

**Cyfrin:** Verified.


### Unused function `validateWithdrawalCredentials()`

**Description:** The function `validateWithdrawalCredentials()` in CasimirManager is private and isn't called anywhere in the contract.

```solidity
function validateWithdrawalCredentials(address withdrawalAddress, bytes memory withdrawalCredentials) // @audit never used
    private
    pure
{
    bytes memory computedWithdrawalCredentials = abi.encodePacked(bytes1(uint8(1)), bytes11(0), withdrawalAddress);
    if (keccak256(computedWithdrawalCredentials) != keccak256(withdrawalCredentials)) {
        revert InvalidWithdrawalCredentials();
    }
}
```

**Recommended Mitigation:** Consider removing the unused function.

**Casimir:**
Fixed in [d6bd8da](https://github.com/casimirlabs/casimir-contracts/commit/d6bd8dae6e8e2f927f34abc3fdb2db15899ae71b).

**Cyfrin:** Verified.


### `getUserStake` function failure for non-staker accounts

**Description:** The function `getUserStake` in the smart contract throws an error when invoked for an address that does not have any stakes. Specifically, the function fails due to a division by zero error. This occurs because the divisor, `users[userAddress].rewardStakeRatioSum0`, can be zero if `userAddress` has never staked, leading to an unhandled exception in the `Math.mulDiv` operation.

````solidity
function getUserStake(address userAddress) public view returns (uint256 userStake) {
    userStake = Math.mulDiv(users[userAddress].stake0, rewardStakeRatioSum, users[userAddress].rewardStakeRatioSum0);
}
````

**Recommended Mitigation:** Consider modifying the `getUserStake` function to include a check for a zero divisor before performing the division. If `users[userAddress].rewardStakeRatioSum0` is zero, the function should return a stake of 0 to avoid the division by zero error.

**Casimir:**
Fixed in [27c09f5](https://github.com/casimirlabs/casimir-contracts/commit/27c09f548d6d73222a087f2ef237335353cdfefa)

**Cyfrin:** Verified.

\clearpage