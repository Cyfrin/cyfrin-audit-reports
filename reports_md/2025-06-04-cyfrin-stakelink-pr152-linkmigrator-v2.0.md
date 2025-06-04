**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)

[holydevoti0n](https://x.com/HolyDevoti0n)

---

# Findings
## Low Risk


### Minimum deposit value not enforced in `LINKMigrator`

**Description:** The `LINKMigrator` contract includes a `queueDepositMin` field intended to define the minimum deposit amount. However, this value is currently unused, allowing users to deposit amounts as small as 1 juel (1e-18 LINK).

**Impact:** Without enforcement, users can submit deposits smaller than the protocol likely intended, potentially increasing overhead or disrupting expected deposit behavior.

**Recommended Mitigation:** Consider either removing the unused `queueDepositMin` field or enforcing it in the `initiateMigration` function:

```diff
  function initiateMigration(uint256 _amount) external {
-     if (_amount == 0) revert InvalidAmount();
+     if (_amount < queueDepositMin) revert InvalidAmount();
```

**stake.link:**
Fixed in [`0abd4f8`](https://github.com/stakedotlink/contracts/commit/0abd4f86e3c5ed28f9ea444fdc9db5394ad5b5ed)

**Cyfrin:** Verified. `queueDepositMin` is removed. `minStakeAmount` is now fetched from the community pool and verified against `_amount`:
```solidity
(uint256 minStakeAmount, ) = communityPool.getStakerLimits();
if (_amount < minStakeAmount) revert InvalidAmount();
```


### Missing `poolStatus` check in `bypassQueue`

**Description:** The `bypassQueue` function in `PriorityPool.sol` doesn't check the pool's status before depositing tokens directly into the staking pool.
```solidity
function bypassQueue(
    address _account,
    uint256 _amount,
    bytes[] calldata _data
) external onlyQueueBypassController {
    token.safeTransferFrom(msg.sender, address(this), _amount);

    uint256 canDeposit = stakingPool.canDeposit();
    if (canDeposit < _amount) revert InsufficientDepositRoom();

    stakingPool.deposit(_account, _amount, _data);
}
```
The pool status check is part of the protocol's emergency response system. The [RebaseController](https://github.com/stakedotlink/contracts/blob/4b6b0811835bafa4c8379a39512bfe99bc6c6ebf/contracts/contracts/core/RebaseController.sol#L120-L140) can set the pool status to `CLOSED` during emergency situations, such as when the strategy is leading to a loss of funds. This reason can be seen on `RebaseController` when reopening the pool:
```solidity
@>     * @notice Reopens the priority pool and security pool after they were paused as a result
@>     * of a loss and updates strategy rewards in the staking pool
     * @param _data encoded data to pass to strategies
     */
    function reopenPool(bytes calldata _data) external onlyOwner {
        if (priorityPool.poolStatus() == IPriorityPool.PoolStatus.OPEN) revert PoolOpen();


        priorityPool.setPoolStatus(IPriorityPool.PoolStatus.OPEN);
        if (address(securityPool) != address(0) && securityPool.claimInProgress()) {
            securityPool.resolveClaim();
        }
        _updateRewards(_data);
    }
```
This missing check in the `bypassQueue` function allows user funds to be deposited when the pool is `CLOSED`, potentially causing deposited tokens to be lost during protocol emergency shutdowns.

**Impact:** LINK tokens can be deposited via `LINKMigrator` even when the `PriorityPool` is `CLOSED` or `DRAINING`, effectively bypassing the emergency pause mechanism intended for use during security incidents. This could potentially result in users losing funds. However, this risk is considered low in the context of the Chainlink community pool, as there is no inherent mechanism for loss, slashing only occurs in the operator pool. As such, the scenario would only pose a threat if one of the involved contracts were compromised and a user still migrates to it.

**Recommended Mitigation:** Add a pool status check in the bypassQueue function:
```diff
function bypassQueue(
    address _account,
    uint256 _amount,
    bytes[] calldata _data
) external onlyQueueBypassController {
+    if (poolStatus != PoolStatus.OPEN) revert DepositsDisabled();
    ...
}
```

**stake.link:**
Fixed in [`c595886`](https://github.com/stakedotlink/contracts/commit/c595886faef706a74bc11815b103af6670d7ed4d)

**Cyfrin:** Verified. The recommended mitigation was implemented.


### Existing Chainlink stakers can skip queue by bypassing migration requirements

**Description:** The purpose of `LINKMigrator` is that users can migrate their existing position from the Chainlink community pool to stake.link vaults, even when the community pool is at full utilization, since vacating a position frees up space. For users without an existing position, a queueing system (`PriorityQueue`) is used to wait for available slots in the community pool.

However, a user with an existing position can exploit this mechanism by faking a migration. By moving their position to another address (e.g., a small contract they control), they can bypass the queue and open a new position in stake.link if space is available.

Migration begins with a call to [`LINKMigrator::initiateMigration`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L79-L92):

```solidity
function initiateMigration(uint256 _amount) external {
    if (_amount == 0) revert InvalidAmount();

    uint256 principal = communityPool.getStakerPrincipal(msg.sender);

    if (principal < _amount) revert InsufficientAmountStaked();
    if (!_isUnbonded(msg.sender)) revert TokensNotUnbonded();

    migrations[msg.sender] = Migration(
        uint128(principal),
        uint128(_amount),
        uint64(block.timestamp)
    );
}
```

Here, the user's principal is recorded. Later, the migration is completed via `transferAndCall`, which triggers [`LINKMigrator::onTokenTransfer`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L100-L117):

```solidity
uint256 amountWithdrawn = migration.principalAmount -
    communityPool.getStakerPrincipal(_sender);
if (amountWithdrawn < _value) revert InsufficientTokensWithdrawn();
```

This compares the recorded and current principal to verify the withdrawal. However, it does not validate that the total staked amount in the community pool has decreased. As a result, a user can withdraw their position, transfer it to a contract they control, and still pass the check, allowing them to deposit directly into stake.link and bypass the queue.

**Impact:** A user with an existing position in the Chainlink community vault can circumvent the queue system and gain direct access to stake.link staking. This requires being in the claim period, having sufficient LINK to stake again, and available space in the Chainlink community vault. It also resets the bonding period, meaning the user would need to wait another 28 days (the Chainlink bonding period at the time of writing) before interacting with the new position. Nevertheless, this behavior could lead to unfair queue-skipping and undermine the fairness of the protocol.

**Proof of Concept:** Add the following test to `link-migrator.ts` which demonstrates the queue bypass by simulating a migration and re-staking via a third contract::
```javascript
it('can bypass queue using existing position', async () => {
  const { migrator, communityPool, accounts, token, stakingPool } = await loadFixture(
    deployFixture
  )

  // increase max pool size so we have space for the extra position
  await communityPool.setMaxPoolSize(toEther(3000))

  // deploy our small contract to hold the existing position
  const chainlinkPosition = (await deploy('ChainlinkPosition', [
    communityPool.target,
    token.target,
  ])) as ChainlinkPosition

  // get to claim period
  await communityPool.unbond()
  await time.increase(unbondingPeriod)

  // start batch transaction
  await ethers.provider.send('evm_setAutomine', [false])

  // 1. call initiate migration
  await migrator.initiateMigration(toEther(1000))

  // 2. unstake
  await communityPool.unstake(toEther(1000))

  // 3. transfer the existing position to a contract you control
  await token.transfer(chainlinkPosition.target, toEther(1000))
  await chainlinkPosition.deposit()

  // 4. transferAndCall a new position bypassing the queue
  await token.transferAndCall(
    migrator.target,
    toEther(1000),
    ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]'], [[encodeVaults([])]])
  )
  await ethers.provider.send('evm_mine')
  await ethers.provider.send('evm_setAutomine', [true])

  // user has both a 1000 LINK position in stake.link StakingPool and chainlink community pool
  assert.equal(fromEther(await communityPool.getStakerPrincipal(accounts[0])), 0)
  assert.equal(fromEther(await stakingPool.balanceOf(accounts[0])), 1000)
  assert.equal(fromEther(await communityPool.getStakerPrincipal(chainlinkPosition.target)), 1000)

  // community pool is full again
  assert.equal(fromEther(await communityPool.getTotalPrincipal()), 3000)
  assert.equal(fromEther(await stakingPool.totalStaked()), 2000)
  assert.deepEqual(await migrator.migrations(accounts[0]), [0n, 0n, 0n])
})
```
Along with `ChainlinkPosition.sol`:
```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;

import "./interfaces/IStaking.sol";
import "../core/interfaces/IERC677.sol";

contract ChainlinkPosition {

    IStaking communityPool;
    IERC677 link;

    constructor(address _communityPool, address _link) {
        communityPool = IStaking(_communityPool);
        link = IERC677(_link);
    }

    function deposit() public {
        link.transferAndCall(address(communityPool), link.balanceOf(address(this)), "");
    }
}
```

**Recommended Mitigation:** In `LINKMigrator::onTokenTransfer`, consider validating that the total principal in the community pool has decreased by at least `_value`, to ensure the migration reflects an actual exit from the community pool.

**stake.link:**
Fixed in [`de672a7`](https://github.com/stakedotlink/contracts/commit/de672a77813d507896502c20241618230af1bd85)

**Cyfrin:** Verified. Recommended mitigation was implemented. Community pool total principal is now recorded in `initiateMigration` then compared to the new pool total principal in `onTokenTransfer`.

\clearpage
## Informational


### Unused error

**Description:** In [`LINKMigrator.sol#L47`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L47) the error `InvalidPPState` is unused, consider using or removing it.

**stake.link:**
Fixed in [`6827d9d`](https://github.com/stakedotlink/contracts/commit/6827d9df664de5132d81570f03b55ed4a482dff5)

**Cyfrin:** Verified.


### Lack of events emitted on important state changes

**Description:** [`LINKMigrator::setQueueDepositMin`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L119-L125) and [`PriorityPool::setQueueBypassController`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/core/priorityPool/PriorityPool.sol#L678-L685) change internal state without emitting events. Events are important for off-chain tracking and transparency. Consider emitting events from these functions.

**stake.link:**
Acknowledged.


### Consider renaming `LINKMigrator::_isUnbonded` for clarity

**Description:** In the `LINKMigrator` contract, the function [`_isUnbonded`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L132-L137) checks whether a user is currently within the claim period for Chainlink staking:

```solidity
function _isUnbonded(address _account) private view returns (bool) {
    uint256 unbondingPeriodEndsAt = communityPool.getUnbondingEndsAt(_account);
    if (unbondingPeriodEndsAt == 0 || block.timestamp < unbondingPeriodEndsAt) return false;

    return block.timestamp <= communityPool.getClaimPeriodEndsAt(_account);
}
```

While functionally correct, the name `_isUnbonded` may not clearly convey its purpose, as it specifically checks whether a user is in the claim period. For improved clarity and consistency with Chainlink’s naming convention—such as in [`StakingPoolBase::_inClaimPeriod`](https://etherscan.io/address/0xbc10f2e862ed4502144c7d632a3459f49dfcdb5e#code)—renaming it could make the intent more immediately clear:

```solidity
function _inClaimPeriod(Staker storage staker) private view returns (bool) {
  if (staker.unbondingPeriodEndsAt == 0 || block.timestamp < staker.unbondingPeriodEndsAt) {
    return false;
  }

  return block.timestamp <= staker.claimPeriodEndsAt;
}
```

**Recommended Mitigation:** Consider renaming `_isUnbonded` to `_inClaimPeriod` to better reflect its logic and improve code readability.

**stake.link:**
Fixed in [`9d710bf`](https://github.com/stakedotlink/contracts/commit/9d710bf35304e9b45ed1ad8468714915817904a1)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Unchanged state variables can be immutable

**Description:** None of:
* [`LINKMigrator.linkToken`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L22)
* [`LINKMigrator.communityPool`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L24)
* [`LINKMigrator.priorityPool`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L27)

Are changed outside of the constructor. Consider making them `immutable` to save on gas when accessing them.

**stake.link:**
Fixed in [`6f9d9b7`](https://github.com/stakedotlink/contracts/commit/6f9d9b77201184d2dfc8f4c06f3430f2d360db24)

**Cyfrin:** Verified.


### Inefficient storage layout in `LINKMigrator.Migration`

**Description:** Here's the [`LINKMigrator.Migration`](https://github.com/stakedotlink/contracts/blob/0bd5e1eecd866b2077d6887e922c4c5940a6b452/contracts/linkStaking/LINKMigrator.sol#L31-L38) struct:

```solidity
struct Migration {
    // amount of principal staked in Chainlink community pool
    uint128 principalAmount;
    // amount to migrate
    uint128 amount;
    // timestamp when migration was initiated
    uint64 timestamp;
}
```

This struct occupies more than 256 bits and therefore spans two storage slots. However, any LINK amount can be safely stored in a `uint96`, since the total LINK supply is 1 billion (10^9 \* 10^18), which is well below the maximum value representable by a `uint96` (\~7.9 \* 10^28). By changing both amount fields to `uint96`, the struct would comprise `uint96 + uint96 + uint64`, which fits neatly within a single 256-bit storage slot.

**Cyfrin:** Not applicable after fix in [`de672a7`](https://github.com/stakedotlink/contracts/commit/de672a77813d507896502c20241618230af1bd85)

\clearpage