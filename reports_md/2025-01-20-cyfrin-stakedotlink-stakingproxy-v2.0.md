**Lead Auditors**

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## Critical Risk


### Instant withdrawals in priority pool can result in loss of funds for StakingProxy contract

**Description:** When instant withdrawals are enabled in the priority pool, `staker` can permanently lose funds when withdrawing through the `StakingProxy` contract. The issue occurs because the withdrawn amount is not properly updated in the priority pool's `_withdraw` function during instant withdrawals, causing the tokens to be stuck in the Priority Pool while users lose their LSTs.

`PriorityPool::_withdraw`

```solidity
function _withdraw(
    address _account,
    uint256 _amount,
    bool _shouldQueueWithdrawal,
    bool _shouldRevertOnZero,
    bytes[] memory _data
) internal returns (uint256) {
    if (poolStatus == PoolStatus.CLOSED) revert WithdrawalsDisabled();

    uint256 toWithdraw = _amount;
    uint256 withdrawn;
    uint256 queued;

    if (totalQueued != 0) {
        uint256 toWithdrawFromQueue = toWithdraw <= totalQueued ? toWithdraw : totalQueued;

        totalQueued -= toWithdrawFromQueue;
        depositsSinceLastUpdate += toWithdrawFromQueue;
        sharesSinceLastUpdate += stakingPool.getSharesByStake(toWithdrawFromQueue);
        toWithdraw -= toWithdrawFromQueue;
        withdrawn = toWithdrawFromQueue; // -----> @audit withdrawn is set here
    }

    if (
        toWithdraw != 0 &&
        allowInstantWithdrawals &&
        withdrawalPool.getTotalQueuedWithdrawals() == 0
    ) {
        uint256 toWithdrawFromPool = MathUpgradeable.min(stakingPool.canWithdraw(), toWithdraw);
        if (toWithdrawFromPool != 0) {
            stakingPool.withdraw(address(this), address(this), toWithdrawFromPool, _data);
            toWithdraw -= toWithdrawFromPool; // -----> @audit BUG withdrawn is not updated here
        }
    }
    // ... rest of the function
}
```

When processing instant withdrawals, the function fails to update the withdrawn variable after successfully withdrawing tokens from the staking pool. This leads to the following sequence:

1. Staker initiates withdrawal through `StakingProxy::withdraw`
2. `StakingProxy` burns LSTs
3. `PriorityPool` receives underlying tokens from Staking Pool
4. But `PriorityPool` doesn't transfer tokens because `withdrawn` wasn't updated
5. Tokens remain stuck in `PriorityPool` while `StakingProxy` loses access to its liquid staking tokens

**Impact:** `StakingProxy` permanently loses access to its liquid staking tokens when attempting instant withdrawals

**Proof of Concept:** Copy the following test into `staking-proxy.test.ts`

```typescript
 it('instant withdrawals from staking pool are not transferred to staker', async () => {
    const { stakingProxy, stakingPool, priorityPool, signers, token, strategy, accounts } = await loadFixture(deployFixture)

    // Enable instant withdrawals
    await priorityPool.setAllowInstantWithdrawals(true)

    // Deposit initial amount
    await token.approve(stakingProxy.target, toEther(1000))
    await stakingProxy.deposit(toEther(1000), ['0x'])

    // Setup for withdrawals
    await strategy.setMaxDeposits(toEther(2000))
    await strategy.setMinDeposits(0)

    // Track all relevant balances before withdrawal
    const preTokenBalance = await token.balanceOf(stakingProxy.target)
    const preLSTBalance = await stakingPool.balanceOf(stakingProxy.target)

    const prePPBalance = await token.balanceOf(priorityPool.target)

    const withdrawAmount = toEther(500)

    console.log('=== Before Withdrawal ===')
    console.log('Initial LST Balance - Proxy contract:', fromEther(preLSTBalance))
    console.log('Initial Token Balance - Poxy contract:', fromEther(preTokenBalance))


    // Perform withdrawal
    await stakingProxy.withdraw(
        withdrawAmount,
        0,
        0,
        [],
        [],
        [],
        ['0x']
    )

    // Check all balances after withdrawal
    const postTokenBalance = await token.balanceOf(stakingProxy.target)
    const postPPBalance = await token.balanceOf(priorityPool.target)
    const postLSTBalance = await stakingPool.balanceOf(stakingProxy.target)

    console.log('=== After Withdrawal ===')
    console.log('Priority Pool - token balance change:', fromEther(postPPBalance - prePPBalance))
    console.log('Staking Proxy - token balance change:', fromEther(postTokenBalance - preTokenBalance))
    console.log('Staking Proxy - LST balance change:', fromEther(postLSTBalance - preLSTBalance))

    const lstsRedeemed = fromEther(preLSTBalance - postLSTBalance)

    // Assertions

    // 1. Staking Proxy has redeeemed all his LSTs
    assert.equal(
      lstsRedeemed,
        500,
        "Staker redeemed 500 LSTs"
    )

    // 2. But staking proxy doesn't receive underlying tokens
    assert.equal(
      fromEther(postTokenBalance - preTokenBalance),
        0,
        "Staking Proxy didn't receive any tokens despite losing LSTs"
    )

    // 3. The tokens are stuck in Priority Pool
    assert.equal(
        fromEther(postPPBalance- prePPBalance),
        500,
        "Priority Pool is holding the withdrawn tokens"
    )
  })
```

**Recommended Mitigation:** Consider updating the `withdrawn` variable when processing instant withdrawals in `PriorityPool::_withdraw`

**Stake.Link:** Fixed in commit [5f3d282](https://github.com/stakedotlink/contracts/commit/5f3d2829f86bc74d6b9e805d7e61d9392d6b21b1)

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Unrestricted reSDL token deposits with privileged withdrawals can lead to accidental loss of reSDL tokens

**Description:** The `StakingProxy` contract implements ERC721 receiver functionality allowing it to receive reSDL tokens (ERC721) from any address. However, only the contract owner has the ability to withdraw these tokens.

This creates a risk where user owned reSDL tokens can get stuck if sent to the proxy accidentally or without understanding the withdrawal restrictions.

`StakingProxy.sol`

```solidity

// ----> @audit Anyone can transfer reSDL tokens to the proxy
function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
    return this.onERC721Received.selector;
}

// ----> @audit Only owner can withdraw reSDL tokens
function withdrawRESDLToken(uint256 _tokenId, address _receiver) external onlyOwner {
    if (sdlPool.ownerOf(_tokenId) != address(this)) revert InvalidTokenId();
    IERC721(address(sdlPool)).safeTransferFrom(address(this), _receiver, _tokenId);
}
```
The reSDL tokens represent time-locked SDL staking positions that earn rewards. While the proxy's ability to hold reSDL tokens is an intended functionality for reward earning purposes, the unrestricted acceptance of transfers combined with privileged withdrawals creates unnecessary risk.

**Impact:** Any user accidentally transferring their reSDL tokens to the proxy has no direct way of recovering them without manual intervention of protocol team.


**Recommended Mitigation:** Consider gating the `onERC721Received` function to only accept transfers from authorized addresses that can be configured in the StakingProxy contract.

**Stake.link:**
Acknowledged.

**Cyfrin:** Acknowledged.


### Storage collision risk in UUPS upgradeable `StakingProxy` due to missing storage gap

**Description:** `StakingProxy` contract inherits from `UUPSUpgradeable` and `OwnableUpgradeable` but does not implement storage gaps to protect against storage collisions during upgrades.

`StakingProxy` is intended to be used by third parties/DAOs. It is possible that this contract gets inherited by external contracts with their own storage variables. In such a scenario, adding new storage variables to `StakingProxy` during an upgrade can shift storage slots and cause serious storage collision risks.


`StakingProxy.sol`
```solidity
contract StakingProxy is UUPSUpgradeable, OwnableUpgradeable {
    // address of asset token
    IERC20Upgradeable public token;
    // address of liquid staking token
    IStakingPool public lst;
    // address of priority pool
    IPriorityPool public priorityPool;
    // address of withdrawal pool
    IWithdrawalPool public withdrawalPool;
    // address of SDL pool
    ISDLPool public sdlPool;
    // address authorized to deposit/withdraw asset tokens
    address public staker; // ---> @audit missing storage slots
}
```

**Impact:** Potential storage collision can corrupt data and cause contract to malfunction.

**Recommended Mitigation:** Consider adding a storage gap at the end of the contract to reserve slots for future inherited contract variable. A slot size of 50 is the [OpenZeppelin's recommended pattern](https://docs.openzeppelin.com/contracts/3.x/upgradeable#:~:text=Storage%20Gaps,with%20existing%20deployments.) for upgradeable contracts.

**Stake.link:**
Acknowledged.

**Cyfrin:** Acknowledged.

\clearpage