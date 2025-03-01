**Lead Auditors**

[Immeas](https://twitter.com/0ximmeas)


**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## Informational


### Lack of events emitted on state changes

**Description:** The following functions should ideally emit an event to enhance transparency and traceability:


[`Vault::setDelegateRegistry`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/base/Vault.sol#L180-L186) and [`VaultControllerStrategy::setDelegateRegistry`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/base/VaultControllerStrategy.sol#L708-L714):

```diff
  function setDelegateRegistry(address _delegateRegistry) external onlyOwner {
      delegateRegistry = _delegateRegistry;
+     emit SetDelegateRegistry(_delegateRegistry);
  }
```

[`FundFlowController::setNonLINKRewardReceiver`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/FundFlowController.sol#L325-L331):

```diff
  function setNonLINKRewardReceiver(address _nonLINKRewardReceiver) external onlyOwner {
      nonLINKRewardReceiver = _nonLINKRewardReceiver;
+     emit SetNonLINKRewardReceiver(_nonLINKRewardReceiver);
  }
```

Additionally, an event could be emitted when rewards are withdrawn in [`FundFlowController::withdrawTokenRewards`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/FundFlowController.sol#L307-L323):
```diff
  function withdrawTokenRewards(address[] calldata _vaults, address[] calldata _tokens) external {
      // ...
+     emit WithdrawTokenRewards(msg.sender, _vaults, _tokens);
  }
```

Consider adding events to these functions to provide a clear on-chain record of when and by whom these actions were executed. This improves transparency and makes it easier to track changes.

**Stake.Link:** Acknowledged.

**Cyfrin:** Acknowledged.

\clearpage
## Gas Optimization


### Unnecessary token transfer when withdrawing reward tokens

**Description:** When claiming non-LINK reward tokens, the tokens are transferred `Vault -> FundFlowController -> nonLINKRewardReceiver`:

[`Vault::withdrawTokenRewards`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/base/Vault.sol#L168-L178) transfers to `msg.sender` (`FundFlowController`):
```solidity
function withdrawTokenRewards(address[] calldata _tokens) external onlyFundFlowController {
    for (uint256 i = 0; i < _tokens.length; ++i) {
        IERC20Upgradeable rewardToken = IERC20Upgradeable(_tokens[i]);
        uint256 balance = rewardToken.balanceOf(address(this));
        if (balance != 0) rewardToken.safeTransfer(msg.sender, balance);
    }
}
```

and [`FundFlowController::withdrawTokenRewards`](https://github.com/stakedotlink/audit-2025-02-linkpool/blob/046c65a9c771315816bc59533183f52661af8e5e/contracts/linkStaking/FundFlowController.sol#L312-L323) transfers to the protocol wallet `nonLINKRewardReceiver`:
```solidity
function withdrawTokenRewards(address[] calldata _vaults, address[] calldata _tokens) external {
    for (uint256 i = 0; i < _vaults.length; ++i) {
        IVault(_vaults[i]).withdrawTokenRewards(_tokens);
    }

    for (uint256 i = 0; i < _tokens.length; ++i) {
        IERC20Upgradeable rewardToken = IERC20Upgradeable(_tokens[i]);
        if (address(rewardToken) == linkToken) revert InvalidToken();
        uint256 balance = rewardToken.balanceOf(address(this));
        if (balance != 0) rewardToken.safeTransfer(nonLINKRewardReceiver, balance);
    }
}
```

This could be optimized by letting the vault transfer to `nonLINKRewardReceiver` directly, thus removing one token transfer from the flow:

```solidity
function withdrawTokenRewards(address[] calldata _vaults, address[] calldata _tokens) external {
    // cache linkToken
    address _linkToken = linkToken;

    // check for LINK token
    for (uint256 i = 0; i < _tokens.length; ) {
        if (_tokens[i] == _linkToken) revert InvalidToken();
        unchecked { ++i; }
    }

    for (uint256 i = 0; i < _vaults.length; ++i) {
        // add `nonLINKRewardReceiver` in the call to vault.withdrawTokenRewards
        IVault(_vaults[i]).withdrawTokenRewards(_tokens, nonLINKRewardReceiver);
    }
}
```

```diff
- function withdrawTokenRewards(address[] calldata _tokens) external onlyFundFlowController {
+ function withdrawTokenRewards(address[] calldata _tokens, address _receiver) external onlyFundFlowController {
      for (uint256 i = 0; i < _tokens.length; ++i) {
          IERC20Upgradeable rewardToken = IERC20Upgradeable(_tokens[i]);
          uint256 balance = rewardToken.balanceOf(address(this));
-         if (balance != 0) rewardToken.safeTransfer(msg.sender, balance);
+         if (balance != 0) rewardToken.safeTransfer(_receiver, balance);
      }
  }
```

As `Vault::withdrawTokenRewards` is already protected by `onlyFundFlowController` this poses no extra risk.

**Stake.Link:** Acknowledged.

**Cyfrin:** Acknowledged.

\clearpage