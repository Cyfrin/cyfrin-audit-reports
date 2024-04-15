**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**



---

# Findings
## High Risk


### `Goldilend.lock()` will always revert

**Severity:** High

**Description:** In `lock()`, it calls `_refreshiBGT()` before pulling `iBGT` from the user and will revert while calling `iBGTVault(ibgtVault).stake()`.

```solidity
  function lock(uint256 amount) external {
    uint256 mintAmount = _GiBGTMintAmount(amount);
    poolSize += amount;
    _refreshiBGT(amount); //@audit should call after depositing funds
    SafeTransferLib.safeTransferFrom(ibgt, msg.sender, address(this), amount);
    _mint(msg.sender, mintAmount);
    emit iBGTLock(msg.sender, amount);
  }
...
  function _refreshiBGT(uint256 ibgtAmount) internal {
    ERC20(ibgt).approve(ibgtVault, ibgtAmount);
    iBGTVault(ibgtVault).stake(ibgtAmount); //@audit will revert here
  }
```

**Impact:** Users can't lock `iBGT` as `lock()` always reverts.

**Recommended Mitigation:** `_refreshiBGT()` should be called after pulling funds from the user.

**Client:** Fixed in [PR #1](https://github.com/0xgeeb/goldilocks-core/pull/1)

**Cyfrin:** Verified.

### Wrong `PoolSize` increment in `Goldilend.repay()`

**Severity:** High

**Description:** When a user repays his loan using `repay()`, it increases `poolSize` with the repaid interest. During the increment, it uses the wrong amount.

```solidity
  function repay(uint256 repayAmount, uint256 _userLoanId) external {
    Loan memory userLoan = loans[msg.sender][_userLoanId];
    if(userLoan.borrowedAmount < repayAmount) revert ExcessiveRepay();
    if(block.timestamp > userLoan.endDate) revert LoanExpired();
    uint256 interestLoanRatio = FixedPointMathLib.divWad(userLoan.interest, userLoan.borrowedAmount);
    uint256 interest = FixedPointMathLib.mulWadUp(repayAmount, interestLoanRatio);
    outstandingDebt -= repayAmount - interest > outstandingDebt ? outstandingDebt : repayAmount - interest;
    loans[msg.sender][_userLoanId].borrowedAmount -= repayAmount;
    loans[msg.sender][_userLoanId].interest -= interest;
    poolSize += userLoan.interest * (1000 - (multisigShare + apdaoShare)) / 1000; //@audit should use interest instead of userLoan.interest
...
  }
```

It should use `interest` instead of `userLoan.interest` because the user repaid `interest` only.

**Impact:** `poolSize` would be tracked wrongly after calling `repay()` and several functions wouldn't work as expected.

**Recommended Mitigation:** `poolSize` should be updated using `interest`.

**Client:** Fixed in [PR #2](https://github.com/0xgeeb/goldilocks-core/pull/2)

**Cyfrin:** Verified.

### Users can extend an expired boost using invalidated NFTs.

**Severity:** High

**Description:** In `Goldilend.sol#L251`, a user can extend a boost with invalidated NFTs.
- The user has created a boost with a valid NFT.
- After that, the NFT was invalidated using `adjustBoosts()`.
- After the original boost is expired, the user can just call `boost()` with empty arrays, and the boost will be extended again with the original magnitude.

```solidity
  function _buildBoost(
    address[] calldata partnerNFTs,
    uint256[] calldata partnerNFTIds
  ) internal returns (Boost memory newUserBoost) {
    uint256 magnitude;
    Boost storage userBoost = boosts[msg.sender];
    if(userBoost.expiry == 0) {
...
    }
    else {
      address[] storage nfts = userBoost.partnerNFTs;
      uint256[] storage ids = userBoost.partnerNFTIds;
      magnitude = userBoost.boostMagnitude; //@audit use old magnitude without checking
      for (uint256 i = 0; i < partnerNFTs.length; i++) {
        magnitude += partnerNFTBoosts[partnerNFTs[i]];
        nfts.push(partnerNFTs[i]);
        ids.push(partnerNFTIds[i]);
      }
      newUserBoost = Boost({
        partnerNFTs: nfts,
        partnerNFTIds: ids,
        expiry: block.timestamp + boostLockDuration,
        boostMagnitude: magnitude
      });
    }
  }
```

**Impact:** Malicious users can use invalidated NFTs to extend their boosts forever.

**Recommended Mitigation:** Whenever users extend their boosts, their NFTs should be evaluated again.

**Client:** Fixed in [PR #3](https://github.com/0xgeeb/goldilocks-core/pull/3)

**Cyfrin:** Verified.

### Team members can't unstake the initial allocation forever.

**Severity:** High

**Description:** When users call `unstake()`, it calculates the vested amount using `_vestingCheck()`.

```solidity
  function _vestingCheck(address user, uint256 amount) internal view returns (uint256) {
    if(teamAllocations[user] > 0) return 0; //@audit return 0 for team members
    uint256 initialAllocation = seedAllocations[user];
    if(initialAllocation > 0) {
      if(block.timestamp < vestingStart) return 0;
      uint256 vestPortion = FixedPointMathLib.divWad(block.timestamp - vestingStart, vestingEnd - vestingStart);
      return FixedPointMathLib.mulWad(vestPortion, initialAllocation) - (initialAllocation - stakedLocks[user]);
    }
    else {
      return amount;
    }
  }
```

But it returns 0 for team members and they can't unstake forever.
Furthermore, in `stake()`, it just prevents seed investors, not team members. So if team members have staked additionally, they can't unstake also.

**Impact:** Team members can't unstake forever.

**Recommended Mitigation:** `_vestingCheck` should use the same logic as initial investors for team mates.

**Client:** Acknowledged, it is intended that the team cannot unstake their tokens. [PR #4](https://github.com/0xgeeb/goldilocks-core/pull/4) fixes issue of `stake` not preventing team members from staking.

**Cyfrin:** Verified.

### In `GovLocks`, it shouldn't use a `deposits` mapping

**Severity:** High

**Description:** In `GovLocks`, it tracks every user's deposit amount using a `deposits` mapping.
As users can transfer `govLocks` freely, they might have fewer `deposits` than their `govLocks` balance and wouldn't be able to withdraw when they want.

```solidity
  function deposit(uint256 amount) external {
    deposits[msg.sender] += amount; //@audit no need
    _moveDelegates(address(0), delegates[msg.sender], amount);
    SafeTransferLib.safeTransferFrom(locks, msg.sender, address(this), amount);
    _mint(msg.sender, amount);
  }

  /// @notice Withdraws Locks to burn Govlocks
  /// @param amount Amount of Locks to withdraw
  function withdraw(uint256 amount) external {
    deposits[msg.sender] -= amount; //@audit no need
    _moveDelegates(delegates[msg.sender], address(0), amount);
    _burn(msg.sender, amount);
    SafeTransferLib.safeTransfer(locks, msg.sender, amount);
  }
```

Here is a possible scenario.
- Alice has deposited 100 `LOCKS` and got 100 `govLOCKS`. Also `deposits[Alice] = 100`.
- Bob bought 50 `govLOCKS` from Alice to get voting power.
- When Bob tries to call `withdraw()`, it will revert because `deposits[Bob] = 0` although he has 50 `govLOCKS`.

**Impact:** Users wouldn't be able to withdraw `LOCKS` with `govLOCKS`.

**Recommended Mitigation:** We don't need to use the `deposits` mapping at all and we can just rely on `govLocks` balances.

**Client:** Fixed in [PR #8](https://github.com/0xgeeb/goldilocks-core/pull/8)

**Cyfrin:** Verified.

### Some functions of `Goldilend` will revert forever.

**Severity:** High

**Description:** `Goldilend.multisigInterestClaim()/apdaoInterestClaim()/sunsetProtocol()` will revert forever because they doesn't withdraw `ibgt` from `ibgtVault` before the transfer.

```solidity
  function multisigInterestClaim() external {
    if(msg.sender != multisig) revert NotMultisig();
    uint256 interestClaim = multisigClaims;
    multisigClaims = 0;
    SafeTransferLib.safeTransfer(ibgt, multisig, interestClaim);
  }

  /// @inheritdoc IGoldilend
  function apdaoInterestClaim() external {
    if(msg.sender != apdao) revert NotAPDAO();
    uint256 interestClaim = apdaoClaims;
    apdaoClaims = 0;
    SafeTransferLib.safeTransfer(ibgt, apdao, interestClaim);
  }

...

  function sunsetProtocol() external {
    if(msg.sender != timelock) revert NotTimelock();
    SafeTransferLib.safeTransfer(ibgt, multisig, poolSize - outstandingDebt);
  }
```

As `ibgtVault` has all `ibgt` of `Goldilend`, they should withdraw from `ibgtVault` first.

**Impact:** `Goldilend.multisigInterestClaim()/apdaoInterestClaim()/sunsetProtocol()` will revert forever.

**Recommended Mitigation:** 3 functions should be changed like the below.

```diffclea
  function multisigInterestClaim() external {
    if(msg.sender != multisig) revert NotMultisig();
    uint256 interestClaim = multisigClaims;
    multisigClaims = 0;
+  iBGTVault(ibgtVault).withdraw(interestClaim);
    SafeTransferLib.safeTransfer(ibgt, multisig, interestClaim);
  }

  /// @inheritdoc IGoldilend
  function apdaoInterestClaim() external {
    if(msg.sender != apdao) revert NotAPDAO();
    uint256 interestClaim = apdaoClaims;
    apdaoClaims = 0;
+  iBGTVault(ibgtVault).withdraw(interestClaim);
    SafeTransferLib.safeTransfer(ibgt, apdao, interestClaim);
  }

...

  function sunsetProtocol() external {
    if(msg.sender != timelock) revert NotTimelock();
+  iBGTVault(ibgtVault).withdraw(poolSize - outstandingDebt);
    SafeTransferLib.safeTransfer(ibgt, multisig, poolSize - outstandingDebt);
  }
```

**Client:** Fixed in [PR #9](https://github.com/0xgeeb/goldilocks-core/pull/9) and [PR #12](https://github.com/0xgeeb/goldilocks-core/pull/12)

**Cyfrin:** Verified.

## Medium Risk


### `Goldigovernor._getProposalState()` shouldn't use `totalSupply`

**Severity:** Medium

**Description:** In `_getProposalState()`, it uses `Goldiswap(goldiswap).totalSupply()` during the comparison.

```solidity
  function _getProposalState(uint256 proposalId) internal view returns (ProposalState) {
    Proposal storage proposal = proposals[proposalId];
    if (proposal.cancelled) return ProposalState.Canceled;
    else if (block.number <= proposal.startBlock) return ProposalState.Pending;
    else if (block.number <= proposal.endBlock) return ProposalState.Active;
    else if (proposal.eta == 0) return ProposalState.Succeeded;
    else if (proposal.executed) return ProposalState.Executed;
    else if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < Goldiswap(goldiswap).totalSupply() / 20) { //@audit shouldn't use totalSupply
      return ProposalState.Defeated;
    }
    else if (block.timestamp >= proposal.eta + Timelock(timelock).GRACE_PERIOD()) {
      return ProposalState.Expired;
    }
    else {
      return ProposalState.Queued;
    }
  }
```

As `totalSupply` is increasing in real time, a `Queued` proposal might be changed to `Defeated` one unexpectedly due to the increased supply.

**Impact:** A proposal state might be changed unexpectedly.

**Recommended Mitigation:** We should introduce another mechanism for the quorum check rather than using `totalSupply`.

**Client:** Fixed in [PR #5](https://github.com/0xgeeb/goldilocks-core/pull/5)

**Cyfrin:** Verified.

### In `Goldivault.redeemYield()`, users can redeem more yield tokens using reentrancy

**Severity:** Medium

**Description:** Possible reentrancy in `Goldivault.redeemYield()` if `yieldToken` has a `beforeTokenTransfer` hook.

- Let's assume `yt.totalSupply = 100, yieldToken.balance = 100` and the user has 20 yt.
- The user calls `redeemYield()` with 10 yt.
- Then `yt.totalSupply` will be changed to 90 and it will transfer `100 * 10 / 100 = 10 yieldToken` to the user.
- Inside the `beforeTokenTransfer` hook, the user calls `redeemYield()` again with 10 yt.
- As `yieldToken.balance` is still 100, he will receive `100 * 10 / 90 = 11 yieldToken`.

```solidity
  function redeemYield(uint256 amount) external {
    if(amount == 0) revert InvalidRedemption();
    if(block.timestamp < concludeTime + delay || !concluded) revert NotConcluded();
    uint256 yieldShare = FixedPointMathLib.divWad(amount, ERC20(yt).totalSupply());
    YieldToken(yt).burnYT(msg.sender, amount);
    uint256 yieldTokensLength = yieldTokens.length;
    for(uint8 i; i < yieldTokensLength; ++i) {
      uint256 finalYield;
      if(yieldTokens[i] == depositToken) {
        finalYield = ERC20(yieldTokens[i]).balanceOf(address(this)) - depositTokenAmount;
      }
      else {
        finalYield = ERC20(yieldTokens[i]).balanceOf(address(this));
      }
      uint256 claimable = FixedPointMathLib.mulWad(finalYield, yieldShare);
      SafeTransferLib.safeTransfer(yieldTokens[i], msg.sender, claimable);
    }
    emit YieldTokenRedemption(msg.sender, amount);
  }
```

**Impact:** Malicious users can steal `yieldToken` using `redeemYield()`.

**Recommended Mitigation:** We should add a `nonReentrant` modifier to `redeemYield()`.

**Client:** Fixed in [PR #13](https://github.com/0xgeeb/goldilocks-core/pull/13)

**Cyfrin:** Verified.

### Wrong validation in `Goldigovernor.cancel()`

**Severity:** Medium

**Description:** In `Goldigovernor.cancel()`, the proposer should have fewer votes than `proposalThreshold` to cancel his proposal.

```solidity
  function cancel(uint256 proposalId) external {
    if(_getProposalState(proposalId) == ProposalState.Executed) revert InvalidProposalState();
    Proposal storage proposal = proposals[proposalId];
    if(msg.sender != proposal.proposer) revert NotProposer();
    if(GovLocks(govlocks).getPriorVotes(proposal.proposer, block.number - 1) > proposalThreshold) revert AboveThreshold(); //@audit incorrect
    proposal.cancelled = true;
    uint256 targetsLength = proposal.targets.length;
    for (uint256 i = 0; i < targetsLength; i++) {
      Timelock(timelock).cancelTransaction(proposal.targets[i], proposal.eta, proposal.values[i], proposal.calldatas[i], proposal.signatures[i]);
    }
    emit ProposalCanceled(proposalId);
  }
```

**Impact:** A proposer can't cancel his proposal unless he decreases his voting power.

**Recommended Mitigation:** It should be modified like this.

```solidity
if(msg.sender != proposal.proposer && GovLocks(govlocks).getPriorVotes(proposal.proposer, block.number - 1) > proposalThreshold) revert Error;
```

**Client:** Fixed in [PR #7](https://github.com/0xgeeb/goldilocks-core/pull/7)

**Cyfrin:** Verified.

### Users wouldn't cancel their proposals due to the increased `proposalThreshold`.

**Severity:** Medium

**Description:** When users call `cancel()`, it validates the caller's voting power with `proposalThreshold` which can be changed using `setProposalThreshold()`.

```solidity
  function setProposalThreshold(uint256 newProposalThreshold) external {
    if(msg.sender != multisig) revert NotMultisig();
    if(newProposalThreshold < MIN_PROPOSAL_THRESHOLD || newProposalThreshold > MAX_PROPOSAL_THRESHOLD) revert InvalidVotingParameter();
    uint256 oldProposalThreshold = proposalThreshold;
    proposalThreshold = newProposalThreshold;
    emit ProposalThresholdSet(oldProposalThreshold, proposalThreshold);
  }
```

Here is a possible scenario.
- Let's assume `proposalThreshold = 100` and a user has 100 voting power.
- The user has proposed a proposal using `propose()`.
- After that, `proposalThreshold` was increased to 150 by `multisig`.
- When the user calls `cancel()`, it will revert as he doesn't have enough voting power.

**Impact:** Users wouldn't cancel their proposals due to the increased `proposalThreshold`.

**Recommended Mitigation:** It would be good to cache `proposalThreshold` as a proposal state.

**Client:** Acknowledged, we will ensure to only change parameters while there are no pending proposals.

**Cyfrin:** Acknowledged.

### `Goldilend.liquidate()` might revert due to underflow

**Severity:** Medium

**Description:** In `repay()`, there would be a rounding during the `interest` calculation.

```solidity
  function repay(uint256 repayAmount, uint256 _userLoanId) external {
      Loan memory userLoan = loans[msg.sender][_userLoanId];
      if(userLoan.borrowedAmount < repayAmount) revert ExcessiveRepay();
      if(block.timestamp > userLoan.endDate) revert LoanExpired();
      uint256 interestLoanRatio = FixedPointMathLib.divWad(userLoan.interest, userLoan.borrowedAmount);
L425  uint256 interest = FixedPointMathLib.mulWadUp(repayAmount, interestLoanRatio); //@audit rounding issue
      outstandingDebt -= repayAmount - interest > outstandingDebt ? outstandingDebt : repayAmount - interest;
      ...
  }
...
  function liquidate(address user, uint256 _userLoanId) external {
      Loan memory userLoan = loans[msg.sender][_userLoanId];
      if(block.timestamp < userLoan.endDate || userLoan.liquidated || userLoan.borrowedAmount == 0) revert Unliquidatable();
      loans[user][_userLoanId].liquidated = true;
      loans[user][_userLoanId].borrowedAmount = 0;
L448  outstandingDebt -= userLoan.borrowedAmount - userLoan.interest;
      ...
  }
```

Here is a possible scenario.
- There are 2 borrowers of `borrowedAmount = 100, interest = 10`. And `outstandingDebt = 2 * (100 - 10) = 180`.
- The first borrower calls `repay()` with `repayAmount = 100`.
- Due to the rounding issue at L425, `interest` is 9 instead of 10. And `outstandingDebt = 180 - (100 - 9) = 89`.
- In `liquidate()` for the second borrower, it will revert at L448 because `outstandingDebt = 89 < borrowedAmount - interest = 90`.

**Impact:** `liquidate()` might revert due to underflow.

**Recommended Mitigation:** In `liquidate()`, `outstandingDebt` should be updated like the below.

```diff
  /// @inheritdoc IGoldilend
  function liquidate(address user, uint256 _userLoanId) external {
    Loan memory userLoan = loans[msg.sender][_userLoanId];
    if(block.timestamp < userLoan.endDate || userLoan.liquidated || userLoan.borrowedAmount == 0) revert Unliquidatable();
    loans[user][_userLoanId].liquidated = true;
    loans[user][_userLoanId].borrowedAmount = 0;
+  uint256 debtToRepay = userLoan.borrowedAmount - userLoan.interest;
+  outstandingDebt -= debtToRepay > outstandingDebt ? outstandingDebt : debtToRepay;
   ...
  }
```

**Client:** Fixed in [PR #10](https://github.com/0xgeeb/goldilocks-core/pull/10)

**Cyfrin:** Verified.

### In `Goldigovernor`, wrong assumption of block time

**Severity:** Medium

**Description:** In `Goldigovernor.sol`, voting period/delay limits are set with 15s block time.

```solidity
  /// @notice Minimum voting period
  uint32 public constant MIN_VOTING_PERIOD = 5760; // About 24 hours

  /// @notice Maximum voting period
  uint32 public constant MAX_VOTING_PERIOD = 80640; // About 2 weeks

  /// @notice Minimum voting delay
  uint32 public constant MIN_VOTING_DELAY = 1;

  /// @notice Maximum voting delay
  uint32 public constant MAX_VOTING_DELAY = 40320; // About 1 week
```

But Berachain has 5s block time according to [its documentation](https://docs.berachain.com/faq/#how-well-does-berachain-perform).

```
Berachain has the following properties:

- Block time: 5s
```

So these limits will be set shorter than expected.

**Impact:** Voting period/delay limits will be set shorter than expected.

**Recommended Mitigation:** We should calculate these limits with 5s block time.

**Client:** Fixed in [PR #14](https://github.com/0xgeeb/goldilocks-core/pull/14)

**Cyfrin:** Verified.

## Low Risk


### `Goldivault.changeProtocolParameters()` shouldn't update `endTime`.

**Description:** `Goldivault.changeProtocolParameters()` updates `endTime` only without changing `startTime`.

```solidity
  function changeProtocolParameters(
    uint256 _earlyWithdrawalFee,
    uint256 _yieldFee,
    uint256 _delay,
    uint256 _duration
  ) external {
    if(msg.sender != timelock) revert NotTimelock();
    earlyWithdrawalFee = _earlyWithdrawalFee;
    yieldFee = _yieldFee;
    delay = _delay;
    duration = _duration;
    endTime = block.timestamp + _duration;
  }
```

It's more appropriate not to update `endTime` as this function is just to change parameters.

**Client:** Fixed in [PR #11](https://github.com/0xgeeb/goldilocks-core/pull/11)

**Cyfrin:** Verified.

### `Goldilocked._lockedLocks()` should round up.

**Description:** Users might borrow 1 more wei as it rounds down.
```solidity
  function _lockedLocks(address user) internal view returns (uint256) {
    return FixedPointMathLib.divWad(borrowedHoney[user], IGoldiswap(goldiswap).floorPrice());//@audit round up
  }
```
**Client:** Fixed in [PR #15](https://github.com/0xgeeb/goldilocks-core/pull/15)

**Cyfrin:** Verified.

### Possible failure to redeem

**Description:** In `Goldivault`, `redeemOwnership()` wouldn't work as expected after calling `changeProtocolParameters/initializeProtocol()` because `endTime/duration` is changed.

**Client:** Acknowledged, we plan to only call changeProtocolParameters after vault has concluded and ownership token holders have had chance to redeem. We will announce that we are going to update parameters and renew.

**Cyfrin:** Acknowledged.

### Inconsistent comparison while checking `eta`

**Description:** In `Goldigovernor` and `Timelock`, inconsistent comparisons are used.

```solidity
File: Goldigovernor.sol
386:     else if (block.timestamp >= proposal.eta + Timelock(timelock).GRACE_PERIOD()) {
387:       return ProposalState.Expired;
388:     }

File: Timelock.sol
138:     if(block.timestamp > eta + GRACE_PERIOD) revert TxStale();
```
**Client:** Fixed in [PR #6](https://github.com/0xgeeb/goldilocks-core/pull/6)

**Cyfrin:** Verified.

### Wrong comment

**Description:**
```solidity
File: Timelock.sol
49:   /// @notice Delay for queueing a transaction in blocks //@audit seconds, not blocks
60:   /// @param _delay Delay the timelock will use, in blocks //@audit seconds, not blocks
103:   /// @param eta Duration of time until transaction can be executed, in blocks //@audit seconds, not blocks
123:   /// @param eta Duration of time until transaction can be executed, in blocks //@audit seconds, not blocks
154:   /// @param eta Duration of time until transaction can be executed, in blocks //@audit seconds, not blocks

File: Goldilend.sol
496:   /// @notice Calculates claimable Porridge per GiBGT //@audit claimable reward token
608:   /// @dev Claims existing vault rewards and updates poolSize //@audit this function doesn't update poolSize
```
**Client:** Fixed in [PR #16](https://github.com/0xgeeb/goldilocks-core/pull/16)

**Cyfrin:** Verified.

### Missing bracket in docs

**Description:** [The document](https://goldilocks-1.gitbook.io/goldidocs/locks/the-price-function) is missing a bracket.
```diff
- Market price = Floor Price + ((PSL/Supply)*(FSL+PSL/FSL)^6)
+ Market price = Floor Price + (PSL/Supply)*((FSL+PSL)/FSL)^6
```

**Client:** Acknowledged, this has been corrected.

**Cyfrin:** Acknowledged.

### Rounding loss of 1 wei

**Description:** In `Goldivault`, sum of 2 amounts might be less than `amount` due to the rounding loss.

```solidity
File: Goldivault.sol
159:     if(remainingTime > 0) {
160:       SafeTransferLib.safeTransfer(depositToken, msg.sender, amount * (1000 - _fee) / 1000);
161:       SafeTransferLib.safeTransfer(depositToken, multisig, amount * _fee / 1000); //@audit rounding loss
162:       emit OwnershipTokenRedemption(msg.sender, amount * (1000 - _fee) / 1000);
163:     }

File: Goldilend.sol
430:     poolSize += userLoan.interest * (1000 - (multisigShare + apdaoShare)) / 1000;
431:     _updateInterestClaims(interest); //@audit rounding loss
...
694:   function _updateInterestClaims(uint256 interest) internal {
695:     multisigClaims += interest * multisigShare / 1000;
696:     apdaoClaims += interest * apdaoShare / 1000;
697:   }
```

**Client:** Fixed in [PR #17](https://github.com/0xgeeb/goldilocks-core/pull/17)

**Cyfrin:** Verified.

## Informational


### Unused constant

```solidity
File: Goldigovernor.sol
102:   /// @notice Amount of votes to reach quorum
103:   uint256 public constant quorumVotes = 9_500_000e18; // 5% of LOCKS
```



### Bad design to pull `HONEY` twice from the user

Users should approve the transfer twice during the interaction. It would be better to pull the whole amount from the user at a time and transfer to `multisig` from the contract.

```solidity
File: Goldiswap.sol
149:     SafeTransferLib.safeTransferFrom(honey, msg.sender, address(this), price);
150:     SafeTransferLib.safeTransferFrom(honey, msg.sender, multisig, tax);
```

## Gas Optimization


### Constructors can be marked as `payable`.

Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided. A constructor can safely be marked as `payable`, since only the deployer would be able to pass funds, and the project itself would not pass any funds. (9 Instances)



### Nesting `if`-statements is cheaper than using `andand`.

Nesting `if`-statements avoids the stack operations of setting up and using an extra jumpdest, and saves 6 gas.

```solidity
File: GovLocks.sol
214:     if (srcRep != dstRep && amt > 0) {
237:     if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == block.number) {
266:     if(from != address(0) && to != address(0)) {

File: Goldilend.sol
536:     return _poolSize > 0 && supply > 0 ? FixedPointMathLib.mulWad(lockAmount, _GiBGTRatio(supply, _poolSize)) : lockAmount;

File: Goldiswap.sol
329:     if (elapsedIncrease >= 1 days && elapsedDecrease >= 1 days) {
```



### Use `uint256(1)/uint256(2)` instead of `true/false` to save gas for changes.

Avoids 20000 gas when changing from `false` to `true`, after having been true in the past.

```solidity
File: Goldilend.sol
107:   bool public borrowingActive;

File: Goldivault.sol
91:   bool public concluded;
```



### Augmented assignment operator costs more gas than normal addition for state variables.

Normal addition operation (`x=x+y`) costs less gas than augmented assignment operator (`x+=y`) for state variables (113 gas). (34 instances)


### Cache array length outside of loops and consider unchecked loop incrementing.

```solidity
File: Goldilend.sol
251:   function boost(
252:     address[] calldata partnerNFTs,
253:     uint256[] calldata partnerNFTIds
254:   ) external {
255:     for(uint256 i; i < partnerNFTs.length; i++) {
256:       if(partnerNFTBoosts[partnerNFTs[i]] == 0) revert InvalidBoostNFT();
257:     }
258:     if(partnerNFTs.length != partnerNFTIds.length) revert ArrayMismatch();
259:     boosts[msg.sender] = _buildBoost(partnerNFTs, partnerNFTIds);
260:     for(uint8 i; i < partnerNFTs.length; i++) {
261:       IERC721(partnerNFTs[i]).safeTransferFrom(msg.sender, address(this), partnerNFTIds[i]);
262:     }
263:   }
```

\clearpage