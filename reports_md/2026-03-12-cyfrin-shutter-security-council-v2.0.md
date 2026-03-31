**Lead Auditors**

[Stalin](https://x.com/0xStalin)

[Blckhv](https://x.com/blckhv)

[Slavcheww](https://x.com/Slavcheww)

**Assisting Auditors**



---

# Findings
## Informational


### Guard replacement during council rotation resets veto state, allowing previously-vetoed proposals to execute

**Description:** `council` is immutable in `SecurityCouncilAzorius`. Council rotation requires deploying a new guard contract and calling `Azorius.setGuard(newGuard)`. The new guard starts with a clean, empty `vetoedTxHash` mapping.

If there are proposals currently in the execution window (after timelock, before expiry) that were vetoed under the old guard, those vetoes are NOT in the new guard. The instant `Azorius.setGuard(newGuard)` is executed on-chain, the old vetoes become unenforceable.

As per the `CouncilRotation Procedure` on the `OPERATIONS` file. The veto of existing vetoed txs happens after the new council has been set as the guard on the `Azourius` contract. This creates a gap that could be theoretically front-run to execute a txHash that should be vetoed.


**Attack Scenario:**

1. Attacker submits a malicious proposal
2. Council vetoes it under the old guard — `vetoedTxHash[malicious_hash] = true`
3. The proposal is within its execution window (after timelock)
4. Council rotation is triggered
5. New guard is deployed with empty state, `Azorius.setGuard(newGuard)` is called
6. Old guard's veto state is no longer enforced
7. Attacker immediately executes the malicious proposal through the new guard


**Impact:** During council rotation, there is a time window during which previously vetoed proposals can be executed. This is a race condition between the guard switch and any executor of a malicious proposal.

**Recommended Mitigation:**
- In the `OPERATIONS.md` rotation procedure, add: **"Before executing `setGuard(newGuard)`, the new council must pre-veto all currently-vetoed hashes in the new guard."**
- Consider adding an `initialVetoes` parameter to the constructor to batch-initialize veto state atomically at deployment
- Document this gap prominently in the rotation runbook as a mandatory pre-flight step

**Blockful:** Fixed in commit [227d737](https://github.com/blockful/shutter-security-council/commit/227d7376b7387c1f88c252dcdf8b9b3d2377ca91) && [6a53351](https://github.com/blockful/shutter-security-council/commit/6a533516f8c22f65d45ead714fe5049ec7b442f6)

**Cyfrin:** Verified. `SecurityCouncilAzorius` now inherits `Ownable`. Council rotations will happen on the `SecurityCouncilAzorius` contract, no changes on the `Azorius` guard will happen. Council rotation won't disrupt the current veto state


### `_getProposalTxHashes` can be simplified

**Description:** `SecurityCouncilAzorius._getProposalTxHashes` retrieves the `txHashes` for a given `proposalId` by calling `Azorius.getProposal` and only using the second return value. However, `Azorius` already exposes a dedicated view function, `getProposalTxHashes`, which directly returns the `txHashes`.

**Recommended Mitigation:** Use `Azorius.getProposalTxHashes()` instead. This requires adding `getProposalTxHashes()` to the `IAzorius` interface.

```diff
    function _getProposalTxHashes(uint32 proposalId) internal view returns (bytes32[] memory txHashes) {
-       (, txHashes,,,) = IAzorius(azorius).getProposal(proposalId);
+       txHashes = IAzorius(azorius).getProposalTxHashes(proposalId);
    }
```

**Blockful:** Fixed in commit [d7e96b2](https://github.com/blockful/shutter-security-council/commit/d7e96b262204998bc90cab850f8221e955a1391c#diff-f8e3fe7aff7a5528b681495716238afa73895a423f8032270280e77ff3dd52ad)

**Cyfrin:** Verified.


### `timelockPeriod` documented as seconds but `Azorius` treats it as blocks, causing ~36-day timelock

**Description:** The [GOVERNANCE_PARAMETERS.md:139](https://github.com/Cyfrin/audit-2026-03-shutter-security-council-src/blob/94736af/Shutter-Security-Council/docs/GOVERNANCE_PARAMETERS.md#L139) states that `timelockPeriod` is in seconds and uses `block.timestamp` comparison. The actual `Azorius` code compares it against `block.number`, meaning `timelockPeriod` is in blocks.

The recommended value of `259,200` is calibrated as seconds (3 days), but `Azorius` adds it to `votingEndBlock` and compares against `block.number`. At `12s` average block time, `259,200` blocks equals ~36 days, not 3 days.

[Azorius.sol#L317-L328](https://github.com/Cyfrin/audit-2026-03-shutter-security-council-src/blob/94736af/Shutter-Security-Council/src/azorius/Azorius.sol#L317-L328)
```solidity
uint256 votingEndBlock = _strategy.votingEndBlock(_proposalId);

// ...

} else if (block.number <= votingEndBlock + _proposal.timelockPeriod) {
    return ProposalState.TIMELOCKED;
```

[GOVERNANCE_PARAMETERS.md#L139](https://github.com/Cyfrin/audit-2026-03-shutter-security-council-src/blob/94736af/Shutter-Security-Council/docs/GOVERNANCE_PARAMETERS.md#L139)

`timelockPeriod` is in seconds, not blocks. It uses `block.timestamp` comparison.
For reference, `executionPeriod` is correctly documented as blocks, and its recommended value of `50,400` blocks correctly equals ~7 days at 12s block time.

**Impact:** If the deployment follows the markdown as-is, governance proposals will be locked for ~36 days instead of the intended 3 days after passing a vote. This makes the DAO nearly unusable and proposals would likely expire before reaching the execution window. The correct value for a 3-day timelock is `21,600` blocks (matching the current `votingPeriod` and original `executionPeriod`).

**Recommended Mitigation:** Update `GOVERNANCE_PARAMETERS.md` to correct the unit and value:

- Change timelockPeriod description from "seconds" to "blocks"
- Change the recommended value from `259,200` to `21,600` (3 days in blocks at 12s block time)

**Blockful:** Fixed in commit [76081e2](https://github.com/blockful/shutter-security-council/commit/76081e20a1e668e0ddc794dec2f91c6ccf15e7b2)

**Cyfrin:** Verified. Documentation on `GOVERNANCE_PARAMETERS.md` has been updated to the correct number of blocks for the expected delay time.

\clearpage