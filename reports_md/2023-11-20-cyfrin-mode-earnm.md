**Lead Auditors**

[Dacian](https://twitter.com/devdacian)

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**

 


---

# Findings
## Critical Risk


### Polygon chain reorgs will change mystery box tiers which can be gamed by validators

**Description:** [`REQUEST_CONFIRMATIONS = 3`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L26) is too small for polygon, as [chain re-orgs frequently have block-depth greater than 3](https://polygonscan.com/blocks_forked?p=1).

**Impact:** Chain re-orgs re-order blocks and transactions changing randomness results. Someone who originally won a rare box could have that result changed into a common box and vice versa due to changing randomness result during the re-org.

This can also be [exploited by validators](https://docs.chain.link/vrf/v2/security/#choose-a-safe-block-confirmation-time-which-will-vary-between-blockchains) who can intentionally rewrite the chain's history to force a randomness request into a different block, changing the randomness result. This allows validators to get a fresh random value which may be to their advantage if they are minting mystery boxes by moving the txn around to get a better randomness result to mint a rarer box.

**Recommended Mitigation:** `REQUEST_CONFIRMATIONS = 30` appears very safe for polygon as it is very rare for chain re-orgs to have block-depth greater than this. If this happens occasionally it isn't a big deal, but if it happens all the time ("3" ensures this) that is not good and potentially exploitable by validators.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Transferring mystery boxes bricks token redemption

**Description:** `MysteryBox` is an `ERC1155` contract which users expect to be able to transfer to other addresses via the in-built transfer functions. But `MysteryBox::claimMysteryBoxes()` [reverts](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L296) unless the caller is the same address who minted the box since the internal mappings that track mystery box ownership are never updated when transfers occur.

**Impact:** Token redemption is bricked if users transfer their mystery box. Users reasonably expect to be able to transfer their mystery box from one address they control to another address (if for example their first address is compromised), or they may wish to sell their mystery box on platforms like OpenSea which support `ERC1155` sales.

**Recommended Mitigation:** Override `ERC1155` transfer hooks to either prevent transferring of mystery boxes, or to update the internal mappings such that when mystery boxes are transferred the new owner address can redeem their tokens. The second option may be more attractive for the protocol as it allows mystery box holders to access liquidity without putting sell pressure on the token, creating a "secondary market" for mystery boxes.

**Mode:**
Fixed in commit [a65a50c](https://github.com/Earnft/smart-contracts/commit/a65a50ca8af4d6abc58d3c429785bcd82182c04e) by overriding `ERC1155::_beforeTokenTransfer()` to prevent mystery boxes from being transferred.

**Cyfrin:** Verified.

\clearpage
## High Risk


### Broken check in `MysteryBox::fulfillRandomWords()` fails to prevent same request being fulfilled multiple times

**Description:** Consider the [check](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L221-L222) which attempts to prevent the same request from being fulfilled multiple times:
```solidity
if (vrfRequests[_requestId].fulfilled) revert InvalidVrfState();
```

The problem is that `vrfRequests[_requestId].fulfilled` is never set to `true` anywhere and `vrfRequests[_requestId]` is [deleted](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L244-L245) at the end of the function.

**Impact:** The same request can be fulfilled multiple times which would override the previous randomly generated seed; a malicious provider who was also a mystery box minter could generate new randomness until they got a rare mystery box.

**Recommended Mitigation:** Set `vrfRequests[_requestId].fulfilled = true`.

Consider an optimized version which involves having 2 mappings `activeVrfRequests` and `fulfilledVrfRequests`:
* revert `if(fulfilledVrfRequests[_requestId])`
* else set `fulfilledVrfRequests[_requestId] = true`
* fetch the matching active request into memory from `activeVrfRequests[_requestId]` and continue processing as normal
* at the end `delete activeVrfRequests[_requestId]`

This only stores forever the `requestId` : `bool` pair in `fulfilledVrfRequests`.

Consider a similar approach in `MysteryBox::fulfillBoxAmount()`.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3), [c4c50ed](https://github.com/Earnft/smart-contracts/commit/c4c50edcd2a3f9fc2da4e1934bcfa1d3cbd85809), [d5b14d8](https://github.com/Earnft/smart-contracts/commit/d5b14d80dae0cc78ab63537d405c8c49a6238a57), [5df2b82](https://github.com/Earnft/smart-contracts/commit/5df2b824dba5b25a0d8db28fa10de4a4bc52ec3b).

**Cyfrin:** Verified.


### Owner can rug-pull redemption tokens leaving mystery box contract insolvent and mystery box holders unable to redeem

**Description:** [`MysteryBox::ownerWithdrawEarnm()`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L765-L777) allows the owner to transfer the contract's total redemption token balance to themselves, rug-pulling the redemption tokens which mystery boxes are supposed to be redeemed for.

**Impact:** The contract becomes totally insolvent and mystery box owners are unable to redeem.

**Recommended Mitigation:** The contract should always have the necessary tokens to payout the maximum redemption liability on all currently minted and unclaimed mystery boxes. The owner should only be able to withdraw the surplus amount (the excess over the total liability).

When mystery boxes are minted the total liability increases and when mystery boxes are claimed the total liability decreases. Consider tracking the total liability as mystery boxes are minted & claimed and only allowing the owner to withdraw the surplus tokens above this value.

**Mode:**
Fixed in commit [db7b48e](https://github.com/Earnft/smart-contracts/commit/db7b48e69c33e327d613f88035c8335531572e8d), [edefb61](https://github.com/Earnft/smart-contracts/commit/edefb61534ecee1a2f6cb7e687c113a1f7b82056), [a65a50c](https://github.com/Earnft/smart-contracts/commit/a65a50ca8af4d6abc58d3c429785bcd82182c04e).

**Cyfrin:** Verified.


### Incorrect cap on `batchesAmount` results in 500M instead of 5B tokens distributed to mystery box holders

**Description:** `setBatchesAmount()` [caps](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L782) the maximum `batchesAmount` 100 but this is incorrect. Every batch releases mystery boxes which can be redeemed for ~5M tokens and there are 5B tokens in total so 1000 batches to distribute the entire supply.

**Impact:** Incorrectly capping to 100 batches results in never being able to distribute all 5B tokens, but only 500M tokens.

**Recommended Mitigation:** Cap `batchesAmount` to 1000 to allow full token distribution.

**Mode:**
Fixed in commit [ae3dc68](https://github.com/Earnft/smart-contracts/commit/ae3dc68db8c723293df01cb14297dc3264a21dbe).

**Cyfrin:** Verified.

\clearpage
## Medium Risk


### Excess eth not refunded to user in `MysteryBox::revealMysteryBoxes()`

**Description:** `MysteryBox::revealMysteryBoxes()` [allows execution](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L196-L198) if `msg.value >= mintFee` but in the case where `msg.value > mintFee`, the extra eth gets sent to `operatorAddress` not refunded back to the user.

**Impact:** User loses excess eth above `mintFee`.

**Recommended Mitigation:** Either refund excess eth back to the user or revert if `msg.value != mintFee`.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Minting can be indefinitely stuck due to request timeout of external adapters when using Chainlink Any API

**Description:** Mode has integrated Chainlink Any API to interact with external adapters, verifying user codes and wallet addresses to determine the number of boxes to mint. The system uses a `direct-request` job type, triggering actions based on the `ChainlinkRequested` event emission. However, there's a notable issue: if the initial GET request times out, such requests may remain pending indefinitely. Current design does not have a provision to cancel pending requests and create new ones.

**Impact:** If the external adapter doesn't respond promptly, users are unable to submit another minting request because their code is deleted after the initial request. This could result in users losing their codes and not receiving their mystery box rewards.

**Recommended Mitigation:** Consider implementing a function that code recipients can invoke in the event of a request timeout. This function should internally call `ChainlinkClient:cancelChainlinkRequest` and include a callback to the `MysteryBox` contract to initiate a new request using the same data as the original. Essentially, this means reusing the code/user address and the previously generated random number for the new request.

**Mode:**
Acknowledged.


\clearpage
## Low Risk


### Use low level `call()` to prevent gas griefing attacks when returned data not required

**Description:** Using `call()` when the returned data is not required unnecessarily exposes to gas griefing attacks from huge returned data payload. For [example](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L197-L198):
```solidity
(bool sent, ) = address(operatorAddress).call{value: msg.value}("");
if (!sent) revert Unauthorized();
```
Is the same as writing:
```solidity
(bool sent, bytes memory data) = address(operatorAddress).call{value: msg.value}("");
if (!sent) revert Unauthorized();
```
In both cases the returned data will have to be copied into memory exposing the contract to gas griefing attacks, even though the returned data is not required at all.

**Impact:** Contracts unnecessarily expose themselves to gas griefing attacks.

**Recommended Mitigation:** Use a low-level call when the returned data is not required, eg:

```solidity
bool sent;
assembly {
    sent := call(gas(), receiver, amount, 0, 0, 0, 0)
}
if (!sent) revert Unauthorized();
```
Consider using [ExcessivelySafeCall](https://github.com/nomad-xyz/ExcessivelySafeCall).

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.

\clearpage
## Informational


### Prevent duplicate `boxId` inputs to `MysteryBox::claimMysteryBoxes()`

**Description:** Consider preventing duplicate `boxId` inputs to [`MysteryBox::claimMysteryBoxes()`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L271) as this may be exploitable under certain circumstances.

**Impact:** Attackers could use duplicate inputs to exploit token claiming.

**Recommended Mitigation:** Revert if duplicate inputs occur; `boxId` is unique so duplicate inputs are an obvious sign of a malicious attack.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3), [3713107](https://github.com/Earnft/smart-contracts/commit/3713107bb24382bda0fb6ac2eb51e9c64c39c98d).

**Cyfrin:** Verified.


### `MysteryBox::claimMysteryBoxes()` should return custom error when reverting due to `amountToClaim == 0`

**Description:** `MysteryBox::claimMysteryBoxes()` should [return custom error](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L305) when reverting due to `amountToClaim == 0`. Currently it returns `InsufficientEarnmBalance` which is the same error as if the contract had insufficient token balance for the mystery box being redeemed.

**Impact:** Misleading error is returned.

**Recommended Mitigation:** Return a custom error.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Potential Risk of Price Volatility in EarnNM Token Due to Concentrated Mystery Box Rewards

**Description:** The current mechanism for distributing mystery box rewards in the system is based on randomness, which carries the risk of a large influx of tokens entering circulation within a short span. In particular, unusual situations might arise where a substantial number of high-value boxes (such as 1 mythical, 2 legendary, and 10 epic) are allocated over a brief period, like 1-2 days. Additionally, there's a possibility of minting a significant volume of boxes in a short duration. As a result, there's a possibility that all these boxes might release EarnM tokens simultaneously when their vesting period ends.

EarnM tokens are not fee-based tokens (e.g., token value linked to protocol fees) or any staking mechanisms to encourage token retention. In effect, there are no demand drivers and no supply dampeners in the current design.

**Impact:** Intense sell pressure, especially during a market downturn, may lead to price manipulation risks in liquidity pools. Such a significant price drop could incite panic among users, prompting them to redeem their mystery boxes notwithstanding the 50/90% haircut. This action could amplify the sell-off, potentially spiralling into a severe scenario akin to previous market collapses seen with tokens like Terra Luna.

**Recommended Mitigation:** Given the uncertainty surrounding the scale and reach of EarnM token liquidity pools, we recommend the team ensures sufficient liquidity to counterbalance potential sell pressure post-vesting. Proactive liquidity management could be crucial in stabilising token value during critical periods.

**Mode:**
Acknowledged.


### Centralisation risks as the reward code generator and the Chainlink node operator is the same entity

**Description:** The current system architecture for managing reward codes in MODE is centralized, with both code generation and Chainlink node operations controlled by the MODE team. The endpoint tracking and managing these codes is not public. Using Chainlink Any API under this setup adds limited value, as it's managed by a single node operator – the MODE team itself. This centralization undermines the potential benefits of a decentralized oracle network.

**Impact:** This setup leads to unnecessary complications and expenses, including LINK fees, without offering the decentralization benefits typically associated with Chainlink's infrastructure.

**Recommended Mitigation:** Two potential alternatives could be considered to address this issue:

1. **Engage an External Node Operator:** Delegate the reward code verification tasks to an external node operator. This approach would involve creating a function to call `Chainlink:setChainlinkOracle`, allowing future updates to the oracle. Making the endpoint public in the future would empower MODE to appoint new operators as needed.

2. **Simplify with In-House Tracking:** If the node operator remains the same as the code generation entity, consider simplifying the process. Maintain an on-chain mapping linking codes and addresses to their respective box amounts. Update this mapping each time `apiAddress` triggers `MysteryBox::associateOneTimeCodeToAddress` with the permissible box amount. This streamlined approach would bypass the need for Chainlink oracles and external adapters, reducing LINK fees and complexity while maintaining the current level of centralisation.

We acknowledge that the chosen design was driven by the intent to facilitate the minting of mystery boxes in a single transaction, given the gas limitations associated with VRF (Verifiable Random Function) operations. MODE team's approach was reasonable under these constraints.

**Mode:**
Acknowledged.

\clearpage
## Gas Optimization


### Remove from storage `baseMetadataURI` as already stored in `ERC1155` and `name` as never used

**Description:** Remove from [storage](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L53-L54) `baseMetadataURI` as already stored in `ERC1155` & `name` as never used.

**Impact:** Extra storage costs and extra gas to write these unnecessary values to storage.

**Recommended Mitigation:** Remove both `baseMetadataURI` & `name` from storage.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Standardize `tierId` to either `uint8` or `uint256` avoiding constant conversions back and forth

**Description:** Standardize `tierId` to either `uint8` or `uint256` avoiding constant conversions back and forth.

**Impact:** Having different types for `tierId` means it has to be converted but also increases complexity and confusion as to why it is different in some places to others.

**Recommended Mitigation:** Standardize `tierId` to either `uint8` or `uint256`.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Simplify `boxId` storage mappings as `boxId` is unique to addresses and tiers

**Description:** Since `boxId` is unique such that multiple address or tiers can never have the same `boxId`, at least [2 storage mappings](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L64-L65) could potentially be simplified: `addressToTierToBoxIdToBlockTs` & `addressToBoxIdToTier`.

Consider refactoring the other nested mappings to simplify and reduce complexity.

**Impact:** The storage mappings are already quite complex which is error-prone and the way these 2 are implemented will require more gas to read/write.

**Recommended Mitigation:** Simplify these mappings by taking advantage of the fact that `boxId` is unique to addresses & tiers.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3), [efa8199](https://github.com/Earnft/smart-contracts/commit/efa8199895c7f5c76b5ac3c81bceaa94c8838eb2), [9c5ac66](https://github.com/Earnft/smart-contracts/commit/9c5ac662180602a3b1addf57c791e562c0ab9cd7).

**Cyfrin:** Verified.


### State variables should be cached in stack variables rather than re-reading them from storage

**Description:** State variables should be cached in stack variables rather than re-reading them from storage.

* `MysteryBox::fulfillRandomWords()` reads `vrfRequests[_requestId]` 3 times; consider reading it once into memory then reading from memory to avoid multiple storage reads.
* `MysteryBox::fulfillBoxAmount()` could cache `eaRequestToAddress[_requestId]` and also `delete addressToRandomNumber[sender]`
* `MysteryBox::_assignTierAndMint()` should have `uint256 newBoxId = ++boxIdCounter;` then use `newBoxId` in the rest of the function.

**Impact:** Gas optimization

**Recommended Mitigation:** State variables should be cached in stack variables rather than re-reading them from storage.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3), [c4c50ed](https://github.com/Earnft/smart-contracts/commit/c4c50edcd2a3f9fc2da4e1934bcfa1d3cbd85809), [d5b14d8](https://github.com/Earnft/smart-contracts/commit/d5b14d80dae0cc78ab63537d405c8c49a6238a57), [5df2b82](https://github.com/Earnft/smart-contracts/commit/5df2b824dba5b25a0d8db28fa10de4a4bc52ec3b).

**Cyfrin:** Verified.


### Loop backwards in `MysteryBox::_determineTier()` to avoid multiple variables and simplify code

**Description:** [Loop backwards](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L380-L383) in `MysteryBox::_determineTier()` to avoid multiple variables and simplify code.

**Impact:** Gas optimization and simpler code.

**Recommended Mitigation:** See description.

**Mode:**
Fixed in commit [4d56069](https://github.com/Earnft/smart-contracts/commit/4d560697f7dd6fa4f6b6303cca3e21c4025bee5b).

**Cyfrin:** Verified.


### Simplify calculation in `MysteryBox::_calculateAmountToClaim()`

**Description:** Execute this line every time `return (tokens * (10**EARNM_DECIMALS)) / divisor;` [deleting the other branch](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L416-L417) and the useless `%` calculation.

**Impact:** Gas optimization and cleaner, simpler code.

**Recommended Mitigation:** See description.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Remove unused `category` from `MysteryBox::_calculateVestingPeriodPerBox()`

**Description:** Remove [unused](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L296) `category` from `MysteryBox::_calculateVestingPeriodPerBox()`.

**Impact:** Gas optimization & simpler, cleaner code.

**Recommended Mitigation:** See description.

**Mode:**
Fixed in commit [85b2012](https://github.com/Earnft/smart-contracts/commit/85b20121604b5d162bb14c2c96731b8345ca1cb3).

**Cyfrin:** Verified.


### Check `boxAmount < 100` only once before loop in `MysteryBox::_assignTierAndMint()`

**Description:** As `boxAmount` input is static, [check `boxAmount < 100`](https://github.com/Earnft/smart-contracts/blob/43d3a8305dd6c7325339ed35d188fe82070ee5c9/contracts/MysteryBox.sol#L479) only once before loop in `MysteryBox::_assignTierAndMint()`.

**Impact:** Gas optimization.

**Recommended Mitigation:** See description.

**Mode:**
Fixed in commit [06a6a4f](https://github.com/Earnft/smart-contracts/commit/06a6a4f6f12e5a52f797af26c4a27a4994fe6ce1).

**Cyfrin:** Verified.

\clearpage