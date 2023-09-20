**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**

[0kage](https://twitter.com/0kage_eth)


---

# Findings
## High Risk

### Attackers can use a malicious yield token to steal funds from users

**Severity:** High

**Description:** According to the documentation and the current implementation, anyone can create a new StakePet contract and feed any address for the `YIELD_TOKEN`. As long as a contract implements `IYieldToken` interface, the contract will be created without problems.

An attacker can create a malicious `IYieldToken` implementation and use that to steal funds from users.
The StakePet contract relies on `YIELD_TOKEN.toToken()` and `YIELD_TOKEN.toValue()` in numerous places for accounting.
Consider a contract that has implemented different logic in `toToken()` and `toValue()` according to the owner's hidden flag.
The attacker is likely to let the malicious token contract work normally till the StakePet contract gets enough deposits.
Then they can switch the hidden flag as they needed to mess the accounting and take profit from it.
In the worst case, they can even manipulate the output of `IYieldToken::ERC20_TOKEN()` (maybe to freeze the user funds permanently).

**Impact:** User funds can be stolen or permanently locked.

**Recommended Mitigation:** Consider maintaining a whitelist of YIELD_TOKEN and allow creation of StakePet for only allowed yield tokens.

**Client:** Fixed in commit [308672e](https://github.com/Ranama/StakePet/commit/308672e914651ca2300f2b585d91f16764994bf7).

**Cyfrin:** Verified.

### Inflation attack can cause early users to lose their deposit

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and deposits 1 ether.
- Pete, unfortunately, receives zero ownership while his deposit remains within the contract

**Recommended Mitigation:** Inflation attacks have known defences. A comprehensive discussion can be found [here](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706).

One noteworthy method, as implemented by Uniswap V2, involves depositing minimal liquidity into the contract and transferring its ownership to a null address, creating "dead shares". This technique protects the subsequent depositor from potential inflation attacks.

In this case, it might be beneficial to introduce a minimum collateral requirement during contract initiation, and accordingly adjust `s_totalOwnership` to match this preset collateral.

**Client:** Fixed in commit [a692abc](https://github.com/Ranama/StakePet/commit/a692abc038fdd8992916f93d213a38c30e3a9764) and [21dd15b](https://github.com/Ranama/StakePet/commit/21dd15b1fceecddb9caf47739b6df1a4d1856367).

**Cyfrin:** Verified.

## Medium Risk

### A malicious user can grief a `StakePet` contract by creating massive number of pets

**Severity:** Medium

**Description:** The `StakePet::create` function facilitates the minting of a pet NFT by depositing collateral. However, its lack of a minimum deposit requirement for minting exposes it to potential abuse. A malicious user can exploit this by minting an excessive number of NFTs. Notably, this behaviour can strain functions like `StakePetManager::buryAllDeadPets`, which in turn calls `StakePetManager::getDeadNonBuriedPets`. This latter function iterates through all pet IDs to identify pets that are dead but not yet buried.

**Impact:** When a function processes an extensive and potentially unlimited list of pet IDs, there's a risk of it consuming all available gas. Consequently, it can fail, throwing an out-of-gas exception, which negatively affects users trying to interact with the contract.

**Recommended Mitigation:** To deter such griefing attacks, it's advisable to introduce a minimum deposit requirement for the creation of a new pet. Setting this threshold ensures that the mass-minting strategy becomes cost-prohibitive for attackers.

**Client:** Fixed in commit [a692abc](https://github.com/Ranama/StakePet/commit/a692abc038fdd8992916f93d213a38c30e3a9764).

**Cyfrin:** Verified.

## Low Risk

### Closedown condition is inconsistent with the stated documentation of majority agreement

**Severity:** Low

**Description:** [Documentation](https://hackmd.io/CPINxScvSE2vo-t8mwY_Og#Risks) states the following:

_"Closing the Contract: If the majority of the pets agree, they can vote to close the contract. Once closed, the remaining funds will be divided among the surviving pets. This is the most beneficial scenario for you, as you’ll earn the base rewards, early withdrawal rewards, and rewards from dead pets."_

Inline comments for the [`StakePet::closedown`](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L398C2-L398C2) function state the following"

```
    /// @notice Close down the contract if majority wants it, after closedown everyone can withdraw without getting a yield cut and no pet can die.
    function closedown(uint256[] memory _idsOfMajorityThatWantsClosedown) external {
...
}
```

In both cases, condition for closedown is for `majority of pets` to agree for a closedown. However, the check used for `closedown` is that the total collateral of pets wanting a closedown should be atleast 50% of the total collateral. This would mean that a single or few pet owners with large collateral deposits can trigger a closedown even if its not something that a majority of pet owners agree to.

Having 50% of value agreement and having majority agreement could be 2 different things.

**Impact:** The current model can be hijacked by whales who can trigger closedown of contract whenever they wish to. This could create a bad user experience for majority of pet owners who want to stay in the contract

**Recommended Mitigation:** Please make documentation consistent with the vision for stake pets.

**Client:** Fixed in [54a4dcb](https://github.com/Ranama/StakePet/commit/54a4dcbb696da3138dc0fdd8e7032d664d32b7da)

**Cyfrin:** Verified.

### Exit fees implementation is inconsistent with documentation

**Severity:** Low

**Description:** Inline comments of `StakePet` contract indicate that exit fee is charged as % of the collateral.

```
The contract also has an early exit fee, which is a percentage of the collateral taken if a participant chooses to exit early.
```

However, implementation shows that exit fee is charged as a [percent of yield](https://github.com/Ranama/StakePet/blob/9ba301823b5062d657baa3462224da498dc4bb46/src/StakePet.sol#L559)

```
uint256 earlyExitFee = (uint256(yieldToWithdraw) * EARLY_EXIT_FEE) / BASIS_POINT
```

**Recommended Mitigation:** Consider correcting code documentation to reflect actual implementation

**Client:** Fixed in [54a4dcb](https://github.com/Ranama/StakePet/commit/54a4dcbb696da3138dc0fdd8e7032d664d32b7da)

**Cyfrin:** Verified.

## Gas Optimizations

### Using bools for storage incurs overhead

Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

```solidity
File: StakePet.sol

91:     bool public constant TESTING = true; // TODO: Remove this when not testing

107:     bool public immutable HARDCORE; // Whether the initial collateral is taken if failing to proof of life or not

```

**Client:** Fixed in [aea1f74](https://github.com/Ranama/StakePet/commit/aea1f7464339cb16008143440bd427b6f0a14669)

**Cyfrin:** Verified.

### Cache array length outside of loop

If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

```solidity
File: StakePet.sol

410:         for (uint256 i = 0; i < _idsOfMajorityThatWantsClosedown.length; i++) {

```

```solidity
File: StakePetManager.sol

73:         for (uint256 i = 0; i < _contractIDs.length; i++) {

75:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

108:         for (uint256 i = 0; i < _contractIDs.length; i++) {

110:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

147:         for (uint256 i = 0; i < _contractIDs.length; i++) {

```

**Client:** Fixed in [627d09c](https://github.com/Ranama/StakePet/commit/627d09c34bb4853418e8c22ed8ce291efd7ad087)

**Cyfrin:** Verified.

### Don't initialize variables with default value

```solidity
File: StakePet.sol

128:     uint256 public s_closedAtTimestamp = 0; // The timestamp that the contract was closed down

409:         uint256 _totalValueWantsClosedown = 0;

410:         for (uint256 i = 0; i < _idsOfMajorityThatWantsClosedown.length; i++) {

```

```solidity
File: StakePetManager.sol

73:         for (uint256 i = 0; i < _contractIDs.length; i++) {

75:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

108:         for (uint256 i = 0; i < _contractIDs.length; i++) {

110:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

123:         uint256 j = 0;

137:         for (uint256 i = 0; i < j; i++) {

147:         for (uint256 i = 0; i < _contractIDs.length; i++) {

```

**Client:** Fixed in [970b71c](https://github.com/Ranama/StakePet/commit/970b71cfe73760dc694b0c0e1e5a3a77dc704c8c)

**Cyfrin:** Verified.

### `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)

```solidity
File: StakePet.sol

410:         for (uint256 i = 0; i < _idsOfMajorityThatWantsClosedown.length; i++) {

```

```solidity
File: StakePetManager.sol

73:         for (uint256 i = 0; i < _contractIDs.length; i++) {

75:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

108:         for (uint256 i = 0; i < _contractIDs.length; i++) {

110:             for (uint256 j = 0; j < _petIDs[i].length; j++) {

127:         for (uint256 i = 1; i <= currentPetId; i++) {

131:                 j++;

137:         for (uint256 i = 0; i < j; i++) {

147:         for (uint256 i = 0; i < _contractIDs.length; i++) {

```

**Client:** Fixed in [27225c2](https://github.com/Ranama/StakePet/commit/27225c256c3173cc306045949584b66be7f60c0f)

**Cyfrin:** Verified.

### Use shift Right/Left instead of division/multiplication if possible

```solidity
File: StakePet.sol

420:         if (_totalValueWantsClosedown <= totalValue() / 2) {

```

**Client:** Fixed in [540cca1](https://github.com/Ranama/StakePet/commit/540cca16669ee8575806d0f3430723726e3d9c2e)

**Cyfrin:** Verified.

### Use != 0 instead of > 0 for unsigned integer comparison

```solidity
File: StakePet.sol

269:         if (_amount > 0) {

299:         if (!petAlive && pet.ownership > 0) {

432:         if (totYield > 0) {

497:             if (_milkAmount > 0) {

541:         if (yieldToWithdraw > 0) {

558:                 require(yieldToWithdraw > 0); // This should never be hit and is maybe not needed, but just in case.

562:                 require(yieldToWithdraw > 0); // This should never be hit and is maybe not needed, but just in case.

709:         if (_totalYieldNoMilk > 0) {

723:         if (s_totalOwnership > 0) {

741:         if (s_totalOwnership > 0) {

```

```solidity
File: StakePetManager.sol

129:             if (!stakePetContract.alive(pet.lastProofOfLife) && pet.ownership > 0) {

```

**Client:** Fixed in [9e3d0d0](https://github.com/Ranama/StakePet/commit/9e3d0d0c1b6a324e22e0e3f70453c6d411cd9101)

**Cyfrin:** Verified.