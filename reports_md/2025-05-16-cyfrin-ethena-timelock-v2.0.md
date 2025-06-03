**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Hans](https://x.com/hansfriese)
**Assisting Auditors**

[Alex Roan](https://twitter.com/alexroan)

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

---

# Findings
## Low Risk


### Only allow execution if value parameters match `msg.value` to prevent eth remaining in the `EthenaTimelockController` contract

**Description:** `EthenaTimelockController::execute` and `executeWhitelistedBatch` allow execution without checking that the `msg.value` is equal to the input `value`/`values` parameters.

This can result in eth being temporarily stuck in the contract, though it can be "rescued" by doing a follow-up execution with zero `msg.value` but non-zero `value` input.

**Recommended Mitigation:** Enforce an invariant that the `EthenaTimelockController` should never finish a transaction with a positive ETH balance by:
* in `execute` revert if `msg.value != value`
* in `executeWhitelistedBatch` revert if `msg.value != sum(values)`

The idea being that every execution should use all of the input `msg.value` and no eth from any execution should remain in the `EthenaTimelockController` contract.

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79) by enforcing this invariant in `execute`, `executeBatch` and `executeWhitelistedBatch`.

**Cyfrin:** Verified.


### Re-entrancy protection can be evaded via `TimelockController::executeBatch`

**Description:** `EthenaTimelockController::execute` overrides `TimelockController::execute` and adds a `nonReentrant` modifier to prevent re-entrant calls back into it.

However `TimelockController::executeBatch` is not overridden so re-entrancy can still occur that way. Beyond the re-entrancy evasion this doesn't appear further exploitable.

**Proof Of Concept:**
In `test/EthenaTimelockController.t.sol`, change `MaliciousReentrant::maliciousExecute` to:
```solidity
function maliciousExecute() external {
    if (!reentered) {
        reentered = true;
        // re-enter the timelock through executeBatch
        bytes memory data = abi.encodeWithSignature("maliciousFunction()");
        address[] memory targets = new address[](1);
        targets[0] = address(this);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = data;
        timelock.executeBatch(targets, values, payloads, bytes32(0), bytes32(0));
    }
}
```

Then run the relevant test: `forge test --match-test testExecuteWhitelistedReentrancy -vvv` and see that the test fails because the expected re-entrancy error no longer gets thrown.

**Recommended Mitigation:** Override `TimelockController::executeBatch` in `EthenaTimelockController` to add `nonReentrant` modifier then call the parent function.

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bR147).

**Cyfrin:** Verified.


### `TimelockController` won't revert when executing on non-existent contracts

**Description:** `TimelockController::_execute` does this:
```solidity
function _execute(address target, uint256 value, bytes calldata data) internal virtual {
    (bool success, bytes memory returndata) = target.call{value: value}(data);
    Address.verifyCallResult(success, returndata);
}
```

If `target` is a non-existent contract but `data` contains a valid expected function call with parameters, the `call` will return `true`; `Address.verifyCallResult` fails to catch this case.

**Proof Of Concept:**
Add PoC function to `test/EthenaTimelockController.sol`:
```solidity
function testExecuteNonExistentContract() public {
    bytes memory data = abi.encodeWithSignature("DONTEXIST()");
        _scheduleWaitExecute(address(0x1234), data);
}
```

Run with: `forge test --match-test testExecuteNonExistentContract -vvv`

**Recommended Mitigation:** We reported this bug to OpenZeppelin but they said they prefer the current implementation as it is more flexible. We disagree with this assessment and believe it is incorrect for `TimelockController::_execute` to not revert when there is valid calldata but the target has no code.

**Ethena:** Fixed in commit [e58c547](https://github.com/ethena-labs/timelock-contract/commit/e58c547e3bcbea79d9df7121b5bb04626a2b72e0#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bR191-R197) by overriding `_execute` to revert if `data.length > 0 && target.code.length == 0`.

**Cyfrin:** Verified.


### `EthenaTimelockController::addToWhitelist` and `removeFromWhitelist` don't revert for non-existent `target` address

**Description:** `EthenaTimelockController::addToWhitelist` and `removeFromWhitelist` should revert if the `target` address doesn't exist (has no code).

**Proof of Concept:** Add PoC function to `test/EthenaTimelockController.t.sol`:
```solidity
function testAddNonExistentContractToWhitelist() public {
    bytes memory addToWhitelistData = abi.encodeWithSignature(
        "addToWhitelist(address,bytes4)", address(0x1234), bytes4(keccak256("DONTEXIST()"))
    );
    _scheduleWaitExecute(address(timelock), addToWhitelistData);
}
```

Run with: `forge test --match-test testAddNonExistentContractToWhitelist -vvv`

**Recommended Mitigation:** Revert if `target.code.length == 0`.

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bR6-R76) to not allow whitelisting of targets with no code.

**Cyfrin:** Verified.

\clearpage
## Informational


### Use named imports

**Description:** Use named imports:
```diff
- import "@openzeppelin/contracts/governance/TimelockController.sol";
- import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
+ import {TimelockController, Address} from "@openzeppelin/contracts/governance/TimelockController.sol";
+ import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
```

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bL4-R5).

**Cyfrin:** Verified.


### Use named mappings

**Description:** Use named mappings to explicitly indicate the purpose of keys and values:
```diff
-    mapping(address => mapping(bytes4 => bool)) private _functionWhitelist;
+    mapping(address target => mapping(bytes4 selector => bool allowed)) private _functionWhitelist;
```

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bL28-R29).

**Cyfrin:** Verified.


### Don't allow initially granting `EXECUTOR_ROLE` or `WHITELISTED_EXECUTOR_ROLE` to `address(0)`

**Description:** The client has stated that initially they want the `EXECUTOR_ROLE` to be closed and that in the future they may open this up.

Hence `EthenaTimelockController::constructor` should revert if any elements in the `executors` or `whitelistedExecutors` input arrays is `address(0)`.

**Ethena:** Acknowledged; we prefer to keep the optionality here.


### Only emit events if state actually changes

**Description:** A number of functions in `EthenaTimelockController` will emit events even if the state did not change since they simply write to storage but don't read the current storage value to check if it is changing.

Ideally these functions would revert or at least not emit events if the state did not change:
* `addToWhitelist`
* `removeFromWhitelist`

**Ethena:** Acknowledged.

\clearpage
## Gas Optimization


### Use `ReentrancyGuardTransient` for more efficient `nonReentrant` modifiers

**Description:** Use [`ReentrancyGuardTransient`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) for more efficient `nonReentrant` modifiers:
```diff
- import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
+ import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

- contract EthenaTimelockController is TimelockController, ReentrancyGuard {
+ contract EthenaTimelockController is TimelockController, ReentrancyGuardTransient {
```

**Ethena:** Fixed in commit [89d4190](https://github.com/ethena-labs/timelock-contract/commit/89d41901be3387c11c2150c19eb99883ed807d79#diff-8ca72e61ebf9a693737b5c9052aa3814e8b291e3d6dd0341fe88b5b5e781427bR5-R19).

**Cyfrin:** Verified.

\clearpage