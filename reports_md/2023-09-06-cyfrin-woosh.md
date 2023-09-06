**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**

[0kage](https://twitter.com/0kage_eth)


---

# Findings
## Medium Risk
### Non-standard ERC20 tokens are not supported
**Severity:** Medium

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-xo/weird-erc20) about the non-standard weird ERC20 tokens)

For example, if token incurs fee on transfer, the actually transferred amount will be less than the provided parameter `amount` and the `deposits` will have a wrong state value. Because the current implementation only allows full withdrawal, this means the tokens will be locked in the contract permanently.

**Impact:** If non-standard ERC20 tokens are used, the tokens could be locked in the contract permanently.

**Recommended Mitigation:**
- We recommend adding another field in the `Deposit` structure, say `balance`
- We recommend allow users to withdraw partially and decrease the `balance` field appropriately for successful withdrawals.
If these changes are going to be made, we note that there are other parts that need changes. For example, the withdraw function would need to be updated so that it does not require the withdrawal amount is same to the original deposit amount.

**Protocol:**
Contract updated to support non-standard ERC-20 tokens. We've decided to not allow users to partially withdraw since it would complicate the logic of the signatures, as of now only full withdraws can be executed.

**Cyfrin:** Verified in commit [405fa78](https://github.com/HyperGood/woosh-contracts/commit/405fa78a2c0cf8b8ab8943484cb95b5c8807cbfb).

### Use call instead of transfer
**Severity:** Medium

**Description:** In both of the withdraw functions, `transfer()` is used for native ETH withdrawal.
The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

**Impact:** The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:
- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.

Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.

**Recommended Mitigation:** Use call() instead of transfer().

**Protocol:**
Agree, transfer was causing issues with smart contract wallets.

**Cyfrin:** Verified in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

## Low Risk
### The deposit function is not following CEI pattern
**Severity:** Low

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);//@audit-issue against CEI pattern
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L47, we can see that the token transfer happens before updating the accounting state of the protocol against the CEI pattern.
Because the protocol intends to support all ERC20 tokens, the tokens with hooks (e.g. ERC777) can be exploited for reentrancy.
Although we can not verify an exploit that causes explicit loss due to this, it is still highly recommended to follow CEI pattern to prevent possible reentrancy attack.

**Recommended Mitigation:** Handle token transfers after updating the `deposits` state.

**Protocol:**
Fixed in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

**Cyfrin:** We note that the protocol still does not follow CEI pattern in the final commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).
But we also acknowledge that the fix in [405fa78](https://github.com/HyperGood/woosh-contracts/commit/405fa78a2c0cf8b8ab8943484cb95b5c8807cbfb) to support non-standard ERC20 tokens makes it impossible to follow CEI pattern.
For the current implementation, we verified that there is no reentrancy attack vector due to this issue. If the protocol intends any upgrades in the future related to the `deposits` state, we recommend using [OpenZeppelin's ReentrancyGuard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/8a0b7bed82d6b8053872c3fd40703efd58f5699d/contracts/security/ReentrancyGuard.sol#L22) to prevent possible reentrancy attack.
Please note that the lack of CEI pattern will still be problematic in the sense of [Read-only reentrancy](https://officercia.mirror.xyz/DBzFiDuxmDOTQEbfXhvLdK0DXVpKu1Nkurk0Cqk3QKc) if the states `deposits` are going to be utilized for any other purposes.

## Informational Findings
### Nonstandard usage of nonce
**Severity:** Informational

**Description:** The protocol implemented two withdraw functions `withdrawDeposit()` and `withdraw()`.
While the function `withdrawDeposit()` is designed to be used by the depositor themselves, the function `withdraw()` is designed to be used by anyone who has a signature from the depositor.
The function `withdraw()` has a parameter `nonce` but the usage of this param is not aligned with the general meaning of nonce.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];//@audit-info non aligned with common understanding of nonce
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:         }
77:
78:         emit WithdrawalMade(recipient, amount);
79:     }
```
In common usage, nonce is used to track the latest transaction from the EOA and generally it is increased on the user's transaction. It can be effectively used to invalidate the previous signature by the signer.
But looking at the current implementation, the parameter `nonce` is merely used as an index to refer the `deposit` at a specific index.

This is a bad naming and can confuse the users.

**Recommended Mitigation:** If the protocol intended to provide a kind of invalidation mechanism using the nonce, there should be a separate mapping that stores the nonce for each user. The current nonce can be used to generate a signature and a depositor should be able to increase the nonce to invalidate the previous signatures. Also the nonce would need to be increased on every successful call to `withdraw()` to prevent replay attack.
Please note that with this remediation, the mapping `usedWithdrawalHashes` can be removed completely because the hash will be always decided using the latest nonce and the nonce will be invalidated automatically (because it increases on successful call).

If this is not what the protocol intended, the parameter nonce can be renamed to `depositIndex` as implemented in the function `withdrawDeposit()`.

**Client:**
Fixed in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

**Cyfrin:** Verified.

### Unnecessary parameter amount in withdraw function

**Severity:** Informational

**Description:** The function `withdraw()` has a parameter `amount` but we don't understand the necessity of this parameter.
At line L67, the amount is required to be the same to the whole deposit amount. This means the user does not have a flexibility to choose the withdraw amount, after all it means the parameter was not necessary at all.
```solidity
DepositVault.sol
59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public {
60:         require(nonce < deposits.length, "Invalid deposit index");
61:         Deposit storage depositToWithdraw = deposits[nonce];
62:         bytes32 withdrawalHash = getWithdrawalHash(Withdrawal(amount, nonce));
63:         address signer = withdrawalHash.recover(signature);
64:         require(signer == depositToWithdraw.depositor, "Invalid signature");
65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");
66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");//@audit-info only full withdrawal is allowed
67:
68:         usedWithdrawalHashes[withdrawalHash] = true;
69:         depositToWithdraw.amount = 0;
70:
71:         if(depositToWithdraw.tokenAddress == address(0)){
72:             recipient.transfer(amount);
73:         } else {
74:             IERC20 token = IERC20(depositToWithdraw.tokenAddress);
75:             token.safeTransfer(recipient, amount);
76:         }
77:
78:         emit WithdrawalMade(recipient, amount);
79:     }
```

**Recommended Mitigation:** If the protocol intends to only allow full withdrawal, this parameter can be removed completely (that will help save gas as well).
Unnecessary parameters increase the complexity of the function and more error prone.

**Client:**
Agreed, only full withdraws are allowed. Removed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

### Functions not used internally could be marked external

**Severity:** Informational

**Description:** Using proper visibility modifiers is a good practice to prevent unintended access to functions.
Furthermore, marking functions as `external` instead of `public` can save gas.

```solidity
File: DepositVault.sol

37:     function deposit(uint256 amount, address tokenAddress) public payable

59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public

81:     function withdrawDeposit(uint256 depositIndex) public
```

**Recommended Mitigation:** Consider change the visibility modifier to `external` for the functions that are not used internally.

**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

## Gas Optimizations
### Use assembly to check for `address(0)`
Saves 6 gas per instance

```solidity
File: DepositVault.sol

40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");

45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");

71:         if(depositToWithdraw.tokenAddress == address(0)){

90:         if(depositToWithdraw.tokenAddress == address(0)){

```
**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).

### Use calldata instead of memory for function arguments that do not get mutated
Mark data types as `calldata` instead of `memory` where possible. This makes it so that the data is not automatically loaded into memory. If the data passed into the function does not need to be changed (like updating values in an array), it can be passed in as `calldata`. The one exception to this is if the argument must later be passed into another function that takes an argument that specifies `memory` storage.

```solidity
File: DepositVault.sol

55:     function getWithdrawalHash(Withdrawal memory withdrawal) public view returns (bytes32)

59:     function withdraw(uint256 amount, uint256 nonce, bytes memory signature, address payable recipient) public

```
**Client:**
Acknowledged.

**Cyfrin:** Acknowledged.

### Use Custom Errors

Instead of using error strings, to reduce deployment and runtime cost, you should use [Custom Errors](https://blog.soliditylang.org/2021/04/21/custom-errors/). This would save both deployment and runtime cost.

```solidity
File: DepositVault.sol

38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");

40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");

45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");

60:         require(nonce < deposits.length, "Invalid deposit index");

64:         require(signer == depositToWithdraw.depositor, "Invalid signature");

65:         require(!usedWithdrawalHashes[withdrawalHash], "Withdrawal has already been executed");

66:         require(amount == depositToWithdraw.amount, "Withdrawal amount must match deposit amount");

82:         require(depositIndex < deposits.length, "Invalid deposit index");

84:         require(depositToWithdraw.depositor == msg.sender, "Only the depositor can withdraw their deposit");

85:         require(depositToWithdraw.amount > 0, "Deposit has already been withdrawn");

```
**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).


### Use != 0 instead of > 0 for unsigned integer comparison

```solidity
File: DepositVault.sol

38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");

38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");

39:         if(msg.value > 0)

85:         require(depositToWithdraw.amount > 0, "Deposit has already been withdrawn");

```

**Client:**
Fixed.

**Cyfrin:** Verified in commit [b21d23e](https://github.com/HyperGood/woosh-contracts/commit/b21d23e661b0f25f0e757dc00ee90e4464730b1b).