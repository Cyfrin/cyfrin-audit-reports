**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**

[0kage](https://twitter.com/0kage_eth)


---

# Findings
## Medium Risk

### Use safe transfer for ERC20 tokens

**Severity:** Medium

**Description:** The protocol intends to support all ERC20 tokens but the implementation uses the original transfer functions.
Some tokens (like USDT) do not implement the EIP20 standard correctly and their transfer/transferFrom function return void instead of a success boolean. Calling these functions with the correct EIP20 function signatures will revert.

```solidity
TransferUtils.sol
34:     function _transferERC20(address token, address to, uint256 amount) internal {
35:         IERC20 erc20 = IERC20(token);
36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");
37:         uint256 initialBalance = erc20.balanceOf(to);
38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");//@audit-issue will revert for USDT
39:         uint256 balance = erc20.balanceOf(to);
40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");
41:     }
```

**Impact:** Tokens that do not correctly implement the EIP20 like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.

**Recommended Mitigation:** We recommend using OpenZeppelin's SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

**Protocol:** Fixed in commit [564f711](https://github.com/SwapExchangeio/Contracts/commit/564f711c6f915f5a7696739266a1f8059ee9a172)

**Cyfrin:** Verified.

### Fee-on-transfer tokens are not supported

**Severity:** Medium

**Description:** The protocol intends to support all ERC20 tokens but does not support fee-on-transfer tokens.
The protocol utilizes the functions `TransferUtils::_transferERC20()` and `TransferUtils::_transferFromERC20()` to transfer ERC20 tokens.

```solidity
TransferUtils.sol
34:     function _transferERC20(address token, address to, uint256 amount) internal {
35:         IERC20 erc20 = IERC20(token);
36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");
37:         uint256 initialBalance = erc20.balanceOf(to);
38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");
39:         uint256 balance = erc20.balanceOf(to);
40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");//@audit-issue reverts for fee on transfer token
41:     }
```

The implementation verifies that the transfer was successful by checking that the balance of the recipient is greater than or equal to the initial balance plus the amount transferred. This check will fail for fee-on-transfer tokens because the actual received amount will be less than the input amount. (Read [here](https://github.com/d-xo/weird-erc20#fee-on-transfer) about fee-on-transfer tokens)

Although there are very few fee-on-transfer tokens, the protocol can't say it supports all ERC20 tokens if it doesn't support these weird ERC20 tokens.

**Impact:** Fee-on-transfer tokens can not be used for the protocol.
Because of the rarity of these tokens, we evaluate this finding as a Medium risk.

**Recommended Mitigation:** The transfer utility functions can be updated to return the actually received amount.
Or clearly document that only standard ERC20 tokens are supported.

**Protocol:** We are choosing not to implement this at this stage.

**Cyfrin:** Acknowledged. As recommended, please mention this in user documentation.

### Centralization risk

**Severity:** Medium

**Description:** The protocol has an owner with privileged rights to perform admin tasks that can affect users.
Especially, the owner can change the fee settings and reward handler address.

1. Validation is missing for admin fee setter functions.

```solidity
FeeData.sol
31:     function setFeeValue(uint256 feeValue) external onlyOwner {
32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");
33:         _feeValue = feeValue;
34:     }

43:
44:     function setFixedFee(uint256 fixedFee) external onlyOwner {//@audit-issue validate min/max
45:         _fixedFee = fixedFee;
46:     }
```

2. Important changes initiated by admin should be logged via events.

```solidity
File: helpers/FeeData.sol

31:     function setFeeValue(uint256 feeValue) external onlyOwner {

36:     function setMaxHops(uint256 maxHops) external onlyOwner {

40:     function setMaxSwaps(uint256 maxSwaps) external onlyOwner {

44:     function setFixedFee(uint256 fixedFee) external onlyOwner {

48:     function setFeeToken(address feeTokenAddress) public onlyOwner {

53:     function setFeeTokens(address[] memory feeTokenAddresses) public onlyOwner {

60:     function clearFeeTokens() public onlyOwner {

```

```solidity
File: helpers/TransferHelper.sol

86:     function setRewardHandler(address rewardAddress) external onlyOwner {

92:     function setRewardsActive(bool _rewardsActive) external onlyOwner {

```

**Impact:** While the protocol owner is regarded as a trusted party, the owner can change the fee settings and reward handler address without any validation or logging. This can lead to unexpected results and users can be affected.

**Recommended Mitigation:**
- Specify the owner's privileges and responsibilities in the documentation.
- Add constant state variables that can be used as the minimum and maximum values for the fee settings.
- Add proper validation for the admin functions.
- Log the changes in the important state variables via events.

**Protocol:**

- setFeeNumerator changes fixed in commit [f8f07c5](https://github.com/SwapExchangeio/Contracts/commit/f8f07c5e72c052d11c1b4c4dfd8b849a99694e03)
- setFeeNumerator maximum reduced in commit [7874a8f](https://github.com/SwapExchangeio/Contracts/commit/7874a8f677b1e06e9b3e0289a91ab33e46806ff2)
- setFixedFee changes fixed in commit [af760b4](https://github.com/SwapExchangeio/Contracts/commit/af760b484ff6da0ad9a8492a96a5e7ef19056df1)
- events for setFeeToken/clearFeeToken/setFeeTokens as well as separating initialization setter to save emitting a heap of events when deploying, fixed in commit [927c102](https://github.com/SwapExchangeio/Contracts/commit/[927c1020a71c017d3a17e653be84996ba86ff8ed])
- changing array arg type to calldata rather than memory, fixed in commit [e615cb2](https://github.com/SwapExchangeio/Contracts/commit/e615cb21ac67d8a31656c622d3b2e3ddc1dc8891)
- events for RewardHandler and RewardsActive, fixed in commit [3068a2e](https://github.com/SwapExchangeio/Contracts/commit/3068a2e88621f991a54be80ef16d868e4fb10d25)
- events for MaxHops and MaxSwaps, fixed in commit [077577b](https://github.com/SwapExchangeio/Contracts/commit/077577ba26b66cbb4b977b3738b59eb727c5d87d).

**Cyfrin:** Verified.

## Low Risk

### Validation is missing for tokenA in `SwapExchange::calculateMultiSwap()`

**Severity:** Low

**Description:** The protocol supports claiming a chain of swaps and the function `SwapExchange::calculateMultiSwap()` is used to do some calculations including the amount of tokenA that can be received for a given amount of tokenB.
Looking at the implementation, the protocol does not validate that the tokenA of the last swap in the chain is actually the same as the tokenA of `multiClaimInput`.
Because this view function is supposed to be used by the frontend to 'preview' the result of a `MultiSwap`, this does not imply a direct security risk but can lead to unexpected results. (It is notable that the actual swap function `SwapExchange::_claimMultiSwap()` implemented a proper validation.)

```solidity
SwapExchange.sol
150:     function calculateMultiSwap(SwapUtils.MultiClaimInput calldata multiClaimInput) external view returns (SwapUtils.SwapCalculation memory) {
151:         uint256 swapIdCount = multiClaimInput.swapIds.length;
152:         if (swapIdCount == 0 || swapIdCount > _maxHops) revert Errors.InvalidMultiClaimSwapCount(_maxHops, swapIdCount);
153:         if (swapIdCount == 1) {
154:             SwapUtils.Swap memory swap = swaps[multiClaimInput.swapIds[0]];
155:             return SwapUtils._calculateSwapNetB(swap, multiClaimInput.amountB, _feeValue, _feeDenominator, _fixedFee);
156:         }
157:         uint256 matchAmount = multiClaimInput.amountB;
158:         address matchToken = multiClaimInput.tokenB;
159:         uint256 swapId;
160:         bool complete = true;
161:         for (uint256 i = 0; i < swapIdCount; i++) {
162:             swapId = multiClaimInput.swapIds[i];
163:             SwapUtils.Swap memory swap = swaps[swapId];
164:             if (swap.tokenB != matchToken) revert Errors.NonMatchingToken();
165:             if (swap.amountB < matchAmount) revert Errors.NonMatchingAmount();
166:             if (matchAmount < swap.amountB) {
167:                 if (!swap.isPartial) revert Errors.NotPartialSwap();
168:                 matchAmount = MathUtils._mulDiv(swap.amountA, matchAmount, swap.amountB);
169:                 complete = complete && false;
170:             }
171:             else {
172:                 matchAmount = swap.amountA;
173:             }
174:             matchToken = swap.tokenA;
175:         }
176:         (uint8 feeType,) = _calculateFeeType(multiClaimInput.tokenA, multiClaimInput.tokenB);//@audit-issue no validation matchToken == multiClaimInput.tokenA
177:         uint256 fee = FeeUtils._calculateFees(matchAmount, multiClaimInput.amountB, feeType, swapIdCount, _feeValue, _feeDenominator, _fixedFee);
178:         SwapUtils.SwapCalculation memory calculation;
179:         calculation.amountA = matchAmount;
180:         calculation.amountB = multiClaimInput.amountB;
181:         calculation.fee = fee;
182:         calculation.feeType = feeType;
183:         calculation.isTokenBNative = multiClaimInput.tokenB == Constants.NATIVE_ADDRESS;
184:         calculation.isComplete = complete;
185:         calculation.nativeSendAmount = SwapUtils._calculateNativeSendAmount(calculation.amountB, calculation.fee, calculation.feeType, calculation.isTokenBNative);
186:         return calculation;
187:     }
```

**Impact:** The function will return an incorrect swap calculation result if the last swap in the chain has a different tokenA than the tokenA of `multiClaimInput` and it can lead to unexpected results.

**Recommended Mitigation:** Add a validation that the tokenA of the last swap in the chain is the same as the tokenA of `multiClaimInput`.

**Protocol:** Fixed in commit [d3c758e](https://github.com/SwapExchangeio/Contracts/commit/d3c758e6c08f6be75bd420ffd8bf4de71a407897).

**Cyfrin:** Verified.

## Informational Findings

### Not proper variable naming

**Severity:** Informational

**Description:** The contract `FeeData` has a internal variable `_feeValue` that is used to calculate the fee.
Across the usage of this variable, it is used as a numerator while calculating the fee percentage.
We recommend renaming this variable to `feeNumerator` to avoid confusion.

```solidity
FeeUtils.sol
16:     function _calculateFees(uint256 amountA, uint256 amountB, uint8 feeType,  uint256 hops, uint256 feeValue, uint256 feeDenominator, uint256 fixedFee)
17:     internal pure returns (uint256) {
18:         if (feeType == Constants.FEE_TYPE_TOKEN_B) {
19:             return MathUtils._mulDiv(amountB, feeValue, feeDenominator) * hops;
20:         }
21:         if (feeType == Constants.FEE_TYPE_TOKEN_A) {
22:             return MathUtils._mulDiv(amountA, feeValue, feeDenominator) * hops;
23:         }
24:         if (feeType == Constants.FEE_TYPE_ETH_FIXED) {
25:             return fixedFee * hops;
26:         }
27:         revert Errors.UnknownFeeType(feeType);
28:     }
```

**Protocol:** Fixed in commit [f6154c9](https://github.com/SwapExchangeio/Contracts/commit/f6154c99edabe7b62d956935a94567c88ee89b3d).

**Cyfrin:** Verified.

### Unnecessary logical operation

**Severity:** Informational

**Description:** In the function `SwapExchange::calculateMultiSwap()` there is a logical operation that is not necessary in the for loop.

```solidity
SwapExchange.sol
161:         for (uint256 i = 0; i < swapIdCount; i++) {
162:             swapId = multiClaimInput.swapIds[i];
163:             SwapUtils.Swap memory swap = swaps[swapId];
164:             if (swap.tokenB != matchToken) revert Errors.NonMatchingToken();
165:             if (swap.amountB < matchAmount) revert Errors.NonMatchingAmount();
166:             if (matchAmount < swap.amountB) {
167:                 if (!swap.isPartial) revert Errors.NotPartialSwap();
168:                 matchAmount = MathUtils._mulDiv(swap.amountA, matchAmount, swap.amountB);
169:                 complete = complete && false;//@audit-issue INFO unnecessary operation, just set complete=false
170:             }
171:             else {
172:                 matchAmount = swap.amountA;
173:             }
174:             matchToken = swap.tokenA;
175:         }
```

**Protocol:** Fixed in commit [a079c11](https://github.com/SwapExchangeio/Contracts/commit/a079c11cc3bc044c61493040dab1f94de4a0f14a).

**Cyfrin:** Verified.

## Gas Optimizations

### Using bools for storage incurs overhead

Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from `false` to `true`, after having been `true` in the past. Check more [here](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

```solidity
File: helpers/FeeData.sol

18:     mapping(address => bool) public feeTokenMap;

```

```solidity
File: helpers/TransferHelper.sol

16:     bool public rewardsActive;

```

**Protocol:** Fixed in commits [2d48a4b](https://github.com/SwapExchangeio/Contracts/commit/2d48a4b7c371054207866f90b2cd98c98fb34d5a), [84dbd3a](https://github.com/SwapExchangeio/Contracts/commit/84dbd3aafa28ddad88ab1406d0946525f910a261).

**Cyfrin:** Verified.

### Cache array length outside of loop

If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

```solidity
File: SwapExchange.sol

403:         for (uint i = 0; i < swapIds.length; i++) {
```

```solidity
File: helpers/FeeData.sol

55:         for (uint i = 0; i < feeTokenAddresses.length; i++) {
61:         for (uint i = 0; i < feeTokenKeys.length; i++) {

```

**Protocol:** Fixed in commit [9ba2a93](https://github.com/SwapExchangeio/Contracts/commit/9ba2a93bdad911f541056ced4661bb2fce8db8e0)

**Cyfrin:** Verified.

### For Operations that will not overflow, you could use unchecked

```solidity
File: SwapExchange.sol

209:    ++recordCount;

254:    totalNativeSendAmount += calculation.nativeSendAmount;

407:    total += swap.amountA;

```

```solidity
File: libraries/SwapUtils.sol

93:             uint256 expectedValue = amount + fee;

```

**Protocol:** Fixed in commit [f7a5dac](https://github.com/SwapExchangeio/Contracts/commit/f7a5dac3141f71b06a6d4ad3e44d657bc55ee441).

**Cyfrin:** Verified.

### Use Custom Errors

Instead of using error strings, to reduce deployment and runtime cost, you should use Custom Errors. This would save both deployment and runtime cost. Read more [here](https://blog.soliditylang.org/2021/04/21/custom-errors/).

```solidity
File: helpers/FeeData.sol

32:         require(feeValue < _feeDenominator, "Fee percentage must be less than 1");

```

```solidity
File: helpers/TransferHelper.sol

20:         require(rewardAddress != address(0), "Reward Address is Invalid");

87:         require(rewardAddress != address(0), "Reward Address is Invalid");

98:         require(rewardHandler.logTokenFee(token, fee), "LogTokenFee failed");

103:         require(rewardHandler.logNativeFee(fee), "LogTNativeFee failed");

```

```solidity
File: libraries/TransferUtils.sol

36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");

38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");

40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");

45:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");

47:         require(erc20.transferFrom(from, to, amount), "ERC20 Transfer failed");

49:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");

54:         require(flag == true, "ETH transfer failed");

```

**Protocol:** Fixed in commit [ffe50aa](https://github.com/SwapExchangeio/Contracts/commit/ffe50aa913d373724ec12bc704387dfaefaab7a5) and [9ba796f](https://github.com/SwapExchangeio/Contracts/commit/9ba796f6ff0161376b254d80db55d3bc33414a30)

**Cyfrin:** Verified.

### Don't initialize variables with default value

```solidity
File: SwapExchange.sol

130:         for (uint256 i = 0; i < length; i++) {

161:         for (uint256 i = 0; i < swapIdCount; i++) {

247:         for (uint256 i = 0; i < length; i++) {

346:         for (uint256 i = 0; i < swapIdCount; i++) {

403:         for (uint i = 0; i < swapIds.length; i++) {

```

```solidity
File: helpers/FeeData.sol

55:         for (uint i = 0; i < feeTokenAddresses.length; i++) {

61:         for (uint i = 0; i < feeTokenKeys.length; i++) {

```

```solidity
File: libraries/Constants.sol

6:     uint8 public constant FEE_TYPE_ETH_FIXED = 0;

```

**Protocol:** Fixed for for-loops in commit 83ffebcc099da256ec53644afc733eab2586c636.

**Cyfrin:** Verified.

### `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)

```solidity
File: SwapExchange.sol

130:         for (uint256 i = 0; i < length; i++) {

161:         for (uint256 i = 0; i < swapIdCount; i++) {

247:         for (uint256 i = 0; i < length; i++) {

346:         for (uint256 i = 0; i < swapIdCount; i++) {

403:         for (uint i = 0; i < swapIds.length; i++) {

```

```solidity
File: helpers/FeeData.sol

55:         for (uint i = 0; i < feeTokenAddresses.length; i++) {

61:         for (uint i = 0; i < feeTokenKeys.length; i++) {

```

**Protocol:** Fixed in commit [5662786](https://github.com/SwapExchangeio/Contracts/commit/5662786421251a32444427d4ede74100a4c772f0).

**Cyfrin:** Verified.

### Use != 0 instead of > 0 for unsigned integer comparison

```solidity
File: helpers/FeeData.sol

64:         while (feeTokenKeys.length > 0) {

```

```solidity
File: libraries/SwapUtils.sol

96:         else if (sentAmount > 0) {

```

**Protocol:** Fixed in commit [4679de1](https://github.com/SwapExchangeio/Contracts/commit/4679de1c3f8adfc4122698fc82a529322ba4b5ed).

**Cyfrin:** Verified.