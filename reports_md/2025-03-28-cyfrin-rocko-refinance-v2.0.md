**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Hans](https://x.com/hansfriese)
**Assisting Auditors**



---

# Findings
## Low Risk


### Protocol fee should round up in favor of the protocol

**Description:** Protocol fee should round up in favor of the protocol in `onMorphoFlashLoan`:
```solidity
uint256 rockoFeeBP = ROCKO_FEE_BP;
if (rockoFeeBP > 0) {
    unchecked {
        feeAmount = (flashBorrowAmount * rockoFeeBP) / BASIS_POINTS_DIVISOR;
        borrowAmountWithFee += feeAmount;
    }
}
```

Consider [using](https://x.com/DevDacian/status/1892529633104396479) OpenZeppelin [`Math::mulDiv`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/fda6b85f2c65d146b86d513a604554d15abd6679/contracts/utils/math/Math.sol#L280) with the rounding parameter or Solady [`FixedPointMathLib::fullMulDivUp`](https://github.com/Vectorized/solady/blob/c9e079c0ca836dcc52777a1fa7227ef28e3537b3/src/utils/FixedPointMathLib.sol#L548).

Another benefit of using these libraries is that intermediate overflow from the multiplication of `flashBorrowAmount * rockoFeeBP` is avoided.

**Rocko:** Fixed in commit [a59ba0e](https://github.com/getrocko/onchain/commit/a59ba0e7958c544ad95788ce29923a342a2ea35a).

**Cyfrin:** Verified.


### Refinancing reverts for `USDT` debt token

**Description:** Refinancing reverts for `USDT` debt token due to the way protocol uses standard `IERC20::approve` and `transfer` functions.

**Impact:** Refinancing is bricked for `USDT` debt tokens. Marked as Low severity as officially only `USDC` is supported at this time. Note the implementation of `USDT` is different across chains; the protocol "as-is" would work with `USDT` on Base but not on Ethereum mainnet.

**Proof of Concept:** As part of the audit we have provided a fork fuzz testing suite; run this command: `forge test --fork-url ETH_RPC_URL --fork-block-number 22000000 --match-test test_FuzzRefinance_AaveToCompound_DepWeth_BorUsdt -vvv`

**Recommended Mitigation:** Replace all uses of `IERC20::approve` with [`SafeERC20::forceApprove`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol#L101-L108) and `IERC20::transfer` with `SafeERC20::safeTransfer` at L738, then re-run the PoC test and it now passes.

Ideally for added safety to prevent front-running of changes to existing approvals, use [`SafeERC20::safeIncreaseAllowance`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol#L68-L71) and [`safeDecreaseAllowance`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol#L82-L90) where suitable (for example in `_revokeTokenSpendApprovals` when the previous allowance amount is known could instead use `safeDecreaseAllowance`).

**Rocko:** Fixed in commit [751e906](https://github.com/getrocko/onchain/commit/751e906b7c2df6cb587e709b12de25593eb02c75).

**Cyfrin:** Verified.

\clearpage
## Informational


### Error messages hardcode `USDC` but other debt tokens may be used

**Description:** Error messages hardcode `USDC` but other token may be used, eg:
```solidity
function _closeLoanPositionAndReturnCollateralBalance(
    // @audit debt token can be other tokens apart from USDC but error
    // message hardcodes USDC
    require(
        debtBalance <= IERC20(debtTokenAddress).balanceOf(FLASH_LOAN_CONTRACT),
        "Insufficient USDC available in the flash contract"
    );
```

This code in `onMorphoFlashLoan` also assumes the debt token will be USDC:
```solidity
uint256 usdcBalance = IERC20(ctx.debtTokenAddress).balanceOf(FLASH_LOAN_CONTRACT);
bool feeAmountAvailable = usdcBalance >= feeAmount;
```

**Rocko:** Fixed in commit [ec9f5be](https://github.com/getrocko/onchain/commit/ec9f5be20f9249cd20fcc1e173192361ecd97ef5).

**Cyfrin:** Verified.


### Events missing indexed parameters

**Description:** Events in Solidity can have up to three indexed parameters, which are stored as topics in the event log. Indexed parameters allow for efficient filtering and searching of events by off-chain services. Without indexed parameters, it becomes more difficult and resource-intensive for applications to filter for specific events.

There are instances of events missing indexed parameters that could be improved.
```solidity
    event LogRefinanceLoanCall(
        string logType,
        address rockoWallet,
        string from,
        string to,
        uint256 debtBalance,
        address debtTokenAddress,
        address collateralTokenAddress,
        address aCollateralTokenAddress,
        Id morphoMarketId
    );
    event LogFlashLoanCallback(
        string logType,
        address rockoWallet,
        string from,
        string to,
        address debtTokenAddress,
        address collateralTokenAddress,
        address aCollateralTokenAddress,
        uint256 flashBorrowAmount,
        bytes data,
        Id morphoMarketId
    );
```

**Recommended Mitigation:** Add the `indexed` keyword to important parameters in the event that would commonly be used for filtering, such as `rockoWallet`, `debtTokenAddress`, and `collateralTokenAddress`.

**Rocko:** Fixed in commit [f5c9c80](https://github.com/getrocko/onchain/commit/f5c9c8051d5ba1bf04774ae6e8aa407aeddbcde1).

**Cyfrin:** Verified.


### Unnecessary event emission when configuration values do not change

**Description:** `RockoFlashRefinance::updateFee` updates the `ROCKO_FEE_BP` variable and emits a `FeeUpdated` event regardless of whether the new fee value is different from the current one. This leads to unnecessary event emissions when the owner calls the function with the same fee value that is already set.
The function `pauseContract` can be improved similarly too.

**Rocko:** Fixed in commit [99a73dc](https://github.com/getrocko/onchain/commit/99a73dc20fce34811c224fdd46b7e173748bfeb8).

**Cyfrin:** Verified.


### Inconsistent implementation approach for retrieving collateral balance from Morpho

**Description:** `RockoFlashRefinance::_collateralBalanceOfMorpho` uses direct storage slot access to retrieve a user's collateral balance from Morpho, while similar functionality for debt retrieval is implemented using `MorphoLib`. This inconsistency in the implementation approach makes the code less readable and maintainable.
```solidity
    function _collateralBalanceOfMorpho(
        Id morphoMarketId,
        address rockoWallet
    ) private view returns (uint256 totalCollateralAssets) {//@audit-issue use MorphoLib::collateral instead
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = MorphoStorageLib.positionBorrowSharesAndCollateralSlot(morphoMarketId, rockoWallet);
        bytes32[] memory values = MORPHO.extSloads(slots);
        totalCollateralAssets = uint256(values[0] >> 128);
    }

    function _getMorphoDebtAndShares(Id marketId, address rockoWallet) private returns (uint256 debt, uint256 shares) {
        MarketParams memory marketParams = MORPHO.idToMarketParams(marketId);
        MORPHO.accrueInterest(marketParams);

        uint256 totalBorrowAssets = MORPHO.totalBorrowAssets(marketId);
        uint256 totalBorrowShares = MORPHO.totalBorrowShares(marketId);
        shares = MORPHO.borrowShares(marketId, rockoWallet);
        debt = shares.toAssetsUp(totalBorrowAssets, totalBorrowShares);
    }
```

**Recommended Mitigation:** Refactor `_collateralBalanceOfMorpho` to use `MorphoLib::collateral` for consistency with other parts of the codebase:

```diff
function _collateralBalanceOfMorpho(
    Id morphoMarketId,
    address rockoWallet
) private view returns (uint256 totalCollateralAssets) {
-    bytes32[] memory slots = new bytes32[](1);
-    slots[0] = MorphoStorageLib.positionBorrowSharesAndCollateralSlot(morphoMarketId, rockoWallet);
-    bytes32[] memory values = MORPHO.extSloads(slots);
-    totalCollateralAssets = uint256(values[0] >> 128);
+    totalCollateralAssets = MorphoLib.collateral(MORPHO, morphoMarketId, rockoWallet);
}
```

**Rocko:** Fixed in commit [5ef86b4](https://github.com/getrocko/onchain/commit/5ef86b44063a988afed93fe3f69074be757768bd).

**Cyfrin:** Verified.


### Insufficient data length validation in `onMorphoFlashLoan`

**Description:** `RockoFlashRefinance::onMorphoFlashLoan` performs a basic check on the length of the `data` parameter, requiring it to be at least 20 bytes. However, this check is insufficient as the actual data being sent is much larger, containing multiple addresses, strings, and an Id parameter. The minimum expected data length should be at least 256 bytes plus additional bytes for dynamic string data.

**Recommended Mitigation:**
```diff
-        require(data.length >= 20, "Invalid data");
+        require(data.length >= 256, "Invalid data");
```

**Rocko:** Fixed in commit [1da67d7](https://github.com/getrocko/onchain/commit/1da67d7f3ae8076a6cc135ef9a6e5595ad6e29a2).

**Cyfrin:** Verified.


### In `_withdrawAaveCollateral` fetch `aTokenAddress` from Aave instead of receiving as input in `refinance` as passing it to morpho and back again

**Description:** Aave's `aTokenAddress` is only required when withdrawing collateral in `_withdrawAaveCollateral`, but currently it is:
* passed in as input to `refinance`
* has some validation performed on it
* encoded along with other data and sent to `Morpho::flashLoan`
* then Morpho passes it back when calling `onMorphoFlashLoan`
* where it is decoded again and passed around some more

Instead of all this, simply use Aave's API function [`IPool::getReserveData`](https://github.com/aave/aave-v3-core/blob/782f51917056a53a2c228701058a6c3fb233684a/contracts/interfaces/IPool.sol#L582) to get the correct `aTokenAddress` inside `_withdrawAaveCollateral` where it is required:
```solidity
    function _withdrawAaveCollateral(
        address collateralAddress,
        uint256 collateralBalance,
        address rockoWallet
    ) private {
        DataTypes.ReserveData memory reserveData = AAVE.getReserveData(collateralAddress);

        // Rocko Wallet needs to send aToken here after debt is paid off
        // Be sure that Rocko Wallet has approved this contract to spend aTokens for > `collateralBalance` tokens
        _pullTokensFromCallerWallet(reserveData.aTokenAddress, rockoWallet, collateralBalance);

        // function withdraw(address asset, uint256 amount, address to)
        AAVE.withdraw(collateralAddress, collateralBalance, FLASH_LOAN_CONTRACT);
    }
```

Fetching this parameter via Aave's API removes unnecessary code/validations also decreases the attack surface.

**Rocko:** Fixed in commit [d793f96](https://github.com/getrocko/onchain/commit/d793f960598240fa3eacdc6a4ec67d55dcfa2a75).

**Cyfrin:** Verified.


### Provide a way for users to revoke all approvals

**Description:** `RockoFlashRefinance` is designed to move existing loan positions from one lending protocol to another. On behalf of the user the contract must be able to:
* close the loan from the previous lending provider
* open a new loan on the new lending provider

For Aave, users must allow the refinance contract to spend the [AToken](https://github.com/aave/aave-v3-core/blob/master/contracts/protocol/tokenization/AToken.sol) to close the position and to spend the [VariableDebtToken](https://github.com/aave/aave-v3-core/blob/master/contracts/protocol/tokenization/VariableDebtToken.sol) to open a new position.

For Compound (Comet), users must allow the refinance contract by calling the [allow function](https://github.com/compound-finance/comet/blob/68cd639c67626c86e890e5aac775ad4b6405d923/contracts/CometExt.sol#L162C14-L162C19).

For Morpho, users must authorize the refinance protocol by calling the [setAuthorization](https://github.com/morpho-org/morpho-blue/blob/9e2b0755b47bbe5b09bf1be8f00e060d4eab6f1c/src/Morpho.sol#L437C14-L437C30) function.

The protocol team provided their frontend source related to these approvals and there were only "approving" support, not revoking. It is recommended to provide an easy way for users to revoke all these approvals.

**Rocko:** Users revokes will be included in the batch transaction when called from the Rocko app.


### Consider allowing update to `AAVE_DATA_PROVIDER`

**Description:** `RockoFlashRefinance::AAVE_DATA_PROVIDER` immutably stores the address of `AaveProtocolDataProvider`. However `AaveProtocolDataProvider` is not upgradeable and the "current" one on mainnet was deployed 43 days ago to address 0x497a1994c46d4f6C864904A9f1fac6328Cb7C8a6.

Hence consider whether `AAVE_DATA_PROVIDER` should not be `immutable` and an `onlyOwner` function should exist to allow updating it in the future.

Since `RockoFlashRefinance` has no relevant internal state it can just be re-deloyed. The trade-off is having  `immutable` `AAVE_DATA_PROVIDER` means user transactions involving it cost slightly less gas but the contract needs to be re-deployed to update it.

**Rocko:** Acknowledged; prefer the current setup for lower user gas costs.

\clearpage
## Gas Optimization


### Use `ReentrancyGuardTransient` instead of `ReentrancyGuard` or more gas-efficient `nonReentrant` modifiers

**Description:** Use [`ReentrancyGuardTransient`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) instead of `ReentrancyGuard` for more gas-efficient `nonReentrant` modifiers. The OpenZeppelin version would need to be bumped to 5.1.

**Rocko:** Fixed in commit [675f4b2](https://github.com/getrocko/onchain/commit/675f4b2e59cddf6c3f9f2e866f4401564bd0a006).

**Cyfrin:** Verified.


### Remove obsolete check in `updateFee`

**Description:** Remove obsolete check in `updateFee`:
```diff
-        require(newFee >= 0, "Fee must not be negative");
```

This check is obsolete since `newFee` is declared as `uint256` therefore cannot be negative.

**Rocko:** Fixed in commit [2c50838](https://github.com/getrocko/onchain/commit/2c50838a5cc5e498a14874a5d3348da20087e6bc).

**Cyfrin:** Verified.


### Use `msg.sender` instead of `owner()` inside `onlyOwner` functions

**Description:** Using `msg.sender` instead of `owner()` inside `onlyOwner` functions is more efficient as it eliminates reading from storage. It is also safe since the `onlyOwner` modifier ensures that `msg.sender` is the owner:
```solidity
757:        IERC20(tokenAddress).safeTransfer(owner(), amount);
766:        (bool success, ) = owner().call{ value: amount }("");
```

**Rocko:** Fixed in commit [751e906](https://github.com/getrocko/onchain/commit/751e906b7c2df6cb587e709b12de25593eb02c75).

**Cyfrin:** Verified.


### Prevent repetitive hashing of identical strings

**Description:** `RockoFlashRefinance::_compareStrings` is often called with the same values resulting in duplicate unnecessary work. A simple and more efficient way to prevent this is by first performing the conversion using `_parseProtocol` for both `from`/`to` inputs then simply comparing the enums as needed in functions like `refinance` and `_revokeTokenSpendApprovals`.

If string comparisons are required:
* hard-code the hash result as `bytes32` constants for common expected strings such as "aave", "morpho", "compound" and using these hard-coded constants inside `_parseProtocol` and other functions
* in functions such as `RockoFlashRefinance::refinance`, cache the hash of the `from`/`to` inputs in local `bytes32` variables and use the cached hashes and the hard-coded constants for the comparisons

One simple way to achieve this is by:
* defining a function to return the hash of a string:
```solidity
    function _hashString(string calldata input) private pure returns (bytes32 output) {
        output = keccak256(bytes(input));
    }
```
* changing `_compareStrings` to take two `bytes32` as input:
```solidity
    function _compareStrings(bytes32 a, bytes32 b) private pure returns (bool) {
        return a == b;
    }
```

Consider OpenZeppelin's string equality [implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Strings.sol#L134-L136) as well.

**Rocko:** Fixed in commit [a59ba0e](https://github.com/getrocko/onchain/commit/a59ba0e7958c544ad95788ce29923a342a2ea35a).

**Cyfrin:** Verified.


### Don't initialize to default values

**Description:** Don't initialize to default values as Solidity already does this:
```solidity
78:        ROCKO_FEE_BP = 0;
597:        uint256 debtBalance = 0;
598:        uint256 morphoDebtShares = 0;
```

**Rocko:** Fixed in commit [751e906](https://github.com/getrocko/onchain/commit/751e906b7c2df6cb587e709b12de25593eb02c75).

**Cyfrin:** Verified.


### Use named return variables to eliminate redundant local variables and `return` statements

**Description:** Use named return variables to eliminate redundant local variables and `return` statements:
```diff
// _closeLoanPositionAndReturnCollateralBalance L457
-    ) private returns (uint256) {
+    ) private returns (uint256 collateralBalance) {

// L464
-        uint256 collateralBalance;

// L480
-        return collateralBalance;
```

Same idea can be applied to `_collateralBalanceOfAave`, `_getDebtBalanceOfAave`.

**Rocko:** Fixed in commit [751e906](https://github.com/getrocko/onchain/commit/751e906b7c2df6cb587e709b12de25593eb02c75).

**Cyfrin:** Verified.


### Remove redundant `onBehalfOf` variables

**Description:** Remove redundant `onBehalfOf` variables:
```diff
    function _supplyToAave(address collateralAddress, uint256 collateralBalance, address rockoWallet) private {
-       address onBehalfOf = rockoWallet;
-       AAVE.supply(collateralAddress, collateralBalance, onBehalfOf, AAVE_REFERRAL_CODE);
+       AAVE.supply(collateralAddress, collateralBalance, rockoWallet, AAVE_REFERRAL_CODE);
    }
    function _borrowFromAave(address rockoWallet, address token, uint256 borrowAmount) private {
-       address onBehalfOf = rockoWallet;
-       AAVE.borrow(token, borrowAmount, AAVE_INTERESTE_RATE_MODE, AAVE_REFERRAL_CODE, onBehalfOf);
+       AAVE.borrow(token, borrowAmount, AAVE_INTERESTE_RATE_MODE, AAVE_REFERRAL_CODE, rockoWallet);
    }
```

**Rocko:** Fixed in commit [751e906](https://github.com/getrocko/onchain/commit/751e906b7c2df6cb587e709b12de25593eb02c75).

**Cyfrin:** Verified.


### Remove redundant `morphoMarketId` validation checks in `_closeLoanMorphoWithShares` and `_openLoanPosition`

**Description:** `RockoFlashRefinance::_closeLoanMorphoWithShares` and `_openLoanPosition` contain redundant validation `morphoMarketId`. The reasons why this validation is redundant:

* `RockoFlashRefinance::refinance` already validates the input `morphoMarketId`, encodes it into the `data` payload then calls `Morpho::flashLoan` with the `data` payload:
```solidity
if (_compareStrings(to, "morpho") || _compareStrings(from, "morpho")) {
    require(_isValidId(morphoMarketId), "Morpho Market ID required for Morpho refinance");
}

bytes memory data = abi.encode(
    rockoWallet,
    from,
    to,
    debtTokenAddress,
    collateralTokenAddress,
    aCollateralTokenAddress,
    morphoMarketId,
    morphoDebtShares
);

MORPHO.flashLoan(debtTokenAddress, debtBalance, data);
```

* `Morpho::flashLoan` always passes the unmodified `data` payload to `RockoFlashRefinance::onMorphoFlashLoan`:
```solidity
function flashLoan(address token, uint256 assets, bytes calldata data) external {
    require(assets != 0, ErrorsLib.ZERO_ASSETS);

    emit EventsLib.FlashLoan(msg.sender, token, assets);

    IERC20(token).safeTransfer(msg.sender, assets);

    // @audit passing unmodified `data` payload to `onMorphoFlashLoan`
    IMorphoFlashLoanCallback(msg.sender).onMorphoFlashLoan(assets, data);

    IERC20(token).safeTransferFrom(msg.sender, address(this), assets);
}
```

*`RockoFlashRefinance::onMorphoFlashLoan` decodes the unmodified `data` payload and calls `_closeLoanMorphoWithShares` and `_openLoanPosition` using the decoded `morphoMarketId` which has already been validated in `RockoFlashRefinance::refinance`.

**Recommended Mitigation:** Remove the redundant `morphoMarketId` validation checks at:
```solidity
325: require(_isValidId(morphoMarketId), "Invalid Morpho Market ID");

503: require(_isValidId(morphoMarketId), "Morpho Market ID required for Morpho refinance");
```

**Rocko:** Fixed in commit [5a9aa7d](https://github.com/getrocko/onchain/commit/5a9aa7d3cfb80150448608854440c285ea08fa53).

**Cyfrin:** Verified.


### Redundant collateral balance check in `_openLoanMorpho`

**Description:** `RockoFlashRefinance::_openLoanMorpho` contains a redundant check for collateral balance availability. The function verifies that the flash loan contract has sufficient collateral balance, but this check is already performed in the calling `_openLoanPosition` function.

**Recommended Mitigation:**
```diff
    function _openLoanMorpho(
        Id morphoMarketId,
        uint256 borrowAmount,
        address collateralAddress,
        uint256 collateralBalance,
        address rockoWallet
    ) private {
        _checkAllowanceAndApproveContract(address(MORPHO), collateralAddress, collateralBalance);
        MarketParams memory marketParams = MORPHO.idToMarketParams(morphoMarketId);
-       uint256 flashLoanContractBalance = IERC20(collateralAddress).balanceOf(FLASH_LOAN_CONTRACT);
-       // emit LogBalance("Flash Loan Contract Balance", flashLoanContractBalance);
-       require(
-           flashLoanContractBalance >= collateralBalance,
-           "Insufficient collateral available in the flash contract"
-       );
```

**Rocko:** Fixed in commit [a8efb43](https://github.com/getrocko/onchain/commit/a8efb43b10673508e1fd184aec23a5373f73cd5d).

**Cyfrin:** Verified.

\clearpage