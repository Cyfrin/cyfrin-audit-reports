**Lead Auditors**

[0xStalin](https://x.com/0xStalin)

[MrPotatoMagic](https://x.com/MrPotatoMagic)

**Assisting Auditors**



---

# Findings
## Low Risk


### Tick spacing type mismatch in ExactInputSingleParams

**Description:** V3DexSwap uses the [Ramses V3 Swap Router](https://lineascan.build/address/0x8BE024b5c546B5d45CbB23163e1a4dca8fA5052A#code) to perform WETH to Linea swaps.

However, the ExactInputSingleParams struct definition passed as parameter to the exactInputSingle function differs between the V3DexSwap and the router contract.

**V3SwapDex definition**:
```solidity
struct ExactInputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 tickSpacing; <<
    address recipient;
    uint256 deadline;
    uint256 amountIn;
    uint256 amountOutMinimum;
    uint160 sqrtPriceLimitX96;
  }
```

**Ramses Router**:

```solidity
struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        int24 tickSpacing; <<
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
```

As we can see, the tickSpacing member has differing types: uint24 and int24.

**Impact:** Due to this, if the POOL_TICK_SPACING value is greater than type(int24).max i.e. 8388607, the value will be interpreted incorrectly as a negative value in the router, causing a revert if such a pool does not exist or a successful swap through an unintended pool that anyone can frontrun create on RamsesV3.

**Proof of Concept:** **Recommended Mitigation:**
Update the struct definition in V3DexSwap to use int24 for tickSpacing instead of uint24.

**Linea:** Fixed at commit [be1cbc](https://github.com/Consensys/linea-monorepo/pull/1620/commits/be1cbce5ad0410d004e09d0f559522e4eee22daa)

**Cyfrin:** Verified.

\clearpage
## Informational


### Inconsistent deadline check in `V3DexSwap.swap `

**Description:** The swap() function in V3DexSwap implements the require check in the snippet below which ensures block.timestamp is strictly less than the `_deadline`.

```solidity
require(_deadline > block.timestamp, DeadlineInThePast());
```

However, the [Ramses V3 Swap Router](https://lineascan.build/address/0x8BE024b5c546B5d45CbB23163e1a4dca8fA5052A#code) allows swaps to occur even when the block.timestamp is equal to the deadline.

```solidity
modifier checkDeadline(uint256 deadline) {
        if (_blockTimestamp() > deadline) revert Old();
        _;
    }
```

**Impact:** Due to this inconsistency, if `_deadline` is passed as block.timestamp to the `V3DexSwap.swap ` function, the call would revert even though it's a valid value accepted by the router.

**Proof of Concept:** **Recommended Mitigation:**

**Linea:** Fixed at commit [e531e7](https://github.com/Consensys/linea-monorepo/pull/1620/commits/be1cbce5ad0410d004e09d0f559522e4eee22daa)

**Cyfrin:** Verified.


### Unnecessary implementation of the `RollupRevenueVault::initialize` given that the deployed proxy is already initialized

**Description:** The `RollupRevenueVault` contract will be used to upgrade the implementation of the [proxy](https://lineascan.build/address/0xfd5fb23e06e46347d8724486cdb681507592e237)
The proxy is already initialized; therefore, the `_initialized` flag is already set to 1. This means that no function calling the `initializer` modifier can be executed again, not even after the upgrade.
This means that the only alternative to initializing the values of the new implementation is to call the `reinitializer` modifier, which is invoked by the `RollupRevenueVault::initializeRolesAndStorageVariables` function.
```solidity
    function initialize(
        ...
@>  ) external initializer {
        ...
    }

    function initializeRolesAndStorageVariables(
        ...
@>  ) external reinitializer(2) {
        ...
        );
    }
```

**Proof of Concept:** Run the following PoC to verify the upgrade only works when calling the `initializeRolesAndStorageVariables` function and reverts when calling the `initialize` function.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy,
    ITransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {RollupRevenueVault} from "src/operational/RollupRevenueVault.sol";

import {Vm} from "forge-std/Vm.sol";

contract RollupRevenueVaultUpgradeSimulationTest is Test {
    ITransparentUpgradeableProxy public proxy;
    RollupRevenueVault public newImpl;
    RollupRevenueVault public vaultUpgraded; // Proxy cast to upgraded interface

    bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Existing proxy address on Linea
    address public proxyAddr = 0xFD5FB23e06e46347d8724486cDb681507592e237;

    // Fork URL for Linea mainnet
    string public lineaRpc = "https://linea-mainnet.g.alchemy.com/v2/<ALCHEMY_API_KEY>";

    // Variables for initialization
    address public admin;
    address public invoiceSubmitter;
    address public burner;
    address public invoicePaymentReceiver;
    address public tokenBridge = address(100);
    address public messageService = address(101);
    address public l1LineaTokenBurner = 0x000000000000000000000000000000000000dEaD;
    address public lineaToken = address(102);
    address public dex = address(103);
    uint256 public lastInvoiceDate;

    function setUp() public {
        // Create and select fork of Linea mainnet
        uint256 forkId = vm.createFork(lineaRpc);
        vm.selectFork(forkId);

        // Set the proxy
        proxy = ITransparentUpgradeableProxy(payable(proxyAddr));

        assertGt(address(proxy).balance, 0);

                //@audit-info => Doesn't work because the caller is not the admin :) !
                // admin = proxy.admin();

        // Get the current admin
        admin = getAdminAddress(address(proxy));

        // Set mock/test values for roles and receiver (in production, these would be specific addresses)
        invoiceSubmitter = vm.addr(1); // Placeholder, replace with actual if known
        burner = vm.addr(2); // Placeholder, replace with actual if known
        invoicePaymentReceiver = vm.addr(3); // Placeholder, replace with actual if known
        lastInvoiceDate = block.timestamp; // Use current timestamp for simulation

        // Deploy the new implementation
        newImpl = new RollupRevenueVault();

        // Encode the initialize calldata for upgrade (initialize())
        bytes memory initDataUpgrade_initialize = abi.encodeWithSelector(
            RollupRevenueVault.initialize.selector,
            lastInvoiceDate,
            admin, // Keep the same admin
            invoiceSubmitter,
            burner,
            invoicePaymentReceiver,
            tokenBridge,
            messageService,
            l1LineaTokenBurner,
            lineaToken,
            dex
        );

//@audit => upgrade fails when calling initialize because of the initializer modifier
        vm.prank(admin);
        vm.expectRevert();
        proxy.upgradeToAndCall(address(newImpl), initDataUpgrade_initialize);

        // Encode the reinitialization calldata for upgrade (reinitializer(2))
        bytes memory initDataUpgrade_reinitialize = abi.encodeWithSelector(
            RollupRevenueVault.initializeRolesAndStorageVariables.selector,
            lastInvoiceDate,
            admin, // Keep the same admin
            invoiceSubmitter,
            burner,
            invoicePaymentReceiver,
            tokenBridge,
            messageService,
            l1LineaTokenBurner,
            lineaToken,
            dex
        );

//@audit => upgrade succeeds when calling initializeRolesAndStorageVariables because of the reinitializer modifier
        vm.prank(admin);
        proxy.upgradeToAndCall(address(newImpl), initDataUpgrade_reinitialize);


        // Cast the proxy to the new interface
        vaultUpgraded = RollupRevenueVault(payable(address(proxy)));
    }

    function testUpgradeSimulation() public {
        // Verify the implementation has been updated
        assertEq(getImplementationAddress(address(proxy)), address(newImpl));

        // // Verify initialization values after upgrade
        assertEq(vaultUpgraded.lastInvoiceDate(), lastInvoiceDate);
        assertEq(vaultUpgraded.invoicePaymentReceiver(), invoicePaymentReceiver);
        assertEq(vaultUpgraded.dex(), dex);
        assertEq(address(vaultUpgraded.tokenBridge()), tokenBridge);
        assertEq(address(vaultUpgraded.messageService()), messageService);
        assertEq(vaultUpgraded.l1LineaTokenBurner(), l1LineaTokenBurner);
        assertEq(vaultUpgraded.lineaToken(), lineaToken);

        // Verify invoice arrears starts at 0
        assertEq(vaultUpgraded.invoiceArrears(), 0);

        // Verify constants
        assertEq(vaultUpgraded.ETH_BURNT_PERCENTAGE(), 20);

        // Verify the proxy still holds its balance (should be unchanged)
        assertGt(address(proxy).balance, 0); // From explorer, ~198 ETH
    }

    function getAdminAddress(address proxy) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 adminSlot = vm.load(proxy, ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }

    function getImplementationAddress(address proxy) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 implementationSlot = vm.load(proxy, IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implementationSlot)));
    }
}
```

**Recommended Mitigation:** Remove the `RollupRevenueVault::initialize`. Only `RollupRevenueVault::initializeRolesAndStorageVariables` is required to reinitialize the values for the upgrade.

**Linea:** Fixed at [PR 1604](https://github.com/Consensys/linea-monorepo/pull/1604)

**Cyfrin:** Verified. The initialize function has been removed.


### emiting `EthReceived` event when `RollupRevenueVault` receives 0 eth

**Description:** [`RollupRevenueVault::receive`](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/RollupRevenueVault.sol#L292-L294) && [`RollupRevenueVault:fallback`](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/RollupRevenueVault.sol#L285-L287) functions emit the `EthReceived` event whenever they are called, regardless of whether there was actually any native sent to the contract.

Especially for the `fallback()`, the event will be emitted whenever the function catches a call that doesn't match any of the functions specified on the ABI.


**Recommended Mitigation:** Consider skipping the event emission when no native is received on the `fallback` or `receive` functions.

**Linea:** Fixed at [PR 1604](https://github.com/Consensys/linea-monorepo/pull/1604)

**Cyfrin:** Verified. Both `receive()` and `fallback()` functions revert if `msg.value` is 0.


### Lack of validation to prevent receiving less LINEA tokens for the swap than the expected `minAmountOut`

**Description:** There is no validation on the [`V3DexSwap::swap` ](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/V3DexSwap.sol#L50-L74)to prevent the dex swapper from receiving fewer tokens than the specified `minAmountOut`. It is true that most routers indeed enforce the received `amountOut` to be at least `minAmountOut`. However, full reliance on the router performing this validation poses a potential problem in case the dex swapper is updated to work with a router that does not perform this check.

**Recommended Mitigation:** Consider validating that the received LINEA tokens for the swap are at least the expected `minAmountOut`.

**Linea:** Fixed at [PR 1604](https://github.com/Consensys/linea-monorepo/pull/1604)

**Cyfrin:** Verified. Added a check to verify the caller received at least the specified `_minLineaOut` of  LINEA token.


### No event emission when initializing parameters

**Description:** On the constructors of the [`L1LineaTokenBurner`](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/L1LineaTokenBurner.sol#L21-L27) and [`V3DexSwap` ](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/V3DexSwap.sol#L31-L41)contracts, there are no event emissions to log the values of the parameters that were initialized.
The same occurs when reinitializing the values on the [`RollupRevenueVault`](https://github.com/Consensys/linea-monorepo/blob/8285efababe0689aec5f0a21a28212d9d22df22e/contracts/src/operational/RollupRevenueVault.sol#L98-L160).

**Recommended Mitigation:** Consider emitting events to log the values of the initialized parameters.

**Linea:** Fixed at [PR 1604](https://github.com/Consensys/linea-monorepo/pull/1604)

**Cyfrin:** Verified.


### Require condition `_minLineaOut > 0` offers no protection against malicious BURNER_ROLE behaviour

**Description:** Function burnAndBridge in RollupRevenueVault is only callable by the BURNER_ROLE. During this call, the BURNER_ROLE can pass in arbitrary `_swapData` to call on the V3DexSwap contract. The swap() function contains the following check:
```solidity
require(_minLineaOut > 0, ZeroMinLineaOutNotAllowed());
```

However, this check provides no protection against malicious behaviour by the BURNER_ROLE since `_minLineaOut` can be passed as 1 wei instead.

**Impact:** Loss of ETH is intended to be bridged to L1 as part of the burn and bridge mechanism.

**Proof of Concept:** **Recommended Mitigation:**
It is recommended to either implement a configurable slippage percent on the swap amount that `_minLineaOut` should not exceed or consider acknowledging this risk.

**Linea:** Acknowledged.

**Cyfrin:** Acknowledged.


### Condition `_invoiceAmount != 0` in submitInvoice() can prevent clearing existing debt

**Description:** Function submitInvoice() implements the following check below:

```solidity
require(_invoiceAmount != 0, ZeroInvoiceAmount());
```

However, if the INVOICE_SUBMITTER role wants to only clear `invoiceArrears` if sufficient ETH balance becomes available, it will not be able to do so. For example:

 - Assume at T1, `invoiceArrears` = 1e18 since there is not enough native token balance in the contract.
 - At T2, the contract receives 1e18 native token balance, which can be used to clear the existing debt stored in `invoiceArrears`.
 - However, `invoiceArrears` cannot be cleared by passing in `_invoiceAmount` as 0 due to the check in submitInvoice().

**Impact:** Although the INVOICE_SUBMITTER can wait until the next invoice submission, this delays payment of existing debt that could've been paid out sooner.

**Proof of Concept:** **Recommended Mitigation:**
Consider ackowledging this behaviour or implementing either one of the following fixes:
1. Remove the `_invoiceAmount != 0` condition.
2. Implement a separate function that allows clearing invoiceArrears.

**Linea:** Fixed in [PR 1637](https://github.com/Consensys/linea-monorepo/pull/1637/files).

**Cyfrin:** Verified.


### Burn and bridge mechanism can be delayed due to paused token bridge state

**Description:** Contract RollupRevenueVault provides the BURNER_ROLE with the burnAndBridge() function. In this process, Linea tokens are meant to be bridged to L1 and burned there.

For bridging, the `tokenBridge` service is used, which can revert due to [it being paused](https://github.com/tree/contract-freeze-2025-10-12/blob/503a36c900419e9c6df00f5dad3d4c54d83f0578/linea/contracts/src/bridging/token/TokenBridgeBase.sol#L210)

**Impact:** Exeuction of the burn and bridge mechanism can be DOSed.

**Proof of Concept:** **Recommended Mitigation:**
Consider acknowledging the risk here and ensure appropriate measures are taken to handle such a scenario.

**Linea:** Acknowledged. This is acceptable, as we would then pause our burn job.

**Cyfrin:** Verified.


### Function updateInvoiceArrears() updates `lastInvoiceDate` even when `invoiceArrears` remains unchanged

**Description:** Function updateInvoiceArrears() allows the DEFAULT_ADMIN_ROLE to update the `invoiceArrears` variable as well as `lastInvoiceDate` accordingly. However, even if the `invoiceArrears` variable remains unchanged, `lastInvoiceDate` can still be updated to a different timestamp.

```solidity
function updateInvoiceArrears(
    uint256 _newInvoiceArrears,
    uint256 _lastInvoiceDate
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(_lastInvoiceDate >= lastInvoiceDate, InvoiceDateTooOld());

    invoiceArrears = _newInvoiceArrears;
    lastInvoiceDate = _lastInvoiceDate;

    emit InvoiceArrearsUpdated(_newInvoiceArrears, _lastInvoiceDate);
  }
```


**Impact:** Variable `lastInvoiceDate` is updated even when `invoiceArrears` is not updated.

**Proof of Concept:** **Recommended Mitigation:**
Consider disallowing this behaviour by implementing a check to ensure `_newInvoiceArrears` is not equal to `invoiceArrears`. Alternatively, if such behaviour is intended, consider renaming the function to `updateInvoiceArrearsAndLastInvoiceDate`.

**Linea:** Acknowledged, this accounts for various flexible situations and ways we can correct slow infrastructure billing updates.

**Cyfrin:** Acknowledged.


### Function updateInvoiceArrears() does not emit old values

**Description:** Function updateInvoiceArrears() should consider emitting previous `invoiceArrears` and `lastInvoiceDate` values to maintain consistency with other setter functions updateL1LineaTokenBurner, updateDex and updateInvoicePaymentReceiver that emit both old and new values in their events.

```solidity
function updateInvoiceArrears(
    uint256 _newInvoiceArrears,
    uint256 _lastInvoiceDate
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(_lastInvoiceDate >= lastInvoiceDate, InvoiceDateTooOld());

    invoiceArrears = _newInvoiceArrears;
    lastInvoiceDate = _lastInvoiceDate;

    emit InvoiceArrearsUpdated(_newInvoiceArrears, _lastInvoiceDate);
  }
```

**Impact:** **Proof of Concept:**

**Recommended Mitigation:** Emit old `invoiceArrears` and `lastInvoiceDate` values in event `InvoiceArrearsUpdated`.

**Linea:** Fixed in commit [6c65701](https://github.com/Consensys/linea-monorepo/pull/1620/commits/6c6570123e25d5e9ecb98df5b663f5030281f3bb)

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Unnecessary ETH to WETH conversion during swap

**Description:** In the V3DexSwap contract, ETH is converted to WETH before processing the swap through the router as seen in the snippet below.

```solidity
IWETH9(WETH_TOKEN).deposit{ value: msg.value }();
IWETH9(WETH_TOKEN).approve(ROUTER, msg.value);
```

However, this is not required since the router supports direct ETH to Linea swaps. As we can observe below, the exactInputSingle function is marked as payable to allow direct ETH transfers when the function is called. In the router's execution path when the uniswapV3SwapCallback() calls the pay() function, it would process the router's contract balance if the token is WETH.

```solidity
File: SwapRouter.sol

/// @inheritdoc ISwapRouter
    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external payable override checkDeadline(params.deadline) returns (uint256 amountOut) {


File: PeripheryPayments.sol

/// @param token The token to pay
    /// @param payer The entity that must pay
    /// @param recipient The entity that will receive payment
    /// @param value The amount to pay
    function pay(
        address token,
        address payer,
        address recipient,
        uint256 value
    ) internal {
        if (token == WETH9 && address(this).balance >= value) {
            // pay with WETH9
            IWETH9(WETH9).deposit{value: value}(); // wrap only what is needed to pay
            IWETH9(WETH9).transfer(recipient, value);
        } else if (payer == address(this)) {
            // pay with tokens already in the contract (for the exact input multihop case)
            TransferHelper.safeTransfer(token, recipient, value);
        } else {
            // pull payment
            TransferHelper.safeTransferFrom(token, payer, recipient, value);
        }
    }
```

**Impact:** This does not pose a risk, however, it will cost unnecessary gas during swaps.

**Proof of Concept:** **Recommended Mitigation:**
Consider using ETH directly during swaps instead of converting to WETH.

**Linea:** Fixed at commit [a0b875](https://github.com/Consensys/linea-monorepo/pull/1620/commits/a0b875154412d5f543ad44994ca464219957b30e) and [dab9ebfd](https://github.com/Consensys/linea-monorepo/pull/1604/commits/dab9ebfdf65be8fbfecb9e2bc79d62056a60218b#diff-f36dd3901bbfa7a03d4cb920bfd8350752560a511fd7daf4a4fad33c7bbe6105)

**Cyfrin:** Verified. Now there are two versions of the DexSwap, one to directly swap ETH for Linea, and another to swap WETH for Linea. Both have been validated.


### Redundant call to sinc LINEA token supply on `L1LineaTokenBurner`

**Description:** `L1LineaTokenBurner::claimMessageWithProof` is in charge of completing the bridge and burn operation of the `RollupRevenueVault` deployed on the L2.

`L1LineaTokenBurner` claims the message on the L1, receives the bridged tokens, and burns them. It can also burn any tokens that are already on the contract.

The redundancy is in calling `LINEA_TOKEN::syncTotalSupplyToL2` each time `L1LineaTokenBurner::claimMessageWithProof` is called, regardless of how much time has passed since the last burn, or how many LINEA tokens were burnt.

Given that `LINEA_TOKEN::syncTotalSupplyToL2` can be called by anyone at any time, and the function uses the current total supply, `L1LineaTokenBurner` can be optimized not to sync the L2 supply on each call.

**Recommended Mitigation:** Consider removing the call to `LINEA_TOKEN::syncTotalSupplyToL2` on the `L1LineaTokenBurner::claimMessageWithProof`; instead, explore alternatives to bundle multiple burns of the LINEA token into a single call to `LINEA_TOKEN::syncTotalSupplyToL2`.
- Define a criterion that determines when the L2 supply should be synced. It can occur after a certain amount of LINEA tokens have been burned, or after a specified time period has passed.

**Linea:** Fixed in commit [43ed33](https://github.com/Consensys/linea-monorepo/pull/1604/commits/43ed33d00873756bb13ab5de5adafeba61d1fd4b)

**Cyfrin:** Verified.

\clearpage