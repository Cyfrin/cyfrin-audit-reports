**Lead Auditors**

[Dacian](https://x.com/DevDacian)
**Assisting Auditors**

 


---

# Findings
## Gas Optimization


### Cache `currentReserve.configuration` in `GenericLogic::calculateUserAccountData`

**Description:** Cache `currentReserve.configuration` in `GenericLogic::calculateUserAccountData` as this is a `view` function which doesn't change state.

**Impact:** `snapshots/Pool.Setters.json`:
```diff
-  "setUserEMode: enter eMode, 1 borrow, 1 supply": "140836",
-  "setUserEMode: leave eMode, 1 borrow, 1 supply": "112635",
+  "setUserEMode: enter eMode, 1 borrow, 1 supply": "140695",
+  "setUserEMode: leave eMode, 1 borrow, 1 supply": "112494",
```

`snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "256480",
-  "borrow: recurrent borrow": "249018",
+  "borrow: first borrow->borrowingEnabled": "256479",
+  "borrow: recurrent borrow": "248877",
  "flashLoan: flash loan for one asset": "197361",
-  "flashLoan: flash loan for one asset and borrow": "279057",
+  "flashLoan: flash loan for one asset and borrow": "279056",
  "flashLoan: flash loan for two assets": "325455",
-  "flashLoan: flash loan for two assets and borrow": "484439",
+  "flashLoan: flash loan for two assets and borrow": "484295",
  "flashLoanSimple: simple flash loan": "170603",
-  "liquidationCall: deficit on liquidated asset": "392365",
-  "liquidationCall: deficit on liquidated asset + other asset": "491921",
-  "liquidationCall: full liquidation": "392365",
-  "liquidationCall: full liquidation and receive ATokens": "368722",
-  "liquidationCall: partial liquidation": "383166",
-  "liquidationCall: partial liquidation and receive ATokens": "359520",
+  "liquidationCall: deficit on liquidated asset": "392223",
+  "liquidationCall: deficit on liquidated asset + other asset": "491638",
+  "liquidationCall: full liquidation": "392223",
+  "liquidationCall: full liquidation and receive ATokens": "368581",
+  "liquidationCall: partial liquidation": "383024",
+  "liquidationCall: partial liquidation and receive ATokens": "359378",
  "repay: full repay": "176521",
  "repay: full repay with ATokens": "173922",
  "repay: partial repay": "189949",
  "supply: first supply->collateralEnabled": "176366",
  "withdraw: full withdraw": "165226",
  "withdraw: partial withdraw": "181916",
-  "withdraw: partial withdraw with active borrows": "239471"
+  "withdraw: partial withdraw with active borrows": "239329"
```

**Recommended Mitigation:** See commit [3cd6639](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/3cd663998a91906460b7e9175862ba3fe794efb1).


### Cache `usersConfig[params.user]` in `LiquidationLogic::executeLiquidationCall`

**Description:** In `LiquidationLogic::executeLiquidationCall`, `usersConfig[params.user]` can be cached and the copy can be safely passed to view functions `GenericLogic::calculateUserAccountData` and `ValidationLogic::validateLiquidationCall`.

A more intrusive optimization is to use and update the cached copy throughout the entire liquidation process, then write the copy to storage at the end. This has been implemented separately in G-06 as it is more intrusive.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "392223",
-  "liquidationCall: deficit on liquidated asset + other asset": "491638",
-  "liquidationCall: full liquidation": "392223",
-  "liquidationCall: full liquidation and receive ATokens": "368581",
-  "liquidationCall: partial liquidation": "383024",
-  "liquidationCall: partial liquidation and receive ATokens": "359378",
+  "liquidationCall: deficit on liquidated asset": "392182",
+  "liquidationCall: deficit on liquidated asset + other asset": "491597",
+  "liquidationCall: full liquidation": "392182",
+  "liquidationCall: full liquidation and receive ATokens": "368539",
+  "liquidationCall: partial liquidation": "382983",
+  "liquidationCall: partial liquidation and receive ATokens": "359337",
```

**Recommended Mitigation:** See commit [4ce346c](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/4ce346c4ba64667d049f2344cf2df9115d104c62).


### Cache `collateralReserve.configuration` in `LiquidationLogic::executeLiquidationCall`

**Description:** In `LiquidationLogic::executeLiquidationCall`, `collateralReserve.configuration` can be safely cached and passed to child functions saving many identical storage reads.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "392182",
-  "liquidationCall: deficit on liquidated asset + other asset": "491597",
-  "liquidationCall: full liquidation": "392182",
-  "liquidationCall: full liquidation and receive ATokens": "368539",
-  "liquidationCall: partial liquidation": "382983",
-  "liquidationCall: partial liquidation and receive ATokens": "359337",
+  "liquidationCall: deficit on liquidated asset": "391606",
+  "liquidationCall: deficit on liquidated asset + other asset": "491021",
+  "liquidationCall: full liquidation": "391606",
+  "liquidationCall: full liquidation and receive ATokens": "367841",
+  "liquidationCall: partial liquidation": "382408",
+  "liquidationCall: partial liquidation and receive ATokens": "358639",
```

**Recommended Mitigation:** See commit [414dc2d](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/414dc2d6cb9314bcda79cd72425407be75be22a6).


### Cache `collateralReserve.id` in `LiquidationLogic::executeLiquidationCall`

**Description:** In `LiquidationLogic::executeLiquidationCall`, `collateralReserve.id` can be safely cached and the copy passed to child functions.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "391606",
-  "liquidationCall: deficit on liquidated asset + other asset": "491021",
-  "liquidationCall: full liquidation": "391606",
-  "liquidationCall: full liquidation and receive ATokens": "367841",
-  "liquidationCall: partial liquidation": "382408",
-  "liquidationCall: partial liquidation and receive ATokens": "358639",
+  "liquidationCall: deficit on liquidated asset": "391560",
+  "liquidationCall: deficit on liquidated asset + other asset": "490975",
+  "liquidationCall: full liquidation": "391560",
+  "liquidationCall: full liquidation and receive ATokens": "367673",
+  "liquidationCall: partial liquidation": "382476",
+  "liquidationCall: partial liquidation and receive ATokens": "358585",
```

**Recommended Mitigation:** See commit [a82d552](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/a82d552a5bb901f9f4b0c81421f36953df686978).


### Use cached `vars.collateralAToken` in `LiquidationLogic::_liquidateATokens`

**Description:** Use cached `vars.collateralAToken` in `LiquidationLogic::_liquidateATokens`; there's no need to read it from storage again.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: full liquidation and receive ATokens": "367673",
+  "liquidationCall: full liquidation and receive ATokens": "367553",
   "liquidationCall: partial liquidation": "382476",
-  "liquidationCall: partial liquidation and receive ATokens": "358585",
+  "liquidationCall: partial liquidation and receive ATokens": "358465",
```

**Recommended Mitigation:** See commit [f6af2e1](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/f6af2e13b8e3b9960abb63ebb4eaeb82e271b718).


### Only read from and write to storage once for `usersConfig[params.user]` in `LiquidationLogic::executeLiquidationCall`

**Description:** `usersConfig[params.user]` can be read once at the start of `LiquidationLogic::executeLiquidationCall`, then the cached copy can be passed around using `memory` and modified as needed, and finally storage can be written once at the end of the function.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "391560",
-  "liquidationCall: deficit on liquidated asset + other asset": "490975",
-  "liquidationCall: full liquidation": "391560",
-  "liquidationCall: full liquidation and receive ATokens": "367553",
-  "liquidationCall: partial liquidation": "382476",
-  "liquidationCall: partial liquidation and receive ATokens": "358465",
+  "liquidationCall: deficit on liquidated asset": "391305",
+  "liquidationCall: deficit on liquidated asset + other asset": "489972",
+  "liquidationCall: full liquidation": "391305",
+  "liquidationCall: full liquidation and receive ATokens": "367366",
+  "liquidationCall: partial liquidation": "382734",
+  "liquidationCall: partial liquidation and receive ATokens": "358795",
```

This change seems to benefit everything apart from partial liquidations where it results in slightly worse performance.

**Recommended Mitigation:** See commit [f419f3c](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/f419f3c638401cef897a265ff0407da762e84021).


### Reduce memory usage and gas by using named return variables in `LiquidationLogic::_calculateAvailableCollateralToLiquidate`

**Description:** Reduce memory usage and gas by using named return variables in `LiquidationLogic::_calculateAvailableCollateralToLiquidate`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "391305",
-  "liquidationCall: deficit on liquidated asset + other asset": "489972",
-  "liquidationCall: full liquidation": "391305",
-  "liquidationCall: full liquidation and receive ATokens": "367366",
-  "liquidationCall: partial liquidation": "382734",
-  "liquidationCall: partial liquidation and receive ATokens": "358795",
+  "liquidationCall: deficit on liquidated asset": "391070",
+  "liquidationCall: deficit on liquidated asset + other asset": "489736",
+  "liquidationCall: full liquidation": "391070",
+  "liquidationCall: full liquidation and receive ATokens": "367131",
+  "liquidationCall: partial liquidation": "382507",
+  "liquidationCall: partial liquidation and receive ATokens": "358569",
```

**Recommended Mitigation:** See commit [af61e44](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/af61e44a43c488ba1a3a569482a7fed18b8518c9).


### Remove memory struct `AvailableCollateralToLiquidateLocalVars` and use only local variables in `LiquidationLogic::_calculateAvailableCollateralToLiquidate`

**Description:** Using in-memory "context" structs to store variables is a nice trick to get around "stack too deep errors", but also uses significantly more gas than using local in-function variables.

When in-memory "context" structs are not required, it is cheaper to not use them. Hence remove memory struct `AvailableCollateralToLiquidateLocalVars` and use only local variables in `LiquidationLogic::_calculateAvailableCollateralToLiquidate`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "391070",
-  "liquidationCall: deficit on liquidated asset + other asset": "489736",
-  "liquidationCall: full liquidation": "391070",
-  "liquidationCall: full liquidation and receive ATokens": "367131",
-  "liquidationCall: partial liquidation": "382507",
-  "liquidationCall: partial liquidation and receive ATokens": "358569",
+  "liquidationCall: deficit on liquidated asset": "390891",
+  "liquidationCall: deficit on liquidated asset + other asset": "489556",
+  "liquidationCall: full liquidation": "390891",
+  "liquidationCall: full liquidation and receive ATokens": "366954",
+  "liquidationCall: partial liquidation": "382335",
+  "liquidationCall: partial liquidation and receive ATokens": "358397",
```

**Recommended Mitigation:** See commit [84d3925](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/84d392575dfd0da6224a43500315962430455af0).


### Move 3 variables from `LiquidationCallLocalVars` struct into body of `LiquidationLogic::executeLiquidationCall`

**Description:** Similar to G-07, at least 3 variables can be moved from the in-memory "context" struct `LiquidationCallLocalVars` into the function body of `LiquidationLogic::executeLiquidationCall` without triggering "stack too deep" errors.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "liquidationCall: deficit on liquidated asset": "390891",
-  "liquidationCall: deficit on liquidated asset + other asset": "489556",
-  "liquidationCall: full liquidation": "390891",
-  "liquidationCall: full liquidation and receive ATokens": "366954",
-  "liquidationCall: partial liquidation": "382335",
-  "liquidationCall: partial liquidation and receive ATokens": "358397",
+  "liquidationCall: deficit on liquidated asset": "390795",
+  "liquidationCall: deficit on liquidated asset + other asset": "489459",
+  "liquidationCall: full liquidation": "390795",
+  "liquidationCall: full liquidation and receive ATokens": "366840",
+  "liquidationCall: partial liquidation": "382220",
+  "liquidationCall: partial liquidation and receive ATokens": "358265",
```

**Recommended Mitigation:** See commit [8bf12e2](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/8bf12e272001306d07ba2ebf07ba2d3668792784).


### Used named return variables in `GenericLogic::calculateUserAccountData`

**Description:** Similar to G-7, cheaper to use named return variables in `GenericLogic::calculateUserAccountData`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "256479",
-  "borrow: recurrent borrow": "248877",
+  "borrow: first borrow->borrowingEnabled": "256117",
+  "borrow: recurrent borrow": "248451",
   "flashLoan: flash loan for one asset": "197361",
-  "flashLoan: flash loan for one asset and borrow": "279056",
+  "flashLoan: flash loan for one asset and borrow": "278694",
   "flashLoan: flash loan for two assets": "325455",
-  "flashLoan: flash loan for two assets and borrow": "484295",
+  "flashLoan: flash loan for two assets and borrow": "483384",
   "flashLoanSimple: simple flash loan": "170603",
-  "liquidationCall: deficit on liquidated asset": "390795",
-  "liquidationCall: deficit on liquidated asset + other asset": "489459",
-  "liquidationCall: full liquidation": "390795",
-  "liquidationCall: full liquidation and receive ATokens": "366840",
-  "liquidationCall: partial liquidation": "382220",
-  "liquidationCall: partial liquidation and receive ATokens": "358265",
+  "liquidationCall: deficit on liquidated asset": "390368",
+  "liquidationCall: deficit on liquidated asset + other asset": "489010",
+  "liquidationCall: full liquidation": "390368",
+  "liquidationCall: full liquidation and receive ATokens": "366414",
+  "liquidationCall: partial liquidation": "381793",
+  "liquidationCall: partial liquidation and receive ATokens": "357839",
-  "withdraw: partial withdraw with active borrows": "239329"
+  "withdraw: partial withdraw with active borrows": "238904"
```

**Recommended Mitigation:** See commit [f6f7cb6](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/f6f7cb6c2ff160d722ebc25a6f121a59528f26a3).


### Remove 5 variables from context struct `CalculateUserAccountDataVars` used in `GenericLogic::calculateUserAccountData`

**Description:** Similar to G-7 and G-8, it is cheaper to remove these variables from the in-memory struct `CalculateUserAccountDataVars` without triggering a "stack too deep" error.

**Impact:** `snapshots/Pool.Operations`:
```diff
-  "borrow: first borrow->borrowingEnabled": "256117",
-  "borrow: recurrent borrow": "248451",
+  "borrow: first borrow->borrowingEnabled": "255807",
+  "borrow: recurrent borrow": "248112",
   "flashLoan: flash loan for one asset": "197361",
-  "flashLoan: flash loan for one asset and borrow": "278694",
+  "flashLoan: flash loan for one asset and borrow": "278384",
   "flashLoan: flash loan for two assets": "325455",
-  "flashLoan: flash loan for two assets and borrow": "483384",
+  "flashLoan: flash loan for two assets and borrow": "482657",
   "flashLoanSimple: simple flash loan": "170603",
-  "liquidationCall: deficit on liquidated asset": "390368",
-  "liquidationCall: deficit on liquidated asset + other asset": "489010",
-  "liquidationCall: full liquidation": "390368",
-  "liquidationCall: full liquidation and receive ATokens": "366414",
-  "liquidationCall: partial liquidation": "381793",
-  "liquidationCall: partial liquidation and receive ATokens": "357839",
+  "liquidationCall: deficit on liquidated asset": "390029",
+  "liquidationCall: deficit on liquidated asset + other asset": "488641",
+  "liquidationCall: full liquidation": "390029",
+  "liquidationCall: full liquidation and receive ATokens": "366075",
+  "liquidationCall: partial liquidation": "381454",
+  "liquidationCall: partial liquidation and receive ATokens": "357501",
-  "withdraw: partial withdraw with active borrows": "238904"
+  "withdraw: partial withdraw with active borrows": "238566"
```

**Recommended Mitigation:** See commits [01e1024](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/01e10245711584b0fffad75029a2ce1ea1201498), [48d773e](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/48d773e84d2f4a57422926b4d6246fb24f97a177).


### Use named returns in `ReserveLogic::cache` and `cumulateToLiquidityIndex`

**Description:** Using named returns in `ReserveLogic::cache` and `cumulateToLiquidityIndex` provides nice gas reductions across many functions.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "255775",
-  "borrow: recurrent borrow": "248098",
-  "flashLoan: flash loan for one asset": "197361",
-  "flashLoan: flash loan for one asset and borrow": "278352",
-  "flashLoan: flash loan for two assets": "325455",
-  "flashLoan: flash loan for two assets and borrow": "482562",
-  "flashLoanSimple: simple flash loan": "170603",
-  "liquidationCall: deficit on liquidated asset": "390014",
-  "liquidationCall: deficit on liquidated asset + other asset": "488644",
-  "liquidationCall: full liquidation": "390014",
-  "liquidationCall: full liquidation and receive ATokens": "366060",
-  "liquidationCall: partial liquidation": "381439",
-  "liquidationCall: partial liquidation and receive ATokens": "357486",
-  "repay: full repay": "176521",
-  "repay: full repay with ATokens": "173922",
-  "repay: partial repay": "189949",
-  "repay: partial repay with ATokens": "185129",
-  "supply: collateralDisabled": "146755",
-  "supply: collateralEnabled": "146755",
-  "supply: first supply->collateralEnabled": "176229",
-  "withdraw: full withdraw": "165226",
-  "withdraw: partial withdraw": "181916",
-  "withdraw: partial withdraw with active borrows": "238552"
+  "borrow: first borrow->borrowingEnabled": "255438",
+  "borrow: recurrent borrow": "247760",
+  "flashLoan: flash loan for one asset": "197044",
+  "flashLoan: flash loan for one asset and borrow": "278015",
+  "flashLoan: flash loan for two assets": "324816",
+  "flashLoan: flash loan for two assets and borrow": "481887",
+  "flashLoanSimple: simple flash loan": "170288",
+  "liquidationCall: deficit on liquidated asset": "389335",
+  "liquidationCall: deficit on liquidated asset + other asset": "487617",
+  "liquidationCall: full liquidation": "389335",
+  "liquidationCall: full liquidation and receive ATokens": "365723",
+  "liquidationCall: partial liquidation": "380761",
+  "liquidationCall: partial liquidation and receive ATokens": "357148",
+  "repay: full repay": "176189",
+  "repay: full repay with ATokens": "173590",
+  "repay: partial repay": "189617",
+  "repay: partial repay with ATokens": "184797",
+  "supply: collateralDisabled": "146423",
+  "supply: collateralEnabled": "146423",
+  "supply: first supply->collateralEnabled": "175897",
+  "withdraw: full withdraw": "164894",
+  "withdraw: partial withdraw": "181583",
+  "withdraw: partial withdraw with active borrows": "238216"
```

**Recommended Mitigation:** See commit [f51ced5](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/f51ced5571da85b33ca3ff4a109f9dfa2e84e87a).


### Misc used named returns to eliminate local variables or for `memory` returns

**Description:** Generally using named returns is more efficient either when it can remove a local variable and/or when the return is `memory`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "255438",
-  "borrow: recurrent borrow": "247760",
+  "borrow: first borrow->borrowingEnabled": "255409",
+  "borrow: recurrent borrow": "247710",
   "flashLoan: flash loan for one asset": "197044",
-  "flashLoan: flash loan for one asset and borrow": "278015",
+  "flashLoan: flash loan for one asset and borrow": "277986",
   "flashLoan: flash loan for two assets": "324816",
-  "flashLoan: flash loan for two assets and borrow": "481887",
+  "flashLoan: flash loan for two assets and borrow": "481858",
-  "repay: full repay": "176189",
-  "repay: full repay with ATokens": "173590",
-  "repay: partial repay": "189617",
-  "repay: partial repay with ATokens": "184797",
+  "repay: full repay": "176156",
+  "repay: full repay with ATokens": "173565",
+  "repay: partial repay": "189587",
+  "repay: partial repay with ATokens": "184775",
   "supply: collateralDisabled": "146423",
   "supply: collateralEnabled": "146423",
-  "supply: first supply->collateralEnabled": "175897",
+  "supply: first supply->collateralEnabled": "175868",
```

`snapshots/RewardsController.json`:
```diff
-  "claimAllRewards: one reward type": "50167",
-  "claimAllRewardsToSelf: one reward type": "49963",
-  "claimRewards partial: one reward type": "48299",
-  "claimRewards: one reward type": "48037",
-  "configureAssets: one reward type": "264184",
+  "claimAllRewards: one reward type": "50131",
+  "claimAllRewardsToSelf: one reward type": "49927",
+  "claimRewards partial: one reward type": "48250",
+  "claimRewards: one reward type": "47988",
+  "configureAssets: one reward type": "264175",
```

`snapshots/StataTokenV2.json`:
```diff
-  "claimRewards": "359669",
+  "claimRewards": "359522",
```

Note: there were more benefits as well from later commits.

**Recommended Mitigation:** See commits [ff2f190](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/ff2f190e4454175b6594c3c4fc6aebd35461013e), [460e574](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/460e5744635fe856320eebcfeeb8091211c59039), [47933e7](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/47933e7e74c906fe475cfe8eb9fc2537bca30922), [2ad50db](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/2ad50db0d160f2a45dca9dcbebb4b0931e356b71), [9e76a0b](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/9e76a0b71aa1f523d4afdcc6be03bf184b7a2a7a), [757b9a7](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/757b9a7a3825bd2bc596b11fd2bf51884f6ff5d9).


### Only read from and write to `userConfig` storage once in `SupplyLogic::executeWithdraw`

**Description:** Only read from and write to `userConfig` storage once in `SupplyLogic::executeWithdraw`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "supply: first supply->collateralEnabled": "175868",
-  "withdraw: full withdraw": "164894",
-  "withdraw: partial withdraw": "181583",
-  "withdraw: partial withdraw with active borrows": "238208"
+  "supply: first supply->collateralEnabled": "175872",
+  "withdraw: full withdraw": "164728",
+  "withdraw: partial withdraw": "181499",
+  "withdraw: partial withdraw with active borrows": "237972"
```

**Recommended Mitigation:** See commit [ba371a8](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/ba371a8dc77295dfe27a3c4b6b62d63213ec4a62).


### Cache `usersConfig[params.from]` in `SupplyLogic::executeFinalizeTransfer`

**Description:** Caching `usersConfig[params.from]` in `SupplyLogic::executeFinalizeTransfer` and putting `uint256 reserveId = reserve.id;` inside the `if` statement provides a gas reduction across a number of functions.

**Impact:** `snapshots/AToken.transfer.json`:
```diff
-  "full amount; sender: ->disableCollateral;": "103316",
-  "full amount; sender: ->disableCollateral; receiver: ->enableCollateral": "145062",
-  "full amount; sender: ->disableCollateral; receiver: dirty, ->enableCollateral": "132989",
+  "full amount; sender: ->disableCollateral;": "103282",
+  "full amount; sender: ->disableCollateral; receiver: ->enableCollateral": "145028",
+  "full amount; sender: ->disableCollateral; receiver: dirty, ->enableCollateral": "132955",
-  "partial amount; sender: collateralEnabled;": "103347",
-  "partial amount; sender: collateralEnabled; receiver: ->enableCollateral": "145093"
+  "partial amount; sender: collateralEnabled;": "103208",
+  "partial amount; sender: collateralEnabled; receiver: ->enableCollateral": "144954"
```

`snapshots/StataTokenV2.json`:
```diff
-  "depositATokens": "219313",
+  "depositATokens": "219279",
-  "redeemAToken": "152637"
+  "redeemAToken": "152498"
```

`snapshots/WrappedTokenGatewayV3.json`:
```diff
-  "withdrawETH": "258800"
+  "withdrawETH": "258766"
```

**Recommended Mitigation:** See commit [aba92d2](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/aba92d2afb5c15275bd0b00cf844e26905020a5f).


### Cache `userConfig` in `BorrowLogic::executeBorrow`

**Description:** Cache `userConfig` in `BorrowLogic::executeBorrow`.

**Impact:** `snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "255409",
-  "borrow: recurrent borrow": "247710",
+  "borrow: first borrow->borrowingEnabled": "255253",
+  "borrow: recurrent borrow": "247555",
   "flashLoan: flash loan for one asset": "197044",
-  "flashLoan: flash loan for one asset and borrow": "277986",
+  "flashLoan: flash loan for one asset and borrow": "277830",
   "flashLoan: flash loan for two assets": "324816",
-  "flashLoan: flash loan for two assets and borrow": "481858",
+  "flashLoan: flash loan for two assets and borrow": "481547",
```

**Recommended Mitigation:** See commit [204a894](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/204a894f194eecdb2ea8d32edc996e52501a988e).


### In `RewardsDistributor`, cache `storage` array lengths and when expected to read it `>= 3` times also for `memory`

**Description:** Cache array lengths for `storage` and when expected to read it `>= 3` times also for `memory`.

**Impact:** `snapshots/RewardsController.json`:
```diff
-  "getUserAccruedRewards: one reward type": "2182"
+  "getUserAccruedRewards: one reward type": "2090"
```

**Recommended Mitigation:** See commit [a3117ba](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/a3117ba9a5a3e1eb7134219e1797c49168436484).



### Cache event emission parameters in `RewardsDistributor:::setDistributionEnd`, `setEmissionPerSecond`

**Description:** Cache event emission parameters in `RewardsDistributor:::setDistributionEnd`, `setEmissionPerSecond`.

**Impact:** `snapshots/RewardsController.json`:
```diff
-  "setDistributionEnd": "5972"
+  "setDistributionEnd": "5940"
-  "setEmissionPerSecond: one reward one emission": "11541"
+  "setEmissionPerSecond: one reward one emission": "11455"
```

**Recommended Mitigation:** See commits [8f488dc](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/8f488dcc67a0a8469e1b0f99924d5653c03f92a9), [f516e0c](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/f516e0c65b0940c5d8cfc8a23171e1f0eae598ee), [c932b96](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/c932b96c7733c6f3fa5472c8895ebf39ae20df12), [38408b1](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/38408b112b3bb4c2cf4b8581b6e7e484965bb282).


### Read and increment `availableRewardsCount` in same statement in `RewardsDistributor::_configureAssets`

**Description:** Read and increment `availableRewardsCount` in same statement in `RewardsDistributor::_configureAssets`.

**Impact:** `snapshots/RewardsController.json`:
```diff
-  "configureAssets: one reward type": "264175",
+  "configureAssets: one reward type": "263847",
```

**Recommended Mitigation:** See commit [654ecad](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/654ecada3c3514f9c351258fa4a6c59ec2e93080).


### Exit quickly in `RewardsDistributor::_updateData` when `numAvailableRewards == 0`

**Description:** Exit quickly in `RewardsDistributor::_updateData` when `numAvailableRewards == 0` to avoid unnecessary work prior to exiting.

This optimization improves performance of any functions where the most common case is `numAvailableRewards = 0`, but results in worse performance when claiming rewards when `numAvailableRewards != 0`.

Hence it is a trade-off that should be considered based on what is the most likely case.

**Impact:** `snapshots/AToken.transfer.json`:
```diff
-  "full amount; receiver: ->enableCollateral": "144885",
-  "full amount; sender: ->disableCollateral;": "103282",
-  "full amount; sender: ->disableCollateral; receiver: ->enableCollateral": "145028",
-  "full amount; sender: ->disableCollateral; receiver: dirty, ->enableCollateral": "132955",
-  "full amount; sender: collateralDisabled": "103139",
-  "partial amount; sender: collateralDisabled;": "103139",
-  "partial amount; sender: collateralDisabled; receiver: ->enableCollateral": "144885",
-  "partial amount; sender: collateralEnabled;": "103208",
-  "partial amount; sender: collateralEnabled; receiver: ->enableCollateral": "144954"
+  "full amount; receiver: ->enableCollateral": "144757",
+  "full amount; sender: ->disableCollateral;": "103154",
+  "full amount; sender: ->disableCollateral; receiver: ->enableCollateral": "144900",
+  "full amount; sender: ->disableCollateral; receiver: dirty, ->enableCollateral": "132827",
+  "full amount; sender: collateralDisabled": "103011",
+  "partial amount; sender: collateralDisabled;": "103011",
+  "partial amount; sender: collateralDisabled; receiver: ->enableCollateral": "144757",
+  "partial amount; sender: collateralEnabled;": "103080",
+  "partial amount; sender: collateralEnabled; receiver: ->enableCollateral": "144826"
```

`snapshots/Pool.Operations.json`:
```diff
-  "borrow: first borrow->borrowingEnabled": "255253",
-  "borrow: recurrent borrow": "247555",
+  "borrow: first borrow->borrowingEnabled": "255189",
+  "borrow: recurrent borrow": "247491",

-  "flashLoan: flash loan for one asset and borrow": "277830",
+  "flashLoan: flash loan for one asset and borrow": "277766",

-  "flashLoan: flash loan for two assets and borrow": "481547",
+  "flashLoan: flash loan for two assets and borrow": "481419",

-  "liquidationCall: deficit on liquidated asset": "389335",
-  "liquidationCall: deficit on liquidated asset + other asset": "487617",
-  "liquidationCall: full liquidation": "389335",
-  "liquidationCall: full liquidation and receive ATokens": "365723",
-  "liquidationCall: partial liquidation": "380761",
-  "liquidationCall: partial liquidation and receive ATokens": "357148",
-  "repay: full repay": "176156",
-  "repay: full repay with ATokens": "173565",
-  "repay: partial repay": "189587",
-  "repay: partial repay with ATokens": "184775",
-  "supply: collateralDisabled": "146423",
-  "supply: collateralEnabled": "146423",
+  "liquidationCall: deficit on liquidated asset": "389079",
+  "liquidationCall: deficit on liquidated asset + other asset": "487297",
+  "liquidationCall: full liquidation": "389079",
+  "liquidationCall: full liquidation and receive ATokens": "365403",
+  "liquidationCall: partial liquidation": "380505",
+  "liquidationCall: partial liquidation and receive ATokens": "356828",
+  "repay: full repay": "176092",
+  "repay: full repay with ATokens": "173437",
+  "repay: partial repay": "189523",
+  "repay: partial repay with ATokens": "184647",
+  "supply: collateralDisabled": "146359",
+  "supply: collateralEnabled": "146359",
```

`snapshots/RewardsController.json`: (claiming worse)
```diff
-   "claimAllRewards: one reward type": "50131",
-   "claimAllRewardsToSelf: one reward type": "49927",
-   "claimRewards partial: one reward type": "48250",
-   "claimRewards: one reward type": "47988",
+  "claimAllRewards: one reward type": "50311",
+  "claimAllRewardsToSelf: one reward type": "50107",
+  "claimRewards partial: one reward type": "48430",
+  "claimRewards: one reward type": "48168"
```

`snapshots/StataTokenV2.json`: (some worse, some better)
```diff
-  "claimRewards": "359522",
-  "deposit": "280209",
-  "depositATokens": "219279",
-  "redeem": "205420",
-  "redeemAToken": "152498"
+  "claimRewards": "359882",
+  "deposit": "280145",
+  "depositATokens": "219151",
+  "redeem": "205356",
+  "redeemAToken": "152370"
```

`snapshots/WrappedTokenGatewayV3.json`:
```diff
-  "borrowETH": "249186",
-  "depositETH": "222292",
-  "repayETH": "192572",
-  "withdrawETH": "258766"
+  "borrowETH": "249122",
+  "depositETH": "222228",
+  "repayETH": "192508",
+  "withdrawETH": "258574"
```

**Recommended Mitigation:** See commit [be7f13c](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/be7f13c5ddef7343f4a3911a6e573cfcd29ed271).


### Read and increment `streamId` in same statement, also use named return in `Collector::createStream`

**Description:** Read and increment `streamId` in same statement, also use named return in `Collector::createStream`.

**Impact:** `snapshots/Collector.json`:
```diff
-  "createStream": "211680",
+  "createStream": "211600",
```

**Recommended Mitigation:** See commit [a008981](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/a008981433710d3603be8d44dacbb3d1d62e18b8).



### Don't copy entire `Stream` struct from `storage` to `memory` in `Collector::deltaOf`

**Description:** Don't copy entire `Stream` struct from `storage` to `memory` in `Collector::deltaOf`, since only 2 variables are required.

**Impact:** `snapshots/Collector.json`:
```diff
-  "cancelStream: by funds admin": "18522",
-  "cancelStream: by recipient": "49489",
+  "cancelStream: by funds admin": "16710",
+  "cancelStream: by recipient": "47635",
-  "withdrawFromStream: final withdraw": "43594",
-  "withdrawFromStream: intermediate withdraw": "42252"
+  "withdrawFromStream: final withdraw": "42656",
+  "withdrawFromStream: intermediate withdraw": "41326"
```

**Recommended Mitigation:** See commit [78c8150](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/78c81502825580181528787596cde4521c05194e).




### Remove struct `BalanceOfLocalVars` and use local variables in `Collector::balanceOf`

**Description:** Remove struct `BalanceOfLocalVars` and use local variables in `Collector::balanceOf`.

**Impact:** `snapshots/Collector.json`:
```diff
-  "cancelStream: by funds admin": "16710",
-  "cancelStream: by recipient": "47635",
+  "cancelStream: by funds admin": "16483",
+  "cancelStream: by recipient": "47407",
-  "withdrawFromStream: final withdraw": "42656",
-  "withdrawFromStream: intermediate withdraw": "41326"
+  "withdrawFromStream: final withdraw": "42560",
+  "withdrawFromStream: intermediate withdraw": "41230"
```

**Recommended Mitigation:** See commit [cc31124](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/cc31124fd1f30081c053f9a1b1294afad2b9958f).




### Remove struct `CreateStreamLocalVars` and use local variables in `Collector::createStream`

**Description:** Remove struct `CreateStreamLocalVars` and use local variables in `Collector::createStream`.

**Impact:** `snapshots/Collector.json`:
```diff
-  "createStream": "211600",
+  "createStream": "211518",
```

**Recommended Mitigation:** See commit [dc3da97](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/dc3da97e44f523045642364d301c08f578450361).




### Don't copy entire `Stream` struct from `storage` to `memory` and refactor `onlyAdminOrRecipient` modifier into internal function in `Collector::withdrawFromStream` and `cancelStream`

**Description:** Don't copy entire `Stream` struct from `storage` to `memory` and refactor `onlyAdminOrRecipient` modifier into internal function in `Collector::withdrawFromStream` and `cancelStream`.

**Impact:** `snapshots/Collector.json`:
```diff
-  "cancelStream: by funds admin": "16483",
-  "cancelStream: by recipient": "47407",
+  "cancelStream: by funds admin": "15718",
+  "cancelStream: by recipient": "46456",
-  "withdrawFromStream: final withdraw": "42560",
-  "withdrawFromStream: intermediate withdraw": "41230"
+  "withdrawFromStream: final withdraw": "41449",
+  "withdrawFromStream: intermediate withdraw": "40224"
```

**Recommended Mitigation:** See commit [73e6123](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/73e61234427c673fd1852f88862b3f154d2c74ce).




### Cache `oldId` prior to `require` check to save 1 storage read in `PoolAddressesProviderRegistry::unregisterAddressesProvider`

**Description:** Cache `oldId` prior to `require` check to save 1 storage read in `PoolAddressesProviderRegistry::unregisterAddressesProvider`:

**Recommended Mitigation:**
```diff
  function unregisterAddressesProvider(address provider) external override onlyOwner {
-   require(_addressesProviderToId[provider] != 0, Errors.ADDRESSES_PROVIDER_NOT_REGISTERED);
    uint256 oldId = _addressesProviderToId[provider];
+   require(oldId != 0, Errors.ADDRESSES_PROVIDER_NOT_REGISTERED);
    _idToAddressesProvider[oldId] = address(0);
    _addressesProviderToId[provider] = 0;
```

See commit [93935b8](https://github.com/devdacian/aave-v3-origin-liquidation-gas-fixes/commit/93935b820e52ea8ee8498eae928b2c2d9b695124).

\clearpage