**Lead Auditors**

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

**Assisting Auditors**




---

# Findings
## Medium Risk


### Incorrect state update in `RiskOracle::_processUpdate`

**Description:** Within the `RiskParameterUpdate` struct, there is a field [`bytes previousValue`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L15) that is intended to store the previous value of a parameter. This state update is performed within [`RiskOracle::_processUpdate`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L156-L158) with the [value obtained](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L155) from the `updatedById` mapping; however, there is no differentiation between parameters for different update types and markets so this state update will be inaccurate with overwhelming likelihood when there are multiple update types/markets. As such, consumers of this contract will receive recommendations with previous values that could be wildly different from what is expected and perhaps execute risk parameter updates based on a delta that is not representative of the real change.

**Impact:** The `previousValue` state for a given update will be incorrect with a very high likelihood and could result in consumers making risk parameter updates based on inaccurate historical data.

**Proof of Concept:** The following test was written to demonstrate this finding and has since been added to the repository during this engagement.

```solidity
function test_PreviousValueIsCorrectForSpecificMarketAndType() public {
    bytes memory market1 = abi.encodePacked("market1");
    bytes memory market2 = abi.encodePacked("market2");
    bytes memory newValue1 = abi.encodePacked("value1");
    bytes memory newValue2 = abi.encodePacked("value2");
    bytes memory newValue3 = abi.encodePacked("value3");
    bytes memory newValue4 = abi.encodePacked("value4");
    string memory updateType = initialUpdateTypes[0];

    vm.startPrank(AUTHORIZED_SENDER);

    // Publish first update for market1 and type1
    riskOracle.publishRiskParameterUpdate(
        "ref1", newValue1, updateType, market1, abi.encodePacked("additionalData1")
    );

    // Publish second update for market1 and type1
    riskOracle.publishRiskParameterUpdate(
        "ref2", newValue2, updateType, market1, abi.encodePacked("additionalData2")
    );

    // Publish first update for market2 and type1
    riskOracle.publishRiskParameterUpdate(
        "ref3", newValue3, updateType, market2, abi.encodePacked("additionalData3")
    );

    // Publish first update for market1 and type1
    riskOracle.publishRiskParameterUpdate(
        "ref4", newValue4, updateType, market1, abi.encodePacked("additionalData4")
    );

    vm.stopPrank();

    // Fetch the latest update for market1 and type1
    RiskOracle.RiskParameterUpdate memory latestUpdateMarket1Type1 =
        riskOracle.getLatestUpdateByParameterAndMarket(updateType, market1);
    assertEq(latestUpdateMarket1Type1.previousValue, newValue2);

    // Fetch the latest update for market2 and type1
    RiskOracle.RiskParameterUpdate memory latestUpdateMarket2Type1 =
        riskOracle.getLatestUpdateByParameterAndMarket(updateType, market2);
    assertEq(latestUpdateMarket2Type1.previousValue, bytes(""));
}
```

**Recommended Mitigation:** Retrieve the correct historical value using the [`latestUpdateIdByMarketAndType`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L28) mapping.

**Chaos Labs:** Fixed in commit [d16a227](https://github.com/ChaosLabsInc/risk-oracle/commit/d16a2277f7fb0efee0053389492aa116543a2bf7).

**Cyfrin:** Verified, the previous update value is now retrieved from the correct identifier.

\clearpage
## Informational


### Asymmetry in validation between `RiskOracle::addUpdateType` and contract constructor

**Description:** The following [validation](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L92) is present within `RiskOracle::addUpdateType`:
```solidity
require(!validUpdateTypes[newUpdateType], "Update type already exists.");
```
However, this function has the `onlyOwner` modifier applied, so the validation is not strictly necessary. This can be observed within the constructor, invoked when the owner deploys the contract, where there is no such validation – here, it is assumed that duplicates will be checked off-chain. As such, there is an asymmetry between these two instances that is recommended to be made consistent by either completely removing the validation or having it present in both code paths.

**Chaos Labs:** Added duplicate check in constructor in commit [9f7375a](https://github.com/ChaosLabsInc/risk-oracle/commit/9f7375a8291deb04719ec4ddbfff1eb638db55e1).

**Cyfrin:** Verified, the duplicate check has been added to the constructor.


### No restriction on the contract owner becoming an authorized sender

**Description:** Due to the presence of the `onlyOwner` modifier applied to [`RiskOracle::addAuthorizedSender`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L67-L75), only the contract owner is permitted to add authorized senders. Currently, the only validation present is to prevent adding an authorized sender that is already authorized, so it is possible for the owner to add themselves as an authorized sender. If this is not desired, for example to strictly enforce a separation of concerns between the two roles, then this restriction should be added.

**Chaos Labs:** Acknowledged there is no restriction on the contract owner becoming an authorized sender.

**Cyfrin:** Acknowledged.


### Duplicated validation can be moved to shared internal function

**Description:** Currently, both `RiskOracle::publishRiskParameterUpdate` and `RiskOracle::publishBulkRiskParameterUpdates` contain essentially the same validation:
```solidity
// `RiskOracle::publishRiskParameterUpdate`:
require(validUpdateTypes[updateType], "Unauthorized update type.");

// `RiskOracle::publishBulkRiskParameterUpdates`:
require(validUpdateTypes[updateTypes[i]], "Unauthorized update type at index");
```
Both functions also call the internal `_processUpdate()` function, so this validation can be de-duplicated by placing it there instead.

**Chaos Labs:** Fixed in commit [6cf09fb](https://github.com/ChaosLabsInc/risk-oracle/commit/6cf09fbe31a2050d04b60c79eddfa15f5cd5ca15).

**Cyfrin:** Verified, the validation is now present in the shared internal function.


### Parallel data structures are not necessary

**Description:** Usage of the [`updatesById`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L25) mapping with keys given by the monotonically increasing [`updateCounter`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L29) state variable is effectively the same as using the [`updateHistory`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L25) array with an index shift of 1 (due to 0 being reserved for invalid update ids). In the current design, it is not necessary to maintain these parallel data structures, so if the format of update ids is unlikely to change in the future then this `updatesById` mapping can be removed in favor of the `updateHistory` array. Note that this modification would necessitate additional refactoring in the `getLatestUpdateByType()`, `getLatestUpdateByParameterAndMarket()`, and `getUpdateById()` functions.

**Chaos Labs:** Fixed in commit [6cf09fb](https://github.com/ChaosLabsInc/risk-oracle/commit/6cf09fbe31a2050d04b60c79eddfa15f5cd5ca15).

**Cyfrin:** Verified, the `RiskParameterUpdate[] updateHistory` has been removed.


### Unreachable code can be removed

**Description:** Within [`RiskOracle::_processUpdate`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L155), the `else` branch of the ternary operator is unreachable due to `updateCounter` being initialized to 0 and incremented before this line:

```solidity
updateCounter++;
bytes memory previousValue = updateCounter > 0 ? updatesById[updateCounter - 1].newValue : bytes("");
```

Thus, this variable assignment logic can be simplified to just reading from the mapping (but note that this usage of the `updatedById` mapping is incorrect, as reported in M-01).

**Chaos Labs:** Fixed in commit [6cf09fb](https://github.com/ChaosLabsInc/risk-oracle/commit/6cf09fbe31a2050d04b60c79eddfa15f5cd5ca15).

**Cyfrin:** Verified, the code path has been removed.

\clearpage
## Gas Optimization


### Unnecessary initialization can be removed

**Description:** Initialization of the `updateCounter` state variable [within the constructor](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L64) of `RiskOracle` is unnecessary and can be removed since this state will be `0` by default.

**Chaos Labs:** Fixed in commit [9f7375a](https://github.com/ChaosLabsInc/risk-oracle/commit/9f7375a8291deb04719ec4ddbfff1eb638db55e1).

**Cyfrin:** Verified, the initialization is no longer present.


### Array length validation is not necessary

**Description:** [`RiskOracle::publishBulkRiskParameterUpdates`](https://github.com/ChaosLabsInc/risk-oracle/blob/9449219174e3ee7da9a13a5db7fb566836fb4986/src/RiskOracle.sol#L117-L142) currently validates that the lengths of all input arrays are equal.

```solidity
function publishBulkRiskParameterUpdates(
    string[] memory referenceIds,
    bytes[] memory newValues,
    string[] memory updateTypes,
    bytes[] memory markets,
    bytes[] memory additionalData
) external onlyAuthorized {
    require(
        referenceIds.length == newValues.length && newValues.length == updateTypes.length
            && updateTypes.length == markets.length && markets.length == additionalData.length,
        "Mismatch between argument array lengths."
    );
    for (uint256 i = 0; i < referenceIds.length; i++) {
        require(validUpdateTypes[updateTypes[i]], "Unauthorized update type at index");
        _processUpdate(referenceIds[i], newValues[i], updateTypes[i], markets[i], additionalData[i]);
    }
}
```

This validation can be removed on account of the loop over `referenceIds`, as a length mismatch will either revert due to out-of-bounds access or result in additional elements beyond the length of the `referenceIds` array being ignored.

**Chaos Labs:** Fixed in commit [6cf09fb](https://github.com/ChaosLabsInc/risk-oracle/commit/6cf09fbe31a2050d04b60c79eddfa15f5cd5ca15).

**Cyfrin:** Verified, the validation has been removed.

\clearpage