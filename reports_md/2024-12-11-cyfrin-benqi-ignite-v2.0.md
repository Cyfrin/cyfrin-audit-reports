**Lead Auditors**

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

[Immeas](https://twitter.com/0ximmeas)

**Assisting Auditors**



---

# Findings
## High Risk


### Zeeve admin could drain `ValidatorRewarder` by abusing off-chain BLS validation due to `QI` rewards being granted to failed registrations

**Description:** [`Ignite::releaseLockedTokens`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L580-L583) takes the [`failed`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L578) boolean as a parameter, intended to indicate that registration of the node has failed and allow the user's stake to be recovered by a call to [`Ignite::redeemAfterExpiry`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L407). Registrations made by [`Ignite::registerWithAvaxFee`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L251) and [`Ignite::registerWithErc20Fee`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L281) are handled within the [first conditional branch](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L416-L419); however, those made via [`Ignite::registerWithStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L202) and [`Ignite::registerWithPrevalidatedQiStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L361) are not considered until the [final conditional branch](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L459-L471) shown below:

```solidity
} else {
    avaxRedemptionAmount = avaxDepositAmount + registration.rewardAmount;
    qiRedemptionAmount = qiDepositAmount;

    if (qiRewardEligibilityByNodeId[nodeId]) {
        qiRedemptionAmount += validatorRewarder.claimRewards(
            registration.validationDuration,
            registration.tokenDeposits.tokenAmount
        );
    }

    minimumContractBalance -= avaxRedemptionAmount;
}
```

This is fine for registrations made with `AVAX` stake, since the reward amount is never updated from `0`; however, for those made with pre-validated QI stake, the call to `ValidatorRewarder::claimRewards` is executed regardless, returning the original stake in QI plus QI rewards for the full duration.

Furthermore, this behavior could be abused by the Zeeve admin to drain `QI` tokens from the `ValidatorRewarder` contract. Assuming interactions are made directly with the deployed contracts to bypass frontend checks, a faulty BLS proof can be provided to `StakingContract::registerNode` – this BLS proof is validated by an off-chain service when the `NewRegistration` event is detected, and `Ignite::releaseLockedTokens` will be called if it is invalid.

While Zeeve is somewhat of a trusted entity, they could very easily and relatively inconspicuously stake with burner user addresses, forcing the failure of BLS proof validation to drain the `ValidatorRewarder` contract due to the behavior of this off-chain logic in conjunction with the incorrect handling of `QI` rewards for failed registrations.

**Impact:** `QI` rewards will be paid to users of failed registrations made via `Ignite::registerWithPrevalidatedQiStake`. If abused by the Zeeve admin, then entire `ValidatorRewarder` contract balance could be drained.

**Proof of Concept:** The following test can be added to `Ignite.test.js` under `describe("Superpools")`:

```javascript
it("earns qi rewards for failed registrations", async function () {
  await validatorRewarder.setTargetApr(1000);
  await ignite.setValidatorRewarder(validatorRewarder.address);
  await grantRole("ROLE_RELEASE_LOCKED_TOKENS", admin.address);

  // AVAX $20, QI $0.01
  const qiStake = hre.ethers.utils.parseEther("200").mul(2_000);
  const qiFee = hre.ethers.utils.parseEther("1").mul(2_000);

  // approve Ignite to spend pre-validated QI (bypassing StakingContract)
  await qi.approve(ignite.address, qiStake.add(qiFee));
  await ignite.registerWithPrevalidatedQiStake(
    admin.address,
    "NodeID-Superpools1",
    "0x" + blsPoP.toString("hex"),
    86400 * 28,
    qiStake.add(qiFee),
  );

  // registration of node fails
  await ignite.releaseLockedTokens("NodeID-Superpools1", true);

  const balanceBefore = await qi.balanceOf(admin.address);
  await ignite.connect(admin).redeemAfterExpiry("NodeID-Superpools1");

  const balanceAfter = await qi.balanceOf(admin.address);

  // stake + rewards are returned to the user
  expect(Number(balanceAfter.sub(balanceBefore))).to.be.greaterThan(Number(qiStake));
});
```

**Recommended Mitigation:** Avoid paying QI rewards to failed registrations by resetting the `qiRewardEligibilityByNodeId` state in `Ignite::releaseLockedTokens`:

```diff
    } else {
        minimumContractBalance += msg.value;
        totalSubsidisedAmount -= 2000e18 - msg.value;
+       qiRewardEligibilityByNodeId[nodeId] = false;
    }
```

**BENQI:** Fixed in commit [0255923](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/0255923e9c0d23c3fde71a6bdf1237ec4677c02d).

**Cyfrin:** Verified, `QI` rewards are no longer granted to failed registrations.

\clearpage
## Medium Risk


### Redemption of slashed registrations could result in DoS due to incorrect state update

**Description:** Due to the logic surrounding Pay As You Go (PAYG) registrations, potential refunds associated with failed validators, and post-expiry redemptions of stake, a minimum balance of `AVAX` is required to remain within the `Ignite` contract. The [`IgniteStorage::minimumContractBalance`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/IgniteStorage.sol#L97-L98) state variable is responsible for keeping track of this balance and ensuring that [`Ignite::withdraw`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L556-L572) transfers the appropriate amount of `AVAX` to start validation.

When the validation period for a given registration has expired, [`Ignite::releaseLockedTokens`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L574-L707) is called by the privileged `ROLE_RELEASE_LOCKED_TOKENS` actor along with the redeemable tokens. If the registration is slashed, `minimumContractBalance` is [updated](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L695-L697) to include `msg.value` less the slashed amount. Finally, when [`Ignite::redeemAfterExpiry`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L402-L481) is called by the original registerer to redeem the tokens, the `minimumContractBalance` state is again updated to discount this withdrawn amount.

However, this [state update](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L458) is incorrect as it should decrement the `avaxRedemptionAmount` rather than the `avaxDepositAmount` (which includes the already-accounted-for slashed amount). Therefore, `minimumContractBalance` will be smaller than intended, resulting in redemptions reverting due to underflow of the decrement or if a call to `Ignite::withdraw` leaves the contract with insufficient balance to fulfill its obligations.

**Impact:** Redemptions could revert if the current redemption is slashed and the state update underflows or if an earlier redemption is slashed and more `AVAX` is withdrawn than intended.

**Proof of Concept:** The following test can be added under `describe("users can withdraw tokens after the registration becomes withdrawable")` in `ignite.test.js`:

```javascript
it("with slashing using a slash percentage", async function () {
  // Add AVAX slashing percentage to trigger the bug (50% so the numbers are easy)
  await ignite.setAvaxSlashPercentage("5000");

  // Register NodeID-1 for two weeks with 1000 AVAX and 200k QI
  await ignite.registerWithStake("NodeID-1", blsPoP, 86400 * 14, {
    value: hre.ethers.utils.parseEther("1000"),
  });

  // Release the registration with `msg.value` equal to AVAX deposit amount to trigger slashing
  await ignite.releaseLockedTokens("NodeID-1", false, {
    value: hre.ethers.utils.parseEther("1000"),
  });

  // The slashed amount is decremented from the minumum contract balance
  expect(await ignite.minimumContractBalance()).to.equal(hre.ethers.utils.parseEther("500"));

  // Reverts on underflow since it tries to subtract 1000 (avaxDepositAmount) from 500 (minimumContractBalance)
  await expect(ignite.redeemAfterExpiry("NodeID-1")).to.be.reverted;
});
```

Note that this is not an issue for the existing deployed version of this contract as the AVAX slash percentage is zero.

**Recommended Mitigation:** Decrement `minimumContractBalance` by `avaxRedemptionAmount` instead of `avaxDepositAmount`:

```diff
if (registration.slashed) {
    avaxRedemptionAmount = avaxDepositAmount - avaxDepositAmount * registration.avaxSlashPercentage / 10_000;
    qiRedemptionAmount = qiDepositAmount - qiDepositAmount * registration.qiSlashPercentage / 10_000;

-   minimumContractBalance -= avaxDepositAmount;
+   minimumContractBalance -= avaxRedemptionAmount;
} else {
```

**BENQI:** Fixed in commit [fb686b8](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/fb686b85ca88b0d90404f46f959f505fc1674fc0).

**Cyfrin:** Verified. The correct state update is now applied.


### The default admin role controls all other roles within `StakingContract`

**Description:** Within `StakingContract`, there is intended separation between the Zeeve and BENQI admin/super-admin roles as implemented in the [`grantAdminRole()`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L986), [`revokeAdminRole()`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L1017), and [`updateAdminRole()`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L1048) functions. The intention is for admin roles to be managed by the corresponding super-admin; however, `AccessControlUpgradeable::_setRoleAdmin` is never invoked for any of the roles and the current implementation fails to consider the default admin role that is [granted to the BENQI super-admin](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L169) for pausing purposes when the contract is initialized. As a result, the BENQI super-admin can be used to manage all other roles by invoking `AccessControlUpgradeable::grantRole` and `AccessControlUpgradeable::revokeRole` directly. This behavior is used in `Ignite` and `ValidatorRewarder` to grant the appropriate roles; however, it is not desirable in `StakingContract`.

**Impact:** The default admin role granted to the BENQI super-admin can be used to control all other roles.

**Proof of Concept:** The following test can be added to `stakingContract.test.js` under `describe("updateAdminRole")`:

```javascript
it("allows BENQI_SUPER_ADMIN to update ZEEVE_SUPER_ADMIN", async function () {
    const zeeveSuperAdminRole = await stakingContract.ZEEVE_SUPER_ADMIN_ROLE();

    // BENQI_SUPER_ADMIN can use OpenZepplin's grantRole to alter ZEEVE_SUPER_ADMIN_ROLE
    await stakingContract.connect(benqiSuperAdmin).grantRole(zeeveSuperAdminRole, otherUser.address);
    await stakingContract.connect(benqiSuperAdmin).revokeRole(zeeveSuperAdminRole, zeeveSuperAdmin.address);

    expect(await stakingContract.hasRole(zeeveSuperAdminRole, otherUser.address)).to.be.true;
    expect(await stakingContract.hasRole(zeeveSuperAdminRole, zeeveSuperAdmin.address)).to.be.false;
});
```

An equivalent Foundry test can be run with the provided fixtures:

```solidity
function test_defaultAdminControlsAllRolesPoC() public {
    assertEq(stakingContract.getRoleAdmin(stakingContract.DEFAULT_ADMIN_ROLE()), stakingContract.DEFAULT_ADMIN_ROLE());
    assertEq(stakingContract.getRoleAdmin(stakingContract.BENQI_SUPER_ADMIN_ROLE()), stakingContract.DEFAULT_ADMIN_ROLE());
    assertEq(stakingContract.getRoleAdmin(stakingContract.BENQI_ADMIN_ROLE()), stakingContract.DEFAULT_ADMIN_ROLE());
    assertEq(stakingContract.getRoleAdmin(stakingContract.ZEEVE_SUPER_ADMIN_ROLE()), stakingContract.DEFAULT_ADMIN_ROLE());
    assertEq(stakingContract.getRoleAdmin(stakingContract.ZEEVE_ADMIN_ROLE()), stakingContract.DEFAULT_ADMIN_ROLE());

    address EXTERNAL_ADDRESS = makeAddr("EXTERNAL_ADDRESS");
    vm.startPrank(BENQI_SUPER_ADMIN);
    stakingContract.grantRole(stakingContract.ZEEVE_SUPER_ADMIN_ROLE(), EXTERNAL_ADDRESS);
    vm.stopPrank();
    assertTrue(stakingContract.hasRole(stakingContract.ZEEVE_SUPER_ADMIN_ROLE(), EXTERNAL_ADDRESS));
}
```

**Recommended Mitigation:** Consider either:
1. Setting the appropriate role admins during initialization.
2. Removing the default admin role and creating a separate pauser role.
3. Overriding the OpenZeppelin functions to prevent them from being called directly.

**BENQI:** Fixed in commit [491a278](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/491a278be80605bbf23cef71bed5227ea11d201e).

**Cyfrin:** Verified. The OpenZeppelin function have been overridden.


### Inconsistent transfers of native tokens could result in unexpected loss of funds

**Description:** Multiple protocol functions across both `Ignite` and `StakingContract` transfer native `AVAX` to the user and/or protocol fee/slashed token recipients.

Throughout `Ignite` [[1](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L215), [2](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L427), [3](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L477), [4](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L563), [5](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L639), [6](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L699)], the low-level `.call()` pattern is used; however, this same behavior is not followed in `StakingContract` – the `.transfer()` function is used on lines [433](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L433) and [484](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L484), and on line [728](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L728-L733) `_transferETHAndWrapIfFailWithGasLimit()` is used, all with a `2300` gas stipend.

While these other functions may have been used to mitigate against potential re-entrancy attacks, native token transfers using low-level calls are preferred over `.transfer()` to mitigate against changes in gas costs, as described [here](https://consensys.io/diligence/blog/2019/09/stop-using-soliditys-transfer-now/). The instances on lines 433 and 484 are particularly problematic as they have no `WAVAX` fallback and could result in an unexpected loss of funds as described [here](https://solodit.xyz/issues/m-01-swapsol-implements-potentially-dangerous-transfer-code4rena-tally-tally-contest-git) and in the linked examples.

**Impact:** There could be an unexpected loss of funds if the recipient of a transfer (applicable to both users and the Zeeve wallet) is a smart contract that fails to implement a payable fallback function, or the fallback function uses more than 2300 gas units. This could happen, for example, if the recipient is a smart account whose fallback function logic causes the execution to use more than 2300 gas.

**Recommended Mitigation:** Consider modifying the instances of native token transfers in `StakingContract` to use low-level calls, making the necessary adjustments to protect against re-entrancy.

**BENQI:** Fixed in commit [ee98629](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/ee98629daa2b815de4102d9af86f27fb36af67cf).

**Cyfrin:** Verified. The `_transferETHAndWrapIfFailWithGasLimit()` function is now used throughout `StakingContract`.


### Redemption of failed registration fees and pre-validated QI is not guaranteed to be possible

**Description:** [`Ignite::registerWithStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L202) performs a [low-level call](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L215-L216) as part of its validation to ensure the beneficiary,in this case `msg.sender`, can receive `AVAX`:

```solidity
// Verify that the sender can receive AVAX
(bool success, ) = msg.sender.call("");
require(success);
```

However, this is missing from [`Ignite::registerWithAvaxFee`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L251), meaning that failed registration fees are not guaranteed to be redeemable if the sender is a contract that cannot receive `AVAX`.

Similarly, [`Ignite::registerWithPrevalidatedQiStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L361) performs no such validation on the beneficiary. While this may not seem to be problematic, since the stake requirement is provided in `QI`, there is a [low-level call](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L477-L478) in [`Ignite::redeemAfterExpiry`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L407) that will attempt a zero-value transfer for pre-validated `QI` stakes:

```solidity
(bool success, ) = msg.sender.call{ value: avaxRedemptionAmount}("");
require(success);
```

If the specified beneficiary is a contract without a payable fallback/receive function then this call will fail. Furthermore, if this beneficiary contract is immutable, the `QI` stake will be locked in the `Ignite` contract unless it is upgraded.

**Impact:** Failed `AVAX` registration fees and prevalidated `QI` stakes will remain locked in the `Ignite` contract.

**Proof of Concept:** The following standalone Forge test demonstrates the behavior described above:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";

contract A {}

contract TestPayable is Test {
    address eoa;
    A a;

    function setUp() public {
        eoa = makeAddr("EOA");
        a = new A();
    }

    function test_payable() external {
        // Attempt to call an EOA with zero-value transfer
        (bool success, ) = eoa.call{value: 0 ether}("");

        // Assert that the call succeeded
        assertEq(success, true);

        // Attempt to call a contract that does not have a payable fallback/receive function with zero-value transfer
        (success, ) = address(a).call{value: 0 ether}("");

        // Assert that the call failed
        assertEq(success, false);
    }
}
```

**Recommended Mitigation:** Consider adding validation to `Ignite::registerWithAvaxFee` and `Ignite::registerWithPrevalidatedQiStake`. If performing a low-level call within `Ignite::registerWithPrevalidatedQiStake`, also consider adding the `nonReentrant` modifier.

**BENQI:** Fixed in commit [7d45908](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/7d45908fce2eefec90e5a67963311b250ae8c748). There will no longer be a native token transfer for pre-validated QI stake registrations since this non-zero check is added before the call in commit [f671224](https://github.com/Benqi-fi/ignite-contracts/blob/f67122426c5dff6023da1ec9602c1959703db28e/src/Ignite.sol#L478-L481).

**Cyfrin:** Verified. The low-level call has been added to `Ignite::registerWithAvaxFee` and pre-validated QI stake registrations no longer have a zero-value call on redemption.


### Ignite fee is not returned for pre-validated `QI` stakes in the event of registration failure

**Description:** The `1 AVAX` [Ignite fee](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L387) applied to pre-validated `QI` stakes is [paid to the fee recipient](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L388) at the time of registration. If this registration fails (e.g. due to off-chain BLS proof validation), the registration will be [marked as withdrawable](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L620) once `Ignite::releaseLockedTokens` is called; however, since the fee has already been paid and [deducted from the user's stake amount](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L397), it will not be returned with the refunded `QI` stake. This behavior differs from the other registration methods, which all refund the usually non-refundable fee in the event of registration failure.

**Impact:** Users who register with a hosted Zeeve validator will not be refunded the Ignite fee if registration fails.

**Recommended Mitigation:** Refund the Ignite fee if registration fails for pre-validated `QI` stakes.

**BENQI:** Fixed in commit [f671224](https://github.com/Benqi-fi/ignite-contracts/commit/f67122426c5dff6023da1ec9602c1959703db28e).

**Cyfrin:** Verified. The fee is now taken from successful registrations during the call to `Ignite::releaseLockedTokens`.

\clearpage
## Low Risk


### `StakingContract` refunds are affected by global parameter updates

**Description:** When [`StakingContract::refundStakedAmount`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L691-741) is called by the BENQI admin, the following validation is performed using the globally-defined `refundPeriod`:

```solidity
require(
    block.timestamp > record.timestamp + refundPeriod,
    "Refund period not reached"
);
```

The [`StakingContract::StakeRecord`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L69-77) struct does not have a corresponding member and so does not store the value of `refundPeriod` at the time of staking; however, if [`StakingContract::setRefundPeriod`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L675-689) is called with an updated period then that of an existing record could be shorter/longer than expected.

**Impact:** The refund period for existing records could be affected by global parameter updates.

**Recommended Mitigation:** Consider adding an additional member to the `StakeRecord` struct to store the value of `refundPeriod` at the time of staking.

**BENQI:** Acknowledged, working as expected.

**Cyfrin:** Acknowledged.


### Insufficient validation of Chainlink price feeds

**Description:** Validation of the `price` and `updatedAt` values returned by Chainlink `AggregatorV3Interface::latestRoundData` is performed within the following functions:
- [`StakingContract::_validateAndSetPriceFeed`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L923-925)
- [`StakingContract::_getPriceInUSD`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L937-943)
- [`Ignite::_initialisePriceFeeds`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L187-L189)
- [`Ignite::registerWithStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L218-L223)
- [`Ignite::registerWithErc20Fee`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L291-L296)
- [`Ignite::registerWithPrevalidatedQiStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L373-L378)
- [`Ignite::addPaymentToken`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L806-L808)
- [`Ignite::configurePriceFeed`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L856-L858)

However, there is additional validation shown below that is recommended but currently not present:

```solidity
(uint80 roundId, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
if(roundId == 0) revert InvalidRoundId();
if(updatedAt == 0 || updatedAt > block.timestamp) revert InvalidUpdate();
```

**Impact:** The impact is limited because the most important price and staleness validation are already present.

**Recommended Mitigation:** Consider including this additional validation and consolidating it into a single internal function.

**BENQI:** Acknowledged, current validation is deemed sufficient.

**Cyfrin:** Acknowledged.


### Incorrect operator when validating subsidisation cap

**Description:** When a new registration is created, `Ignite::_registerWithChecks` [validates](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L925-L928) that the subsidisation amount for the registration does not cause the maximum to be exceeded when added to the existing total subsidised amount:

```solidity
require(
    totalSubsidisedAmount + subsidisationAmount < maximumSubsidisationAmount,
    "Subsidisation cap exceeded"
);
```

However, the incorrect operator is used when performing this comparison.

**Impact:** Registrations that cause the maximum subsidization amount to be met exactly will revert.

**Recommended Mitigation:**
```diff
    require(
-       totalSubsidisedAmount + subsidisationAmount < maximumSubsidisationAmount,
+       totalSubsidisedAmount + subsidisationAmount <= maximumSubsidisationAmount,
        "Subsidisation cap exceeded"
    );
```

**BENQI:** Fixed in commit [37446f6](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/37446f681d9f09000bb22682a9a153a0c7b23548).

**Cyfrin:** Verified. The operator has been changed.


### `StakingContract::slippage` can be outside of `minSlippage` or `maxSlippage`

**Description:** When the BENQI admin sets the `slippage` state by calling [`StakingContract::setSlippage`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L313-328), it is validated that this new value is between the `minSlippage` and `maxSlippage` thresholds:

```solidity
require(
    _slippage >= minSlippage && _slippage <= maxSlippage,
    "Slippage must be between min and max"
);
```

The admin can also change both `minSlippage` and `maxSlippage` via [`StakingContract::setMinSlippage`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L330-345) and [`StakingContract::setMaxSlippage`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L347-360); however, neither of these functions has any validation that the `slippage` state variable remains within the boundaries.

**Impact:** Incorrect usage of either `StakingContract::setMaxSlippage` or `StakingContract::setMinSlippage` can result in the `slippage` state variable being outside the range.

**Proof of Concept:** The following test can be added to `stakingContract.test.js` under `describe("setSlippage")`:

```javascript
it("can have slippage outside of max and min", async function () {
    // slippage is set to 4
    await stakingContract.connect(benqiAdmin).setSlippage(4);
    // max slippage is updated below it
    await stakingContract.connect(benqiAdmin).setMaxSlippage(3);

    const slippage = await stakingContract.slippage();
    const maxSlippage = await stakingContract.maxSlippage();
    expect(slippage).to.be.greaterThan(maxSlippage);
});
```

**Recommended Mitigation:** Consider validating that the `slippage` state variable is within the boundaries set using `setMin/MaxSlippage()`.

**BENQI:** Fixed in commits [96e1b96](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/96e1b9610970259cffdf44fd7cf1af527016b0ce) and [dbb13c5](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/dbb13c55047e4ce52e39f833196fc78ed5c0cf8a).

**Cyfrin:** Verified.


### Lack of user-defined slippage and deadline parameters in `StakingContract::swapForQI` may result in unfavorable `QI` token swaps

**Description:** When a user interacts with `StakingContract` to provision a hosted node, they can choose between two methods:[`StakingContract::stakeWithAVAX`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L457-L511) or [`StakingContract::stakeWithERC20`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L513-L577). If the staked token is not `QI`, `StakingContract::swapForQI` is invoked to swap the staked token for `QI` via Trader Joe. Once created, the validator node is then [registered](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L441-448) with [`Ignite`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L353-L400), using `QI`, via `StakingContract::registerNode`.

Within the swap to `QI`, `amountOutMin` is [calculated](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L844) using Chainlink price data and a slippage parameter defined by the protocol:

```solidity
// Get the best price quote
uint256 slippageFactor = 100 - slippage; // Convert slippage percentage to factor
uint256 amountOutMin = (expectedQiAmount * slippageFactor) / 100; // Apply slippage
```

If the actual amount of `QI` received is below this `amountOutMin`, the transaction will [revert](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L897-L900); however, users are restricted by the protocol-defined slippage, which may not reflect their preferences if they desire a smaller slippage tolerance to ensure they receive a more favorable swap execution.

Additionally, the swap [deadline](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L863) specified as `block.timestamp` in `StakingContract::swapForQI` provides no protection as deadline validation will pass whenever the transaction is included in a block:

```solidity
uint256 deadline = block.timestamp;
```

This could expose users to unfavorable price fluctuations and again offers no option for users to provide their own deadline parameter.

**Impact:** Users may receive fewer `QI` tokens than expected due to the fixed slippage tolerance set by the protocol, potentially resulting in unfavorable swap outcomes.

**Recommended Mitigation:** Consider allowing users to provide a `minAmountOut` slippage parameter and a `deadline` parameter for the swap operation. The user-specified `minAmountOut` should override the protocol's slippage-adjusted amount if larger.

**BENQI:** Acknowledged, there is already a slippage check inside `StakingContract::swapForQI` based on the Chainlink pricing.

**Cyfrin:** Acknowledged.

\clearpage
## Informational


### `AccessControlUpgradeable::_setupRole` is deprecated

**Description:** In [`ValidatorRewarder::initialize`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L38-L59) the `DEFAULT_ADMIN_ROLE` is assigned using [`AccessControlUpgradeable::_setupRole`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L54):

```solidity
_setupRole(DEFAULT_ADMIN_ROLE, _admin);
```

This method has been deprecated by OpenZeppelin in favor of the `AccessControlUpgradeable::_grantRole` as written in their [documentation](https://docs.openzeppelin.com/contracts/4.x/api/access#AccessControl-_setupRole-bytes32-address-) and NatSpec:

```solidity
/**
 * @dev Grants `role` to `account`.
 * ...
 * NOTE: This function is deprecated in favor of {_grantRole}.
 */
function _setupRole(bytes32 role, address account) internal virtual {
    _grantRole(role, account);
}
```

Note that `Ignite::initialize` [also uses this](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L136), but since the contract is already initialized it is of no concern.

**Recommended Mitigation:** Consider using `AccessControlUpgradeable::_grantRole` in `ValidatorRewarder::initialize`, and possibly also in `Ignite::initialize`.

**BENQI:** Fixed in commit [8db7fb5](https://github.com/Benqi-fi/ignite-contracts/commit/8db7fb5d4c27be03aa8c48437a17d9cca3bbc32d).

**Cyfrin:** Verified.


### Unchained initializers should be called instead

**Description:** While not an immediate issue in the current implementation, the direct use of initializer functions rather than their unchained equivalents should be avoided. [`ValidatorRewarder::initialize`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L51-L52) and [`StakingContract::initialize`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L259-261) should be modified to avoid [potential duplicate initialization](https://docs.openzeppelin.com/contracts/5.x/upgradeable#multiple-inheritance) in the future.

Note that this is also relevant for [`Ignite::initialize`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L132-134), but since the contract is already initialized it is of no concern.

**Recommended Mitigation:** Consider using unchained initializers in `ValidatorRewarder::initialize`, `StakingContract::initialize`, and possibly also in `Ignite::initialize`.

**BENQI:** Fixed in commit [cd4d43e](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/cd4d43ea8397357b503a127d7ac7966b625a21b7).

**Cyfrin:** Verified. Unchained initializers are now used.


### Missing `onlyInitializing` modifier in `StakingContract`

**Description:** While it is not currently possible for the functions to be invoked elsewhere, both [`StakingContract::initializeRoles`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L152) and [`StakingContract::setInitialParameters`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L185) should be limited to being called during initialization but are missing the `onlyInitializing` modifier. Note that the latter is however handled by its [internal call](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L222-228) to [`StakingContract::_initializePriceFeeds`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L286) that does have it applied.

**Recommended Mitigation:** Consider adding the `onlyInitializing` modifier to `StakingContract::initializeRoles` and possibly also `StakingContract::setInitialParameters`.

**BENQI:** Fixed in commit [cd4d43e](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/cd4d43ea8397357b503a127d7ac7966b625a21b7).

**Cyfrin:** Verified. The modifier has been added.


### Unnecessary `amount` parameter in `StakingContract::stakeWithERC20`

**Description:** When provisioning a node through [`StakingContract::stakeWithERC20`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L513-L577), users can pay with a supported ERC20 token. The [`totalRequiredToken`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L527-530) is calculated based on the [`avaxStakeAmount`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L35) (needed to register the node in Ignite) and the [`hostingFee`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L525) (paid to Zeeve for hosting), before being [transferred](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L534-539) from the user to the contract:

```solidity
require(isTokenAccepted(token), "Token not accepted");
uint256 hostingFee = calculateHostingFee(duration);

uint256 totalRequiredToken = convertAvaxToToken(
    token,
    avaxStakeAmount + hostingFee
);

require(amount >= totalRequiredToken, "Insufficient token");

// Transfer tokens from the user to the contract
IERC20Upgradeable(token).safeTransferFrom(
    msg.sender,
    address(this),
    totalRequiredToken
);
```

The [`amount`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L521) parameter provided by the user is only used to validate that it covers the `totalRequiredToken`, but since execution will revert if the user has not given the contract sufficient allowance for the transfer, the `amount` parameter becomes redundant.

**Recommended Mitigation:** Consider removing the `amount` parameter from `StakingContract::stakeWithERC20`.

**BENQI:** Acknowledged. The purpose is to ensure that the value passed in by the frontend is not lower than the `totalRequiredToken`, acting as a form of slippage check. If it’s lesser than totalRequiredToken, more tokens could be deducted than the user expected.

**Cyfrin:** Acknowledged.


### Staking amount in QI should be calculated differently

**Description:** Currently, if the stake token is `QI`, `stakingAmountInQi` is [calculated](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L542-544) as shown below:

```solidity
stakingAmountInQi = totalRequiredToken - convertAvaxToToken(token, hostingFee);
```

However, this can result in a precision loss of 1 wei.

**Proof of Concept:** This was tested using a Forge fixture and logs within the source code.

**Recommended Mitigation:** Consider calculating `stakingAmountInQi` directly based on `avaxStakeAmount`.

**BENQI:** Acknowledged. 1 wei precision loss is fine.

**Cyfrin:** Acknowledged.


### Tokens with more than `18` decimals will not be supported

**Description:** Currently, tokens with more than `18` decimals are not supported due to the decimals handling logic in [`StakingContract::_getPriceInUSD`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L953):

```solidity
uint256 decimalDelta = uint256(18) - tokenDecimalDelta;
```

and [`Ignite::registerWithErc20Fee`:](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L299)

```solidity
uint tokenAmount = uint(avaxPrice) * registrationFee / uint(tokenPrice) / 10 ** (18 - token.decimals());
```

**Recommended Mitigation:** Modify this logic if tokens with a larger number of decimals are required to be supported.

**BENQI:** Acknowledged, working as expected.

**Cyfrin:** Acknowledged.


### Incorrect revert strings in `StakingContract::revokeAdminRole`

**Description:** There are two revert strings [[1](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L1021), [2](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L1036)], shown below, in `StakingContract::revokeAdminRole` that appear to have been copied incorrectly and should respectively instead be:
- "Cannot revoke role from the zero address"
- "Attempting to revoke an unrecognized role"

```solidity
function revokeAdminRole(bytes32 role, address account) public {
    // Ensure the account parameter is not a zero address to prevent accidental misassignments
    require(
        account != address(0),
        "Cannot assign role to the zero address"
    );

    /* snip: other conditionals */

    } else {
        // Optionally handle cases where an unknown role is attempted to be granted
        revert("Attempting to grant an unrecognized role");
    }

    /*snip: internal call & event emission */
}
```

**Recommended Mitigation:** Modify the revert strings as suggested.

**BENQI:** Fixed in commits [cd4d43e](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/cd4d43ea8397357b503a127d7ac7966b625a21b7) and [99d7f25](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/99d7f25404a8693f5385d91863b098cd0639bb35).

**Cyfrin:** Verified. The revert strings have been modified.


### Placeholder recipient constants in `Ignite` should be updated before deployment

**Description:** While it is understood that the [`FEE_RECIPIENT`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L43) and [`SLASHED_TOKEN_RECIPIENT`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L44) constants in `Ignite` have been modified for testing purposes, it is important to note that they should be reverted to valid values before deployment to ensure that fees and slashed tokens are not lost.

```solidity
address public constant FEE_RECIPIENT = 0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa; // @audit-info - update placeholder values
address public constant SLASHED_TOKEN_RECIPIENT = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;
```

**Recommended Mitigation:** Update the constants before performing the `Ignite` contract upgrade.

**BENQI:** Acknowledged, already in the checklist for deployments.

**Cyfrin:** Acknowledged.


### Missing modifiers

**Description:** Despite the use of OpenZeppelin libraries for re-entrancy guards and pausable functionality, not all external functions have the `nonReentrant` and pausable modifiers applied, so cross-function re-entrancy may be possible and functions could be called when not intended. Specifically:

- [`Ignite::registerWithStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L202), unlike other registration functions, is missing the `whenNotPaused` modifier.
- [`Ignite::registerWithPrevalidatedQiStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L361) is missing both the `nonReentrant` and `whenNotPaused` modifiers.
-  [`StakingContract::registerNode`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L400), which calls `Ignite::registerWithPrevalidatedQiStake`, does not have the `whenNotPaused` modifier applied either.
- The `whenPaused` and `whenNotPaused` modifiers are not applied to any of the pausable functions in both contracts. This is not strictly required but prescient to note.

**Recommended Mitigation:** Add the necessary modifiers where appropriate.

**BENQI:** The registration functions call `_register()` which enforces pause checks. The `nonReentrant` modifier was not added to `Ignite::registerWithPrevalidatedStake` since it is a permissioned function with no unsafe external calls. The `whenNotPaused` modifier has been added to `StakingContract::registerNode` in commit [4956824](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/4956824ad9703927c1eab68aa9b2e215cf91f62b).

**Cyfrin:** Verified.


### Incorrect assumption that Chainlink price feeds will always have the same decimals

**Description:** There are several instances [[1](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L227), [2](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L299), [3](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L381)] in `Ignite` where the decimal precision of Chainlink price feeds are assumed to be equal. Currently, this does not cause any issues as both `AVAX`, `QI`, and all other `USD` feeds return prices with `8` decimal precision, but this should be handled explicitly as `ETH` feeds return prices with `18` decimal precision as explained [here](https://ethereum.stackexchange.com/questions/92508/do-all-chainlink-feeds-return-prices-with-8-decimals-of-precision).

**Recommended Mitigation:** Consider explicit handling of Chainlink price feed decimals.

**BENQI:** Acknowledged, USD feeds always have eight decimals.

**Cyfrin:** Acknowledged.


### Typo in `Ignite::registerWithPrevalidatedQiStake` NatSpec

**Description:** There is a typo in the `Ignite::registerWithPrevalidatedQiStake` [NatSpec](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L355).

**Recommended Mitigation:**
```diff
  /**
   * @notice Register a new node with a prevalidated QI deposit amount
-  * @param  beneficiary User no whose behalf the registration is made
+  * @param  beneficiary User on whose behalf the registration is made
   * @param  nodeId Node ID of the validator
   * @param  blsProofOfPossession BLS proof of possession (public key + signature)
   * @param  validationDuration Duration of the validation in seconds
   * @param  qiAmount The amount of QI that was staked
  */
```

**BENQI:** Fixed in commit [50c7c1a](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/50c7c1a81cbe7058116e53d178f61f828993ebc9).

**Cyfrin:** Verified.


### Magic numbers should be replaced by constant variables

**Description:** The magic numbers `10_000`, `2000e18`, `201`/`201e18` are used throughout the `Ignite` contract but should be made constant variables instead.

**Recommended Mitigation:** Use constants in place of the magic numbers outlined above.

**BENQI:** Acknowledged, won’t change.

**Cyfrin:** Acknowledged.


### Misalignment of `pause()` and `unpause()` access controls across contracts

**Description:** All three contracts, `Ignite`, `ValidatorRewarder`, and `StakingContract`, have pausing functionality that can be triggered by accounts with special privileges; however, they all implement the access control differently:

- In `Ignite`, [`pause()`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L709-L716) can only be called by accounts granted the `ROLE_PAUSE` role and similarly for [`unpause()`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L718-L725) it is the `ROLE_UNPAUSE` role.

- In `ValidatorRewarder`, both [`pause()`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L126-L135) and [`unpause()`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L137-L146) can only be called by accounts granted the `ROLE_PAUSE` role. The role `ROLE_UNPAUSE` is [defined](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/ValidatorRewarder.sol#L22) but not used.

- In `StakingContract`, both [`pause()`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L627-L632) and [`unpause()`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L634-L639) are limited to accounts granted the role `DEFAULT_ADMIN_ROLE`.

**Recommended Mitigation:** Consider aligning the role configuration between all contracts, preferably using the `ROLE_PAUSE`/`ROLE_UNPAUSE` setup from `Ignite` as it gives the most flexibility.

**BENQI:** Acknowledged, won’t change.

**Cyfrin:** Acknowledged.


### Inconsistent price validation in `Ignite::registerWithStake`

**Description:** In [`Ignite::registerWithErc20Fee`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L294), [`Ignite::registerWithPrevalidatedQiStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L376), and [`StakingContract::_getPriceInUSD`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L939-942), prices are validated to be greater than `0`; however, in [`Ignite::registerWithStake`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L221), the `AVAX` price is validated to be greater than the `QI` price. While the `AVAX` price is currently significantly higher than the `QI` price and so will not result in any unwanted reverts, this validation is inconsistent with the other instances and should be modified.

**Recommended Mitigation:** Modify the validation to require the `AVAX` price to be greater than `0` instead of the `QI` price.

**BENQI:** Acknowledged, won’t change.

**Cyfrin:** Acknowledged.

\clearpage
## Gas Optimization


### Unnecessary validation of `EnumerableSet` functions

**Description:** When invoking `EnumerableSet::add` and `EnumerableSet::remove`, it is not necessary to first check whether an element [already exists](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/2f0bc58946db746c0d17a2b9d9a8e13f5a8edd7f/contracts/utils/structs/EnumerableSet.sol#L66) within the set as these functions perform the same validation internally. Instead, the return values should be checked.

Instances include: [`StakingContract::addToken`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L579-595), [`StakingContract::removeToken`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L597-610), [`Ignite::addPaymentToken`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L785-L811), and [`Ignite::removePaymentToken`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L813-L830).

**Recommended Mitigation:** Consider the following diff as an example:

```diff
function addToken(
    address token,
    address priceFeedAddress,
    uint256 maxPriceAge
) external onlyRole(BENQI_ADMIN_ROLE) {
-    require(!acceptedTokens.contains(token), "Token already exists");

    _validateAndSetPriceFeed(token, priceFeedAddress, maxPriceAge);
-    acceptedTokens.add(token);
+    require(acceptedTokens.add(token), "Token already exists");
    emit TokenAdded(token);
}
```

**BENQI:** Fixed in commits [4956824](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/4956824ad9703927c1eab68aa9b2e215cf91f62b) and [420ace6](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/commit/420ace61c598ca1fffc97c9d095b3fe0aafedc97).

**Cyfrin:** Verified. The validation has been updated.


### Unnecessary validation in `StakingContract::registerNode`

**Description:** When a new validator node has been created on behalf of a user, the Zeeve admin reports this by calling `StakingContract::registerNode` which performs some validation before invoking `Ignite::registerWithPrevalidatedQiStake` to register the node according to the requirements in `Ignite`.

Some of this validation done in `StakingContract::registerNode`, shown below, is unnecessary and can be removed.

```solidity
require(
    bytes(nodeId).length > 0 && blsProofOfPossession.length > 0,
    "Invalid node or BLS key"
);
require(
    igniteContract.registrationIndicesByNodeId(nodeId) == 0,
    "Node ID already registered"
);
```

All of [this validation](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L406-413) around `nodeId`, `blsProofOfPossesion`, and the registration index is [performed again](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L973-L979) in `Ignite::_register`.

```solidity
// Retrieve the staking details from the stored records
require(stakeRecords[user].stakeCount > 0, "Staking details not found");
require(index < stakeRecords[user].stakeCount, "Index out of bounds"); // Ensures the index is valid

StakeRecord storage record = stakeRecords[user].records[index]; // Access the record by index
```

If [these requirements](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L414-416) were removed, an invalid index or zero stake count would result in an uninitialized `StakeRecord being [returned](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L418). Thus, execution would revert on all of the subsequent requirements:

```solidity
require(record.timestamp != 0, "Staking details not found");
require(isValidDuration(record.duration), "Invalid duration");
// Ensure the staking status is Provisioning
require(
    record.status == StakingStatus.Provisioning,
    "Invalid staking status"
);
```

Even still, the [timestamp validation](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L419) is superfluous as there is no way for an existing record to have an uninitialized `timestamp`, and the record is guaranteed to exist by the subsequent check on [`status`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L422-425). This means that the [`duration`](https://code.zeeve.net/zeeve-endeavors/benqi_smartcontract/-/blob/b63336201f50f9a67451bf5c7b32ddcc4a847ce2/contracts/staking.sol#L420) validation is also unnecessary, as it is not needed to guarantee the existence of a record and is performed again in [`Ignite::_regiserWithChecks`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L930-L936).

**Recommended Mitigation:** Consider removing the unnecessary validation outlined above.

**BENQI:** Acknowledged. Kept as a redundancy check.

**Cyfrin:** Acknowledged.


### Unnecessary conditional block in `Ignite::getTotalRegistrations` can removed

**Description:** The conditional in [`Ignite::getTotalRegistrations`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L483-L494) is intended to handle the case where there are no registrations aside from the default placeholder registration; however, this is unnecessary because the function would still return `0` without this check if the `registrations.length` is `1`, and due to the presence of the default placeholder registration, it should not be possible to reach a state where `registrations.length` is `0`.

```solidity
function getTotalRegistrations() external view returns (uint) {
    if (registrations.length <= 1) {
        return 0;
    }

    // Subtract 1 because the first registration is a dummy registration
    return registrations.length - 1;
}
```

**Recommended Mitigation:** Consider removing the conditional block.

**BENQI:** Fixed in commit [58af671](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/58af6717bb96410e364f3da3f57a85e7577cac36).

**Cyfrin:** Verified. Validation has been removed.


### Unnecessary validation in `Ignite::getRegistrationsByAccount`

**Description:** In [`Ignite::getRegistrationsByAccount`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L512-L536), there is [validation](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L526-L527) performed on the indices passed as arguments to the function:

```solidity
require(from < to, "From value must be lower than to value");
require(to <= numRegistrations, "To value must be at most equal to the number of registrations");
```

This is not necessary as the call will revert due to underflow [here](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L529) or index out-of-bounds [here](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L532). In the case `to == from`, an empty array would be returned.

**Recommended Mitigation:** Consider removing the validation shown above.

**BENQI:** Fixed in commit [82cf4fc](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/82cf4fc9f753339460e41bc240a572d89c6fd7a8).

**Cyfrin:** Verified. Validation has been removed.


### Unnecessary price feed address validation in `Ignite::configurePriceFeed`

**Description:** Unlike [`Ignite::addPaymentToken`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L791), which performs no validation on the price feed address itself, and only the data it returns, [`Ignite::configurePriceFeed`](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L838) first [validates](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L844) that the price feed address is not `address(0)`. This is not necessary as the [call](https://github.com/Benqi-fi/ignite-contracts/blob/bbca0ddb399225f378c1d774fb70a7486e655eea/src/Ignite.sol#L856) to `AggregatorV3Interface::latestRoundData` would revert during abi decoding of the return data.

**Proof of Concept:** The following standalone Forge test can be used to demonstrate this:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";

contract TestZeroAddressCall is Test {
    function test_zeroAddressCall() external {
        vm.expectRevert(); // see: https://book.getfoundry.sh/cheatcodes/expect-revert#gotcha:~:text=%E2%9A%A0%EF%B8%8F%20Gotcha%3A%20Usage%20with%20low%2Dlevel%20calls
        (bool revertsAsExpected, bytes memory returnData) =
            address(0).call(abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector));
        assertFalse(revertsAsExpected); // the call itself does not revert

        vm.expectRevert(); // it's the decode step that reverts
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            abi.decode(returnData, (uint80, int256, uint256, uint256, uint80));
    }
}

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

```

**Recommended Mitigation:** Consider removing the validation.

**BENQI:** Fixed in commit [7cbe588](https://github.com/Benqi-fi/ignite-contracts/pull/16/commits/7cbe58883cad6da79831b83fff96c2fefe348cdb).

**Cyfrin:** Verified. Validation has been removed and the corresponding test has been updated.

\clearpage