**Lead Auditors**

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

[Carlos Amarante](https://twitter.com/carlitox477)

**Assisting Auditors**



---

# Findings
## High Risk

### Migration of unripe LP from BEAN:3CRV to BEAN:ETH does not account for recapitalization accounting error
**Description:** The global [`AppStorage::recapitalized`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/AppStorage.sol#L485) state refers to the dollar amount recapitalized when Fertilizer was bought with USDC and paired with BEAN for BEAN:3CRV LP. When removing this underlying liquidity and swapping 3CRV for WETH during the migration of unripe LP, it is very likely that the BCM will experience some slippage. This is more likely to be the case if the swap is made on the open market rather than an OTC deal, but either way it is likely that the dollar value of the resulting WETH, and hence BEAN:ETH LP, will be less than it was as BEAN:3CRV before the migration. Currently, [`UnripeFacet::addMigratedUnderlying`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/barn/UnripeFacet.sol#L257) updates the BEAN:ETH LP token balance underlying the unripe LP, completing the migration, but does not account for any changes in the dollar value as outlined above. Based on the current implementation, it is very likely that the BCM will complete migration by transferring less in dollar value while the recapitalization status remains the same, causing inconsistency in [`LibUnripe::percentLPRecapped`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibUnripe.sol#L30-L36) and `LibUnripe::add/removeUnderlying` which are used in the conversion of urBEAN ↔ urBEANETH in `LibUnripeConvert`. Therefore, the global recapitalized state should be updated to reflect the true dollar value of recapitalization on completion of the migration.

**Impact:** Once sufficiently funded by purchasers of Fertilizer, it is possible that recapitalization could be considered completed with insufficient underlying BEAN:ETH LP. This amounts to a loss of user funds since the true recapitalized amount will be less than that specified by [`C::dollarPerUnripeLP`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/C.sol#L190-L192) which is used to calculate the total dollar liability in [`LibFertilizer::remainingRecapitalization`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L159-L163).

**Recommended Mitigation:** Reassign `s.recapitalized` to the oracle USD amount of the new BEAN:ETH LP at the time of migration completion.

```diff
    function addMigratedUnderlying(address unripeToken, uint256 amount) external payable nonReentrant {
        LibDiamond.enforceIsContractOwner();
        IERC20(s.u[unripeToken].underlyingToken).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );
        LibUnripe.incrementUnderlying(unripeToken, amount);

+       uint256 recapitalized = amount.mul(LibEthUsdOracle.getEthUsdPrice()).div(1e18);
+       require(recapitalized != 0, "UnripeFacet: cannot calculate recapitalized");
+       s.recapitalized = s.recapitalized.add(recapitalized);
    }
```

**Beanstalk Farms:** This is intentional – the cost of slippage goes to the Unripe LP token holders. This should be clearly stated in the BIP draft.

**Cyfrin:** Acknowledged.


## Medium Risk

### Insufficient validation of new Fertilizer IDs allow for a denial-of-service (DoS) attack on `SeasonFacet::gm` when above peg, once the last element in the FIFO is paid

**Description:** A Fertilizer NFT can be interpreted as a bond without an expiration date which is to be repaid in Beans and includes interest (Humidity). This bond is placed in a FIFO list and intended to recapitalize the $77 million in liquidity stolen during the [April 2022 exploit](https://docs.bean.money/almanac/farm/barn). One Fertilizer can be purchased for 1 USD worth of WETH: prior to BIP-38, this purchase was made using USDC.

Each fertilizer is identified by an Id that depends on `s.bpf`, indicating the cumulative amount of Beans paid per Fertilizer. This value increases each time [`Sun::rewardToFertilizer`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/sun/SeasonFacet/Sun.sol#L153) is called, invoked by `SeasonFacet::gm` if the Bean price is above peg. Therefore, Fertilizer IDs depend on `s.bpf` [at the moment of minting](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L45-L51), in addition to the [amount of Beans to be paid](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L64-L66).

The FIFO list has following components:
* `s.fFirst`: Fertilizer Id corresponding to the next Fertilizer to be paid.
* `s.fLast`: The highest active Fertilizer Id which is the last Fertilizer to be paid.
* `s.nextFid`: Mapping from Fertilizer Id to Fertilizer id, indicating the next element of a [linked list](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/AppStorage.sol#L477-L477). If an Id points to 0, then there is no next element.

Methods related to this FIFO list include:
`LibFertilizer::push`: Add an element to the FIFO list.
`LibFertilizer::setNext`: Given a fertilizer id, add a pointer to next element in the list
`LibFertilizer::getNext`: Get next element in the list.

The intended behaviour of this list is to add a new element to its end whenever a new fertilizer is minted with a new Id. Intermediate addition to the list was formerly allowed only by the Beanstalk DAO, but this functionality has since been deprecated in the current upgrade with the removal of `FertilizerFacet::addFertilizerOwner`.

*Consequences of replacing BEAN:3CRV MetaPool with the BEAN:ETH Well:*
Before this upgrade, addition of 0 Fertilizer through `LibFertilizer::addFertilizer` was impossible due to the dependency on Curve in `LibFertilizer::addUnderlying`:

```solidity
// Previous code

    function addUnderlying(uint256 amount, uint256 minAmountOut) internal {
        //...
        C.bean().mint(
            address(this),
            newDepositedBeans.add(newDepositedLPBeans)
        );

        // Add Liquidity
        uint256 newLP = C.curveZap().add_liquidity(
            C.CURVE_BEAN_METAPOOL, // where to add liquidity
            [
                newDepositedLPBeans, // BEANS to add
                0,
                amount, // USDC to add
                0
            ], // how much of each token to add
            minAmountOut // min lp ampount to receive
        ); // @audit-ok Does not admit depositing 0 --> https://etherscan.io/address/0x5F890841f657d90E081bAbdB532A05996Af79Fe6#code#L487

        // Increment underlying balances of Unripe Tokens
        LibUnripe.incrementUnderlying(C.UNRIPE_BEAN, newDepositedBeans);
        LibUnripe.incrementUnderlying(C.UNRIPE_LP, newLP);

        s.recapitalized = s.recapitalized.add(amount);
    }
```

However, with the change of dependency involved in the Wells integration, this restriction no longer holds:
```solidity
    function addUnderlying(uint256 usdAmount, uint256 minAmountOut) internal {
        AppStorage storage s = LibAppStorage.diamondStorage();
        // Calculate how many new Deposited Beans will be minted
        uint256 percentToFill = usdAmount.mul(C.precision()).div(
            remainingRecapitalization()
        );
        uint256 newDepositedBeans;
        if (C.unripeBean().totalSupply() > s.u[C.UNRIPE_BEAN].balanceOfUnderlying) {
            newDepositedBeans = (C.unripeBean().totalSupply()).sub(
                s.u[C.UNRIPE_BEAN].balanceOfUnderlying
            );
            newDepositedBeans = newDepositedBeans.mul(percentToFill).div(
                C.precision()
            );
        }

        // Calculate how many Beans to add as LP
        uint256 newDepositedLPBeans = usdAmount.mul(C.exploitAddLPRatio()).div(
            DECIMALS
        );

        // Mint the Deposited Beans to Beanstalk.
        C.bean().mint(
            address(this),
            newDepositedBeans
        );

        // Mint the LP Beans to the Well to sync.
        C.bean().mint(
            address(C.BEAN_ETH_WELL),
            newDepositedLPBeans
        );

        // @audit If nothing was previously deposited this function returns 0, IT DOES NOT REVERT
        uint256 newLP = IWell(C.BEAN_ETH_WELL).sync(
            address(this),
            minAmountOut
        );

        // Increment underlying balances of Unripe Tokens
        LibUnripe.incrementUnderlying(C.UNRIPE_BEAN, newDepositedBeans);
        LibUnripe.incrementUnderlying(C.UNRIPE_LP, newLP);

        s.recapitalized = s.recapitalized.add(usdAmount);
    }
```

Given that the new integration does not revert when attempting to add 0 Fertilizer, it is now possible to add a self-referential node to the end FIFO list, but only if this is the first Fertilizer NFT to be minted for the current season by twice calling `FertilizerFacet.mintFertilizer(0, 0, 0, mode)`. The [validation](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L57-L58) performed to prevent duplicate ids is erroneously bypassed given the Fertilizer amount for the given Id remains zero.

```solidity
    function push(uint128 id) internal {
        AppStorage storage s = LibAppStorage.diamondStorage();
        if (s.fFirst == 0) {
            // Queue is empty
            s.season.fertilizing = true;
            s.fLast = id;
            s.fFirst = id;
        } else if (id <= s.fFirst) {
            // Add to front of queue
            setNext(id, s.fFirst);
            s.fFirst = id;
        } else if (id >= s.fLast) { // @audit this block is entered twice
            // Add to back of queue
            setNext(s.fLast, id); // @audit the second time, a reference is added to the same id
            s.fLast = id;
        } else {
            // Add to middle of queue
            uint128 prev = s.fFirst;
            uint128 next = getNext(prev);
            // Search for proper place in line
            while (id > next) {
                prev = next;
                next = getNext(next);
            }
            setNext(prev, id);
            setNext(id, next);
        }
    }
```
Despite first perhaps seeming harmless, this element can never be remove unless otherwise overridden:

```solidity
    function pop() internal returns (bool) {
        AppStorage storage s = LibAppStorage.diamondStorage();
        uint128 first = s.fFirst;
        s.activeFertilizer = s.activeFertilizer.sub(getAmount(first)); // @audit getAmount(first) would return 0
        uint128 next = getNext(first);
        if (next == 0) { // @audit next != 0, therefore this conditional block is skipped
            // If all Unfertilized Beans have been fertilized, delete line.
            require(s.activeFertilizer == 0, "Still active fertilizer");
            s.fFirst = 0;
            s.fLast = 0;
            s.season.fertilizing = false;
            return false;
        }
        s.fFirst = getNext(first); // @audit this gets s.first again
        return true; // @audit always returns true for a self-referential node
    }
```

`LibFertilizer::pop` is used in [`Sun::rewardToFertilizer`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/sun/SeasonFacet/Sun.sol#L132-L150) which is called through [`Sun::rewardBeans`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/sun/SeasonFacet/Sun.sol#L97) when fertilizing. This function is called through [`Sun::stepSun`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/sun/SeasonFacet/Sun.sol#L73) if the current Bean price is above peg. By preventing the last element from being popped from the list, assuming this element is reached, an infinite loop occurs given that the `while` loop continues to execute, resulting in denial-of-service on [`SeasonFacet::gm`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/sun/SeasonFacet/SeasonFacet.sol#L59) when above peg.

The most remarkable detail of this issue is that this state can be forced when above peg and having already been fully recapitalized. Given that it is not possible to mint additional Fertilizer with the associated Beans, this means that a DoS attack can be performed on `SeasonFacet::gm` once recapitalization is reached if the BEAN price is above peg.

**Impact:** It is possible to perform a denial-of-service (DoS) attack on `SeasonFacet::gm` if the Bean price is above the peg, either once fully recapitalized or when reaching the last element of the Fertilizer FIFO list.

**Proof of Concept:** [This coded PoC](https://gist.github.com/carlitox477/1b0dde178288982f4e25d40b9e43e626) can be run by:
1. Creating file `Beantalk/protocol/test/POCs/mint0Fertilizer.test.js`
2. Navigating to `Beantalk/protocol`
3. Running `yarn test --grep "DOS last fertilizer payment through minting 0 fertilizers"`

**Recommended Mitigation:** Despite being a complex issue to explain, the solution is as simple as replacing `>` with `>=` in `LibFertilizer::addFertilizer` as below:

```diff
    function addFertilizer(
        uint128 season,
        uint256 fertilizerAmount,
        uint256 minLP
    ) internal returns (uint128 id) {
        AppStorage storage s = LibAppStorage.diamondStorage();

        uint128 fertilizerAmount128 = fertilizerAmount.toUint128();

        // Calculate Beans Per Fertilizer and add to total owed
        uint128 bpf = getBpf(season);
        s.unfertilizedIndex = s.unfertilizedIndex.add(
            fertilizerAmount.mul(bpf)
        );
        // Get id
        id = s.bpf.add(bpf);
        // Update Total and Season supply
        s.fertilizer[id] = s.fertilizer[id].add(fertilizerAmount128);
        s.activeFertilizer = s.activeFertilizer.add(fertilizerAmount);
        // Add underlying to Unripe Beans and Unripe LP
        addUnderlying(fertilizerAmount.mul(DECIMALS), minLP);
        // If not first time adding Fertilizer with this id, return
-       if (s.fertilizer[id] > fertilizerAmount128) return id;
+       if (s.fertilizer[id] >= fertilizerAmount128) return id; // prevent infinite loop in `Sun::rewardToFertilizer` when attempting to add 0 Fertilizer, which could DoS `SeasonFacet::gm` when recapitalization is fulfilled
        // If first time, log end Beans Per Fertilizer and add to Season queue.
        push(id);
        emit SetFertilizer(id, bpf);
    }
```

**Beanstalk Farms:** Added a > 0 check to the `mintFertilizer` function in commit hash [4489cb8](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/4489cb869b1a1f8a2535a04364460c79ffb75b11).

**Cyfrin:** Acknowledged. The Beanstalk Farms team has opted to add validation in `FertilizerFacet::mintFertilizer`. This alternative saves more gas compared to the one suggested; however, this issue should be considered in the future if `LibFertilizer::addFertilizer` is used anywhere else. This is the case in `FertilizerFacet::addFertilizerOwner` but assumedly will not be an issue as the owner would not send this type of transaction.


\clearpage
## Low Risk

### Incorrect handling of metadata traits in the attributes of `MetadataFacet::uri`

**Description:** For fully on-chain metadata, external clients expect the URI of a token to contain a base64 encoded JSON object that contains the metadata and base64 encoded SVG image. As raised previously, if these attributes are intented to be utilized as metadata traits then failure to correctly handle the packed encoding of the [attributes variable](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/metadata/MetadataFacet.sol#L38-L47) as an array of JSON objects in `MetadataFacet::uri` results in non-standard JSON metadata when subsequently [returned](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/metadata/MetadataFacet.sol#L48-L55), meaning it cannot be fully utilized by external clients.

**Impact:** External clients such as OpenSea are currently unable to display Beanstalk token metadata traits due to non-standard JSON formatting.

**Recommended Mitigation:** Refactor the inline metadata attributes as an array of metadata trait objects, ensuring the resulting encoded bytes are that of valid JSON.

**Beanstalk Farms:** Fixed in commit [47fef03](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/47fef03a37527c839acd4696db08fbf0bbcd5a71).

**Cyfrin:** Acknowledged.


\clearpage
## Informational

### Resetting of `withdrawSeasons` state was not executed on-chain as part of the BIP-36 upgrade
The [addition](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/init/InitBipNewSilo.sol#L42-L43) of `s.season.withdrawSeasons = 0` to `InitBipNewSilo::init` does not appear to have been present in the [version](https://etherscan.io/address/0xf6c77e64473b913101f0ec1bfb75a386aba15b9e#code) executed as part of the BIP-36 upgrade. Therefore, to have the state of Beanstalk accurately reflect this change, another upgrade should be performed to have this logic executed on-chain.

**Beanstalk Farms:** Fixed in commit [cca6250](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/cca625052179764c930be707a68a43952ec54ddf).

**Cyfrin:** Acknowledged.

### Changes to initialization contracts are not recommended after they are executed on-chain
It is understood that certain modifications to BIP initialization contracts have been made retroactively with the intention that, if run again, any new deployments of the Beanstalk protocol by replaying this history will reflect the current state of Beanstalk. One particular [modification](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/init/InitDiamond.sol#L62) to `InitDiamond::init`, setting the `stemStartSeason` to zero, while seemingly benign as migration logic in `LibSilo` appears to be bypassed, would result in underdlow within `LibLegacyTokenSilo::_calcGrownStalkForDeposit` when calculating the [Season diff](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/Silo/LibLegacyTokenSilo.sol#L469). This issue will be present until `InitBipNewSilo::init` excutes, setting the `stemStartSeason` state to the [Season in which it is executed](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/init/InitBipNewSilo.sol#L76-L77). It is therefore recommended that initialization scripts are ossified after being executed on-chain to maintain an accurate history of the protocol: its mechanism developments, bugs and related upgrades/mitigations.

**Beanstalk Farms:** The purpose of such changes is to future proof future deployments of Beanstalk. If someone were to deploy a fresh Beanstalk, it is important that the protocol continues to function as expected with all upgrades already implemented.

The expectation is that a new Beanstalk would be initialized only with `InitDiamond` and that Beanstalk would automatically be on the newest version. The other `Init` contracts are intended strictly to migrate from a previous version to the next.

The `LibLegacyTokenSilo` is only used to provide legacy support and migration functionality for Silo V2. This includes, the `MigrationFacet`, `LegacyClaimWithdrawalFacet` and `seasonToStem(address token, uint32 season)` in `SiloExit`. The expectation is that a new Beanstalk would be deployed immediately with the Silo V3 upgrade and thus have no reason to be backwards compatable with Silo V2 or support migration from V2 to V3 in any capacity.

**Cyfrin:** Acknowledged.

### Lack of slippage protection when removing liquidity from BEAN:3CRV MetaPool and adding liquidity to BEAN:ETH Well could result in loss of funds due to sandwich attack
Currently, the second and third steps of the *Migration Process*, as provided in BIP-38 specification, are not included in the scope of this BIP. The primary risk associated with these steps is the swap of BEAN:3CRV LP Tokens for BEAN:ETH Well LP Tokens, given the size of the swap to be performed. Sandwiching of the transaction that executes this swap could result in loss of funds. Therefore, the use of reasonable slippage parameters is essential to prevent this. It is understood that the current use of zero [slippage parameters](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/scripts/beanEthMigration.js#L26) within the `beanEthMigration.js` migration script when removing liquidity from the MetaPool and [adding liquidity](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/scripts/beanEthMigration.js#L39) to the Well is only intended for testing purposes. The swap path from 3CRV -> WETH will either be executed manually via the BCM on a DEX aggregator with MEV protection or via an OTC swap, and the BCM will ensure the proper use of slippage parameters when removing/adding liquidity. It is essential that this is the case.

**Beanstalk Farms:** This script is only expected to be used to mock the migration to aid in testing. The expectation is that it will never be used to execute code on mainnet and thus no slippage parameter is added.

**Cyfrin:** Acknowledged.

### `LibEthUsdOracle::getEthUsdPrice` design changes should be documented
Before BIP-38, the `LibEthUsdOracle::getEthUsdPrice` function had the following behavior:
1. If the difference between the Chainlink ETH/USD oracle and the Uniswap ETH/USDC TWAP oracle (considering a 15-minute window) prices was below `0.5%`, then it would return the average of both values. Now, this difference should be below `0.3%`.
2. If the difference between the Chainlink ETH/USD oracle and the Uniswap ETH/USDC TWAP oracle (considering a 15-minute window) was greater than the difference between the Chainlink ETH/USD oracle and the Uniswap ETH/USDT TWAP oracle (considering a 15-minute window), then:
    * If the difference between the Chainlink ETH/USD oracle and the Uniswap ETH/USDT TWAP oracle (considering a 15 minute-window) prices was below `2%`, it would return the average of these two prices. Now, this difference should be less than `1%`.
    * Otherwise, it would return 0, indicating that the oracle is broken or stale. Now, it returns the Chainlink ETH/USD oracle price, assuming it is correct.
3. Otherwise:
    * If the difference between the Chainlink ETH/USD oracle and the Uniswap ETH/USDC TWAP oracle (considering a 15-minute window) prices was below `2%`, it would return the average of these two prices. Now, this difference should be less than `1%`.
    * Otherwise, it would return 0, indicating that the oracle is broken or stale. Now, it returns the Chainlink ETH/USD oracle price, assuming it is correct.

In essence, this function now assumes that the Chainlink ETH/USD price is correct as long as it is not stale or broken (if it returns 0). In cases where the difference between this price and the Uniswap ETH/USDC TWAP oracle price or Uniswap ETH/USDT TWAP oracle price is outside certain thresholds, it considers and averages with one of these values. Previously, if this difference was not within certain bounds, the oracle was considered to be broken.

**Beanstalk Farms:** This change was actually made before BIP-37 was deployed, but this modification was omitted from the previous Cyfrin audit. Thus, no functionality in `getEthUsdPrice` changed as a part of BIP-38.

The comments in `LibEthUsdOracle` were not correct and have been updated in commit [968f783](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/968f783d3d062b93f9f692accc9e7ad60d4f1ab6).

**Cyfrin:** Acknowledged. Comments now match the code's intention.

### Logic in `LibFertilizer::push` related to (deprecated) intermediate addition of Fertilizer to FIFO list should be removed
Intermediate addition to the FIFO list was formerly allowed only by the Beanstalk DAO, but this functionality has since been deprecated in the current upgrade with the removal of `FertilizerFacet::addFertilizerOwner`. Consequently, the [corresponding logic](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L139-L147) in `LibFertilizer::push` should be removed as this now represents unreachable code.

**Beanstalk Farms:** the `push(...)` function is still used internally [here](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/LibFertilizer.sol#L60).

The highlighted segment is not used reachable anymore, but in the case where the humidity is changed for some reason, it could again be reached. For this reason, the decision was made to leave it in.

**Cyfrin:** Acknowledged.

### Consider moving the `MetadataFacet::uri` disclaimer from metadata attributes to the description
The [disclaimer](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/metadata/MetadataFacet.sol#L46) within `MetadataFacet::uri` currently resides at the end of the JSON attributes; however, this may be better placed within the metadata description instead.

**Beanstalk Farms:** The disclaimer placement was largely inspired by [Uniswap V3’s NFT](https://opensea.io/assets/ethereum/0xc36442b4a4522e871399cd717abdd847ab11fe88/528320) and thus, feel that the attribute section is an adequate place to keep it.

**Cyfrin:** Acknowledged.

### Incorrect comment in `MetadataImage::sciNotation` should be corrected
`MetadataImage::sciNotation` is intended to convert an input Stem to its string representation, using scientific notation if the value is [greater than 1e5](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/metadata/MetadataImage.sol#L539). Related comments [referencing 1e7](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/metadata/MetadataImage.sol#L538) as the threshold are incorrect and so should be modified to 1e5.

**Beanstalk Farms:** Fixed in commit [81e452e](https://github.com/BeanstalkFarms/Beanstalk/commit/81e452e41c2533dfc49543dc70fba15ed3c6cc2f).

**Cyfrin:** Acknowledged.

### Continued reference to "Seeds" in `InitBipBasinIntegration::init` is confusing
With the deprecation of the "Seeds" terminology, [continued reference](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/init/InitBipBasinIntegration.sol#L31-L33) is confusing and all instances should be updated to instead refer to the earned Stalk per BDV per Season.

**Beanstalk Farms:** Updated names in commit [ba1d42b](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/ba1d42bc9159881143c5f23ab03a7ba8078bd4b0).

### `InitBipBasinIntegration` NatSpec title tag is inconsistent with the file/contract name
The [title tag](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/init/InitBipBasinIntegration.sol#L17) of the `InitBipBasinIntegration` NatSpec is inconsistent with the file/contract name and should be updated to match.

**Beanstalk Farms:** Fixed in commit [c03f635](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/c03f635ef655eb80a2f6a270c41f19bcbd4a66ad).

**Cyfrin:** Acknowledged.

### Conditional block in `WellPrice::getConstantProductWell` can be removed
The [else block](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/ecosystem/price/WellPrice.sol#L64-L67) in `WellPrice::getConstantProductWell`, which handles the case when it is not possible to determine a price for Bean, is not necessary and can be removed as the default value of the `pool.price` is already zero.

**Beanstalk Farms:** Removed in commit [8aae31d](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/8aae31d683aeec50ccbc17985701b46223cc0a1d).

**Cyfrin:** Acknowledged.

### Unsafe cast in `WellPrice::getDeltaB`
While not likely to overflow, there is an [unsafe cast](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/ecosystem/price/WellPrice.sol#L97) in `WellPrice::getDeltaB` which could be replaced with a safe cast.

**Beanstalk Farms:** Fixed in commit [ff742a6](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/ff742a6f5b0b166df988a2422e475d314b948fc9).

### Typo in `FertilizerFacet::getMintFertilizerOut` NatSpec
The NatSpec of [`FertilizerFacet::getMintFertilizerOut`](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/beanstalk/barn/FertilizerFacet.sol#L108) currently refers to Fertilizer as `Fertilize` which should be corrected.

**Beanstalk Farms:** Fixed in commit [373c094](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/373c0948cce9730446111a943a4fd96dabd90025).

**Cyfrin:** Acknowledged.

### Typo in comment within `LibSilo::_mow`
The following [typo](https://github.com/BeanstalkFarms/Beanstalk/blob/12c608a22535e3a1fe379db1153185fe43851ea7/protocol/contracts/libraries/Silo/LibSilo.sol#L351-L352) in `LibSilo::_mow` should be corrected:

```diff
- //sop stuff only needs to be updated once per season
- //if it started raininga nd it's still raining, or there was a sop
+ // sop stuff only needs to be updated once per season
+ // if it started raining and it's still raining, or there was a sop
```

**Beanstalk Farms:** Fixed in commit [d27567c](https://github.com/BeanstalkFarms/Beanstalk/pull/655/commits/d27567c5f84bf07d604397f4d4549570ac9fb8c4).

**Cyfrin:** Acknowledged.