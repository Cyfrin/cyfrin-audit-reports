**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Jorge](https://x.com/TamayoNft)

**Assisting Auditors**

 

---

# Findings
## Low Risk


### `PriceStorage::setPrice` maximum lower and upper bounds can be easily bypassed by repeatedly calling the function in the same block

**Description:** `PriceStorage::setPrice` limits the price movement to a maximum lower/upper range delta based on the current price, to prevent sudden extreme changes in price:
```solidity
uint256 lastPriceValue = lastPrice.price;
if (lastPriceValue != 0) {
  uint256 upperBound = lastPriceValue + ((lastPriceValue * upperBoundPercentage) / BOUND_PERCENTAGE_DENOMINATOR);
  uint256 lowerBound = lastPriceValue - ((lastPriceValue * lowerBoundPercentage) / BOUND_PERCENTAGE_DENOMINATOR);
  if (_price > upperBound || _price < lowerBound) {
    revert InvalidPriceRange(_price, lowerBound, upperBound);
  }
}
```

But this can be easily bypassed by repeatedly calling the `setPrice` function multiple times in the same block, each time decreasing or increasing the `lastPrice` by the current maximum allowed lower/upper bound.

**Impact:** The limitation of wild price fluctuations can be trivially bypassed so is ineffective, though only by entities having `SERVICE_ROLE`.

**Recommended Mitigation:** Add a configurable parameter `minPriceUpdateDelay` to the`PriceStorage` contract which only `DEFAULT_ADMIN_ROLE` can change. Then in `setPrice`:
```solidity
error PriceUpdateTooSoon(uint256 lastUpdate, uint256 minWaitTime);

// In setPrice:
if(lastPrice.timestamp != 0) {
    if(block.timestamp < lastPrice.timestamp + minPriceUpdateDelay) {
        revert PriceUpdateTooSoon(lastPrice.timestamp, minPriceUpdateDelay);
    }
}
```

**Avant:**
Acknowledged: the suggestion is valid, and we might consider the change in the future if we automate price setting. Currently, the price is calculated manually after a careful NAV process conducted weekly and will most likely be outsourced to an independent party for increased transparency. Once calculated, the price update transaction is also posted manually and requires a quorum of approvals before being submitted on-chain. This setup ensures that no repeated calls or incorrect parameters are ever attempted, and for now, the current code constraints suit our requirements.


### Use multi-sig wallet for contract admin and owner

**Description:** As part of the audit we were asked to investigate the on-chain state of the deployed contracts. Using Ethereum as the example:
* the primary deployer appears to be [0xA5Ab0683d4f4AD107766a9fc4dDd49B5a960e661](https://etherscan.io/address/0xA5Ab0683d4f4AD107766a9fc4dDd49B5a960e661)
* it has transferred ownership and admin to [0xD47777Cf34305Dec4F1095F164792C1A4AFB327e](https://etherscan.io/address/0xd47777cf34305dec4f1095f164792c1a4afb327e)

Both of these are [EOA addresses](https://academy.binance.com/en/glossary/externally-owned-account-eoa):
```
cast code 0xA5Ab0683d4f4AD107766a9fc4dDd49B5a960e661 --rpc-url $ETH_RPC_URL
cast code 0xD47777Cf34305Dec4F1095F164792C1A4AFB327e --rpc-url $ETH_RPC_URL
0x
0x
```

**Impact:** EOAs present significant security risks:
* Single point of failure (one compromised private key = total control)
* No ability to implement time delays, spending limits, or approval requirements
* No recovery mechanism if keys are lost
* Vulnerable to phishing, device compromise, or coercion

**Recommended Mitigation:** Transfer admin and ownership to a multi-signature wallet (e.g., Gnosis Safe) with:
* Minimum 3-of-5 or 2-of-3 threshold
* Time delays for critical operations
* Trusted Third-Party Entity who can veto/cancel time-locked admin actions
* Signers using hardware wallets
* Documented key management procedures

**Avant:**
Acknowledged; Avant intends to transfer contract ownership and admin privileges to EOAs within the ForDeFi custodian ecosystem used to hold the protocol’s funds. The MPC wallets associated with the RBAC structure provided by their platform function similarly to the suggested multisig configuration. Avant’s setup ensures that only a quorum of admin-level users will be allowed to perform admin contract calls.

\clearpage
## Informational


### In Solidity don't initialize to default values

**Description:** In Solidity don't initialize to default values:
```solidity
RequestsManager.sol
72:    for (uint256 i = 0; i < _allowedTokenAddresses.length; i++) {
```

**Avant:**
Fixed in commit [0b590fa](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/0b590fa60fa75d73396b9bb48543b52396c204ca).

**Cyfrin:** Verified.


### Emit missing events

**Description:** Emit missing events:
* `RequestsManager::constructor` should emit `AllowedTokenAdded`

**Avant:**
Fixed in commit [7a3587c](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/7a3587ca6d673d143565703d094b6f9526fd8020).

**Cyfrin:** Verified.


### Remove obsolete `return` statements when using named return variables

**Description:** Remove obsolete `return` statements when using named return variables:
* `RequestManager::_addMintRequest, _addBurnRequest`

**Avant:**
Fixed in commit [7a3587c](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/7a3587ca6d673d143565703d094b6f9526fd8020).

**Cyfrin:** Verified.


### Use named mapping parameters to make explicit the purpose of keys and values

**Description:** Named mapping parameters are already being used in almost all of the codebase, the one exception is:
```solidity
SimpleToken.sol
13:  mapping(bytes32 => bool) private mintIds;
14:  mapping(bytes32 => bool) private burnIds;
```

**Avant:**
Fixed in commit [1cc43e3](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/1cc43e3c59baa16b5b529ad06fee637bd6131ec1).

**Cyfrin:** Verified.


### Add `deadline` parameter for mint and burn requests in `RequestsManager`

**Description:** `RequestsManager::requestMint` and `requestBurn` allow callers to specify the minimum output amount but don't allow callers to specify a deadline for the request to be completed.

Minimum output amounts become "stale" over time; what users would expect as the minimum today could be different tomorrow and different again next week.

It would be ideal to allow callers of `RequestsManager::requestMint` and `requestBurn` to specify a deadline by which the requests must be completed. Past the deadline completion should revert but cancellation must remain possible.

**Avant:**
Considering users can cancel mint and burn requests at any time, and they have already specified their minimum expected output amount, we believe the suggested extra constraint might not add much value while increasing the complexity of the UX.


### Enable whitelist in `RequestsManager::constructor`

**Description:** Currently `RequestsManager::constructor` has the whitelist enablement commented out:
```solidity
  constructor(
    address _issueTokenAddress,
    address _treasuryAddress,
    address _providersWhitelistAddress,
    address[] memory _allowedTokenAddresses
  ) AccessControlDefaultAdminRules(1 days, msg.sender) {
    // *snip : irrelevant stuff* //

    // @audit commented out, starts in permissionless state
    // isWhitelistEnabled = true;
  }
```

It is more defensive to enable the whitelist in the constructor to start in a restricted state, rather than starting in a permissionless state.

**Avant:**
Acknowledged: The whitelisting feature was not on Avant's short-term roadmap, hence the comment. We agree that starting with it adds marginal defense, but since minting and redeeming are two-step request/complete processes that we control, we accepted the tradeoff.



### Add an identifier or descriptor to `PriceStorage` which indicates what token or other entity is being priced

**Description:** The `PriceStorage` contract contains no identifier or descriptor that would readily indicate what is being priced.

Consider adding an identifier or a descriptor such as a string that has the name of the token or entity being priced.

**Avant:**
Acknowledged: Avant will consider adding token identifiers in future `PriceStorage` deployments.

\clearpage
## Gas Optimization


### Enable the optimizer

**Description:** [Enable the Foundry optimizer](https://dacian.me/the-yieldoor-gas-optimizoor#heading-enabling-the-optimizer) in `foundry.toml`:
```diff
+ optimizer = true
+ optimizer_runs = 1_000
```

**Avant:**
Fixed in commit [871140d](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/871140d5175f2f7ca7de7be960b834eb1f671206).

**Cyfrin:** Verified.


### Improve `PriceStorage` storage packing

**Description:** * `PriceStorage::upperBoundPercentage` and `lowerBoundPercentage` can be safely declared as `uint128` to pack them into the same storage slot:
```diff
- uint256 public upperBoundPercentage;
- uint256 public lowerBoundPercentage;
+ uint128 public upperBoundPercentage;
+ uint128 public lowerBoundPercentage;
```

This reduces gas costs of every call to `PriceStorage::setPrice` where they are read together.

* `IPriceStorage::Price` can safely use `uint128` for `price` and `timestamp` to pack each `Price` struct into the same storage slot:
```diff
interface IPriceStorage {
  struct Price {
-   uint256 price;
-   uint256 timestamp;
+   uint128 price;
+   uint128 timestamp;
  }
```

This saves two storage writes in `PriceStorage::setPrice` when writing to `prices[key]` and `lastPrice`.

**Avant:**
Fixed in commits [0325fcd](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/0325fcdfb7d78e311fb194845bb27ea541a301a0), [d40fc3d](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/d40fc3d103a502d2a3ab54939dd43ca8193ca176).

**Cyfrin:** Verified.


### Use `msg.sender` when calling `safeTransfer` in `RequestsManager::cancelMint, cancelBurn`

**Description:** `RequestsManager::cancelMint` first enforces that `request.provider == msg.sender`:
```solidity
    _assertAddress(request.provider, msg.sender);
```

Hence it can directly use `msg.sender` instead of `request.provider` to save 1 storage read when calling `safeTransfer`:
```diff
-   depositedToken.safeTransfer(request.provider, request.amount);
+   depositedToken.safeTransfer(msg.sender, request.amount);
```

The same applies to `RequestsManager::cancelBurn`.

**Avant:**
Fixed in commit [7a3587c](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/7a3587ca6d673d143565703d094b6f9526fd8020).

**Cyfrin:** Verified.


### Modifier `mintRequestExist` can be safely removed from `RequestsManager::cancelMint, cancelBurn` saving 1 identical storage read

**Description:** `RequestsManager::cancelMint` validates that `request.provider == msg.sender`:
```solidity
L152:    _assertAddress(request.provider, msg.sender);
```

Hence the modifier `mintRequestExist(_id)` can be safely removed to save 1 identical storage read of `mintRequests[_id].provider`.

The same applies to `RequestsManager::cancelBurn`.

**Avant:**
Fixed in commit [f74d1fc](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/f74d1fc334cf34f8751285e55cf44e41238859e1).

**Cyfrin:** Verified.


### Cache identical storage reads

**Description:** Reading from storage is expensive; cache identical storage reads:
* `RequestsManager.sol`:
```solidity
// cache `request.amount` in `RequestsManager::completeBurn`
239:    issueToken.burn(_idempotencyKey, address(this), request.amount);
244:    emit BurnRequestCompleted(_id, request.amount, _withdrawalAmount);
```

**Avant:**
Fixed in commit [9bf3b60](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/9bf3b6041bee7bfeb79f19a90a79e13cf6674afa).

**Cyfrin:** Verified.

\clearpage