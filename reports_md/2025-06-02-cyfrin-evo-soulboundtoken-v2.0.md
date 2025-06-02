**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Giovanni Di Siena](https://x.com/giovannidisiena)
**Assisting Auditors**

 


---

# Findings
## Low Risk


### Missing common Chainlink Oracle validations

**Description:** The protocol is missing common [Chainlink Oracle validations](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf); it calls `AggregatorV3Interface::latestRoundData` without any validation of the result:
```solidity
function _getLatestPrice() internal view returns (uint256) {
    //slither-disable-next-line unused-return
    (, int256 price,,,) = i_nativeUsdFeed.latestRoundData();
    return uint256(price);
}
```

**Recommended Mitigation:** Implement common Chainlink oracle validations such as checking for:
* [stale prices](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf#99af) using the [correct heartbeat](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf#fb78) for the particular oracle
* [down L2 sequencer](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf#0faf), [revert if `startedAt == 0`](https://solodit.contractlevel.io/issues/insufficient-checks-to-confirm-the-correct-status-of-the-sequenceruptimefeed-codehawks-zaros-git) and potentially a small [grace period](https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code) of ~2 minutes after it recovers before resuming to fetch price data
* [returned price not at min or max boundaries](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf#00ac)

For this protocol the impact of omitting these checks is quite minimal; in a worst-case scenario users are able to buy NFTs for a cheaper or greater price, but there is no threat to protocol solvency/user liquidation etc as can be a threat in other protocols. And since users can only buy 1 NFT and can't sell/transfer, it isn't that big a deal. If these checks are excluded to keep gas costs down perhaps just put a comment noting this.

**Evo:**
Fixed in commits [6af531e](https://github.com/contractlevel/sbt/commit/6af531e49f7d7dd525da449bcdbdacb171e0c70d),[7a06688](https://github.com/contractlevel/sbt/commit/7a0668860f9b4f43798988349a966147bf94f33f), [93021e4](https://github.com/contractlevel/sbt/commit/93021e4f9c2afb40f64f9f9de69661a134702313).

**Cyfrin:** Verified.


### Users who are removed from the blacklist have to pay again for their NFT

**Description:** When a user is added to the blacklist, the NFT which they already paid for is burned:
```solidity
function _addToBlacklist(address account) internal {
    // *snip: code not relevant *//

    if (balanceOf(account) > 0) {
        uint256 tokenId = tokenOfOwnerByIndex(account, 0); // Get first token
        _burn(tokenId); // Burn the token
    }
}
```

But when they are removed from the blacklist, they do not receive a free NFT to make up for their previously burned one, nor is there any flag set that would enable them to mind their NFT again but without paying a fee:
```solidity
function _removeFromBlacklist(address account) internal {
    if (!s_blacklist[account]) revert SoulBoundToken__NotBlacklisted(account);

    s_blacklist[account] = false;
    emit RemovedFromBlacklist(account);
}
```

**Impact:** A user who bought an NFT, then was blacklisted, then removed from the blacklist will have to pay twice to get the NFT.

**Recommended Mitigation:** This doesn't seem fair; if a user had an NFT burned when they were blacklisted, they should receive a free NFT back if later removed from the blacklist.

**Evo:**
Acknowledged; in the unlikely case a user is blacklisted due to admin error then subsequently removed from the blacklist, the DAO will compensate the user via a community vote.


### Round up fee against users

**Description:** Solidity by default rounds down, but generally fees should be rounded up against users. Using Solady's [library](https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol) is significantly more efficient than OpenZeppelin:
```solidity
import {FixedPointMathLib} from "@solady/utils/FixedPointMathLib.sol";

function _getFee() internal view returns (uint256 fee) {
    // read fee factor directly to output variable
    fee = s_feeFactor;

    // only do extra work if non-zero
    if(fee != 0) fee = FixedPointMathLib.fullMulDivUp(fee, PRICE_FEED_PRECISION, _getLatestPrice());
}
```

A secondary benefit of using the above is eliminating the possibility of revert due to [intermediate multiplication overflow](https://x.com/DevDacian/status/1892529633104396479), though in this code it isn't a real possibility.

If you don't want to round up against users but want a slightly faster implementation than the default:
```solidity
function _getFee() internal view returns (uint256 fee) {
    // read fee factor directly to output variable
    fee = s_feeFactor;

    // only do extra work if non-zero
    if(fee != 0) fee = (fee * PRICE_FEED_PRECISION) / _getLatestPrice();
}
```

**Evo:**
Fixed in commit [52c5384](https://github.com/contractlevel/sbt/commit/52c538448fbceb09f27ae657bcecb0c1483eb933).

**Cyfrin:** Verified.


### Whale can buy near-infinite voting power via `mintWithTerms`

**Description:** Since whales can control near-infinite addresses, as long as they have the funds they can buy near-infinite voting power via `mintWithTerms`.

**Impact:** This could be used seconds before a proposal is due to expire to decide that proposal. Long-term impact is limited however since the admins can blacklist addresses which burn the NFTs.

**Recommended Mitigation:** Implement a snapshot mechanism to capture total and individual user voting power prior to proposals. Consider implementing pausing to prevent users from minting NFTs via `mintWithTerms` since this is the only function which allows "unlimited mints".

**Evo:**
Fixed in commit [2fbd2c5](https://github.com/contractlevel/sbt/commit/2fbd2c5379a5f07a8166ec4041f392d867f5bedd) by allowing admins to pause `mintWithTerms`.

**Cyfrin:** Verified.


### `_verifySignature` is not compatible with smart contract wallets or other smart accounts

**Description:** Support for smart accounts (e.g. [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)) and other smart contract wallets (e.g. Safe{Wallet}) minting tokens is not currently possible as the signature verification implemented in `_verifySignature` is only able to handle those generated by EOAs. Here, it could be beneficial to support signature verification not just for smart accounts but also other smart contracts that could include multi-sig wallets or any other use case, for example DAOs with their own smart contract infrastructure, to allow other organizations to participate as members.

EOAs upgraded to [ERC-7702](https://eips.ethereum.org/EIPS/eip-7702) accounts are unaffected, but any other smart contract signatures cannot be verified without implementing [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271). However, this adds the additional consideration that for EIP-7702 accounts the code length will be non-zero, so while these accounts can have their signatures verified using EIP-1271, the private key still holds full authority to sign transactions which means that any implementation of a code length check such as in the [OpenZeppelin SignatureChecker library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol) will need to be slightly modified to continue to allow verification of signatures from these accounts generated using `eth/personal_sign`. Additional discussion can be found [here](https://blog.rhinestone.wtf/unlocking-chain-abstracted-eoas-with-eip-7702-and-irrevocable-signatures-adc820a150ef).

To support such smart contract signatures, consider falling back to the OpenZeppelin SignatureChecker library function `isValidERC1271SignatureNow` like so:

```diff
    function _verifySignature(bytes memory signature) internal view returns (bool) {
        /// @dev compute the message hash: keccak256(termsHash, msg.sender)
        bytes32 messageHash = keccak256(abi.encodePacked(s_termsHash, msg.sender));

        /// @dev apply Ethereum signed message prefix
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);

        /// @dev attempt to recover the signer
        //slither-disable-next-line unused-return
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(ethSignedMessageHash, signature);

        /// @dev return false if errors or incorrect signer
++      if (error == ECDSA.RecoverError.NoError && recovered == msg.sender) return true;
++      else return SignatureChecker.isValidERC1271SignatureNow(msg.sender, ethSignedMessageHash, signature);
    }
```

**Evo:**
Fixed in commit [6d4f41c](https://github.com/contractlevel/sbt/commit/6d4f41ce160e19713bb4a6cafdf1b739df98e027#diff-39790f8feee6ea105eee119137d7c3d881007ed50d9a62590b54ff559f45b27aL511-R514).

**Cyfrin:** Verified.

\clearpage
## Informational


### Prefer`Ownable2Step` instead of `Ownable`

**Description:** Prefer [Ownable2Step](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol) instead of `Ownable` for [safer ownership transfer](https://www.rareskills.io/post/openzeppelin-ownable2step).

**Evo:**
Fixed in commit [620120e](https://github.com/contractlevel/sbt/commit/620120ec5a85c3a2dbd1be52af4ee34fe946efbe).

**Cyfrin:** Verified.


### Assuming Chainlink price feed decimals can lead to unintended errors

**Description:** In general, Chainlink x/USD price feeds use 8 decimal precision however this is not universally true for example [AMPL/USD](https://etherscan.io/address/0xe20CA8D7546932360e37E9D72c1a47334af57706#readContract#F3) uses 18 decimal precision.

Instead of [assuming Chainlink oracle price precision](https://medium.com/contractlevel/chainlink-oracle-defi-attacks-93b6cb6541bf#87fc), the precision variable could be declared `immutable` and initialized in the constructor via [`AggregatorV3Interface::decimals`](https://docs.chain.link/data-feeds/api-reference#decimals).

In practice though the price oracle is hard-coded in `script/HelperConfig.s.sol` and does use 8 decimals for on Optimism, so the current configuration will work fine.

**Evo:**
Fixed in commit [f594ae0](https://github.com/contractlevel/sbt/commit/f594ae004d4afc80f19e17c0f61d50caa00a4811).

**Cyfrin:** Verified.


### Don't initialize to default values

**Description:** Don't initialize to default values as Solidity already does this:
```solidity
SoulBoundToken.sol
125:        for (uint256 i = 0; i < admins.length; ++i) {
162:        for (uint256 i = 0; i < accounts.length; ++i) {
226:        for (uint256 i = 0; i < accounts.length; ++i) {
245:        for (uint256 i = 0; i < accounts.length; ++i) {
270:        for (uint256 i = 0; i < accounts.length; ++i) {
289:        for (uint256 i = 0; i < accounts.length; ++i) {
312:        for (uint256 i = 0; i < accounts.length; ++i) {
```

**Evo:**
Fixed in commit [f594ae0](https://github.com/contractlevel/sbt/commit/f594ae004d4afc80f19e17c0f61d50caa00a4811).

**Cyfrin:** Verified.


### Remove obsolete `return` statements when already using named returns

**Description:** Remove obsolete `return` statements when already using named returns:
```diff
    function _mintSoulBoundToken(address account) internal returns (uint256 tokenId) {
        tokenId = _incrementTokenIdCounter(1);
        _safeMint(account, tokenId);
-       return tokenId;
    }

    function _incrementTokenIdCounter(uint256 count) internal returns (uint256 startId) {
        startId = s_tokenIdCounter;
        s_tokenIdCounter += count;
-       return startId;
    }
```

**Evo:**
Fixed in commit [f594ae0](https://github.com/contractlevel/sbt/commit/f594ae004d4afc80f19e17c0f61d50caa00a4811).

**Cyfrin:** Verified.


### Consider preventing users from over-paying

**Description:** Currently the protocol allows users to over-pay:
```solidity
function _revertIfInsufficientFee() internal view {
    if (msg.value < _getFee()) revert SoulBoundToken__InsufficientFee();
}
```

Consider changing this to require the exact fee to prevent users from accidentally over-paying:
```solidity
function _revertIfIncorrectFee() internal view {
    if (msg.value != _getFee()) revert SoulBoundToken__IncorrectFee();
}
```

[Fat Finger](https://en.wikipedia.org/wiki/Fat-finger_error) errors have previously resulted in notorious unintended errors in financial markets; the protocol could choose to be defensive and help protect users from themselves.

**Evo:**
Fixed in commit [e3b2f74](https://github.com/contractlevel/sbt/commit/e3b2f74239601b2721118e11aaa92b42dbb502e9).

**Cyfrin:** Verified.


### `else` can be omitted in `mintWithTerms`

**Description:** `else` can be omitted in `mintWithTerms` since if signature validation failed a revert will occur:
```diff
        if (!_verifySignature(signature)) revert SoulBoundToken__InvalidSignature();
-       else emit SignatureVerified(msg.sender, signature);
+       emit SignatureVerified(msg.sender, signature);
        tokenId = _mintSoulBoundToken(msg.sender);
```

**Evo:**
Fixed in commit [e3b2f74](https://github.com/contractlevel/sbt/commit/e3b2f74239601b2721118e11aaa92b42dbb502e9).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Use named returns where this can eliminate local function variables and for `memory` returns

**Description:** Using named returns is more gas efficient where this can eliminate local function variables and for `memory` returns:
```diff
-   function batchMintAsAdmin(address[] calldata accounts) external onlyAdmin returns (uint256[] memory) {
+   function batchMintAsAdmin(address[] calldata accounts) external onlyAdmin returns (uint256[] memory tokenIds) {
        _revertIfEmptyArray(accounts);
        uint256 startId = _incrementTokenIdCounter(accounts.length);

-      uint256[] memory tokenIds = new uint256[](accounts.length);
+      tokenIds = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; ++i) {
            _mintAsAdminChecks(accounts[i]);
            tokenIds[i] = startId + i;
            _safeMint(accounts[i], tokenIds[i]);
        }
-      return tokenIds;
    }
```

Gas Result:
```diff
{
-  "batchMintAsAdmin": "252114"
+  "batchMintAsAdmin": "252102"
}
```

**Evo:**
Fixed in commit [b4fcadb](https://github.com/contractlevel/sbt/commit/b4fcadbd9c5684cc4e3b1ee3c39f72c406aaf658).

**Cyfrin:** Verified.


### Enable the optimizer

**Description:** [Enable the optimizer](https://dacian.me/the-yieldoor-gas-optimizoor#heading-enabling-the-optimizer) in `foundry.toml`.

Gas results:
```diff
{
-  "addToBlacklist": "31090"
+  "addToBlacklist": "30691"

-  "addToWhitelist": "28754"
+  "addToWhitelist": "28392"

-  "batchAddToBlacklist": "60282"
+  "batchAddToBlacklist": "59482"

-  "batchAddToWhitelist": "55790"
+  "batchAddToWhitelist": "54997"

-  "batchMintAsAdmin": "252102"
+  "batchMintAsAdmin": "248867"

-  "batchRemoveFromBlacklist": "5289"
+  "batchRemoveFromBlacklist": "4594"

-  "batchRemoveFromWhitelist": "5305"
+  "batchRemoveFromWhitelist": "4677"

-  "batchSetAdmin": "28090"
+  "batchSetAdmin": "27412"

-  "mintAsAdmin": "130754"
+  "mintAsAdmin": "129447"

-  "mintAsWhitelisted": "135623"
+  "mintAsWhitelisted": "132292"

-  "mintWithTerms": "142281"
+  "mintWithTerms": "137638"

-  "removeFromBlacklist": "2516"
+  "removeFromBlacklist": "2203"

-  "removeFromWhitelist": "2634"
+  "removeFromWhitelist": "2254"

-  "setAdmin": "27187"
+  "setAdmin": "26677"

-  "setContractURI": "29118"
+  "setContractURI": "26842"

-  "setFeeFactor": "26075"
+  "setFeeFactor": "25666"

-  "setWhitelistEnabled": "7175"
+  "setWhitelistEnabled": "6902"

-  "withdrawFees": "14114"
+  "withdrawFees": "13462"
}

```

**Evo:**
Fixed in commit [b4fcadb](https://github.com/contractlevel/sbt/commit/b4fcadbd9c5684cc4e3b1ee3c39f72c406aaf658).

**Cyfrin:** Verified.


### Prefer `calldata` to `memory` for external read-only inputs

**Description:** Prefer `calldata` to `memory` for external read-only inputs:
```diff
-   function mintWithTerms(bytes memory signature) external payable returns (uint256 tokenId) {
+   function mintWithTerms(bytes calldata signature) external payable returns (uint256 tokenId) {

-   function _verifySignature(bytes memory signature) internal view returns (bool) {
+   function _verifySignature(bytes calldata signature) internal view returns (bool) {
```

Gas results:
```diff
{
-  "mintWithTerms": "137638"
+  "mintWithTerms": "137299"
}
```

**Evo:**
Fixed in commit [b4fcadb](https://github.com/contractlevel/sbt/commit/b4fcadbd9c5684cc4e3b1ee3c39f72c406aaf658).

**Cyfrin:** Verified.


### Use solady `safeTransferETH` to send eth

**Description:** Using solady [`safeTransferETH`](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L90-L98) is a [more efficient](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#10-use-safetransferlibsafetransfereth-instead-of-solidity-call-effective-035-cheaper) way to send eth. Also since there is no point in leaving eth inside the contract, consider removing the `amountToWithdraw` input parameter and checks associated with it; instead just send the entire contract balance:
```solidity
function withdrawFees() external onlyOwner {
    uint256 amountToWithdraw = address(this).balance;
    if(amountToWithdraw > 0) {
        // from https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L90-L98
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(call(gas(), caller(), amountToWithdraw, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xefde920d) // `SoulBoundToken__WithdrawFailed()`.
                revert(0x1c, 0x04)
            }
        }

        emit FeesWithdrawn(amountToWithdraw);
    }
}
```

Gas result:
```diff
{
- "withdrawFees": "13462"
+ "withdrawFees": "13353"
}
```

**Evo:**
Fixed in commit [b4fcadb](https://github.com/contractlevel/sbt/commit/b4fcadbd9c5684cc4e3b1ee3c39f72c406aaf658).

**Cyfrin:** Verified.

\clearpage