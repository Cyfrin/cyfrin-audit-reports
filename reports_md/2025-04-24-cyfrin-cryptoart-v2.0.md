**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[Hans](https://x.com/hansfriese)
**Assisting Auditors**



---

# Findings
## Medium Risk


### Collector can add `CreatorStory`, corrupting the provenance of an artwork

**Description:** The purpose of the `IStory` interface is to allow 3 different entities (Admin, Creator and Collectors) to add "Stories" about a given artwork (NFT) which [describes the provenance of the artwork](https://docs.transientlabs.xyz/tl-creator-contracts/common-features/story-inscriptions). In the art world the "provenance" of an item can affect its status and price, so the `IStory` interface aims to facilitate an on-chain record of an artwork's "provenance".

`IStory` is designed to work like this:
* Creator/Admin can add a `CollectionsStory` for when a collection is added to a contract
* Creator of an artwork can add a `CreatorStory`
* Collector of an artwork can add one or more `Story` about their experience while holding the artwork

The `IStory` interface specification requires that `addCreatorStory` is only called by the creator:
```solidity
/// @notice Function to let the creator add a story to any token they have created
/// @dev This function MUST implement logic to restrict access to only the creator
function addCreatorStory(uint256 tokenId, string calldata creatorName, string calldata story) external;
```

But in the CryptoArt implementation of the `IStory` interface, the current token owner can always emit `CreatorStory` events:
```solidity
function addCreatorStory(uint256 tokenId, string calldata, /*creatorName*/ string calldata story)
    external
    onlyTokenOwner(tokenId)
{
    emit CreatorStory(tokenId, msg.sender, msg.sender.toHexString(), story);
}
```

**Impact:** As an NFT is sold or transferred to new owners, each subsequent owner can continue to add new `CreatorStory` events even though they aren't the Creator of the artwork. This corrupts the provenance of the artwork by allowing Collectors to add to the `CreatorStory` as if they were the Creator.

**Recommended Mitigation:** Only the Creator of an artwork should be able to emit the `CreatorStory` event. Currently the on-chain protocol does not record the address of the creator; this could either be added or `onlyOwner` could be used where the contract owner acts as a proxy for the creator.

**CryptoArt:**
Fixed in commit [94bfc1b](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/94bfc1b1454e783ef1fb9627cfaf0328ebe17b47#diff-1c61f2d0e364fa26a4245d1033cdf73f09117fbee360a672a3cb98bc0eef02adL439-R439).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Allow custom Creator and Collector names to be emitted in `IStory` events to build artwork provenance

**Description:** The `IStory` interface is designed to allow custom names to be emitted for the Creator and Collector events. Here is an [example](https://www.transient.xyz/nfts/base/0x6c81306129b3cc63b0a6c7cec3dd50721ac378fe/9) where a Creator has used the custom name `lytke`.

But in CryptoArt's implementation of `IStory` interface, custom names are not allowed and it is always the caller's hex string that will be set:
```solidity
function addCollectionStory(string calldata, /*creatorName*/ string calldata story) external onlyOwner {
    emit CollectionStory(msg.sender, msg.sender.toHexString(), story);
}

/// @inheritdoc IStory
function addCreatorStory(uint256 tokenId, string calldata, /*creatorName*/ string calldata story)
    external
    onlyTokenOwner(tokenId)
{
    emit CreatorStory(tokenId, msg.sender, msg.sender.toHexString(), story);
}

/// @inheritdoc IStory
function addStory(uint256 tokenId, string calldata, /*collectorName*/ string calldata story)
    external
    onlyTokenOwner(tokenId)
{
    emit Story(tokenId, msg.sender, msg.sender.toHexString(), story);
}
```

**Impact:** Custom names should be allowed as they form part of the "provenance" of an artwork; the value of an artwork is often based on who the creator was and if it has been held by significant collectors in the past. Proper custom names are a lot easier to remember and tell a story about rather than 0x1343335...Artworks with custom names will be able to build a better story around them resulting in improved "provenance".

**CryptoArt:**
Fixed in commit [77f34a4](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/77f34a49cbc27589f3179b35b58a86696696bf83).

**Cyfrin:** Verified.


### Prevent code-injection inside `string` fields when emitting `IStory` events or setting `tokenURI` fields

**Description:** An attack vector which spans the intersection between web3 and web2 is when users can [associate arbitrary metadata strings with NFTs](https://medium.com/zokyo-io/under-the-hackers-hood-json-injection-in-nft-metadata-3be78d0f93a7) and those strings are later processed or displayed on a website.

In particular the `IStory::Story` event:
* is emitted by a non-trusted entity, the current holder of the artwork
* emits two arbitrary string parameters, `collectorName` and `story`
* these string parameters are designed to be displayed to users and may be processed by web2 apps

**Recommended Mitigation:** The most important validation is for non-trusted user-initiated functions, eg:
* When a Creator emits `CreatorStory` or a Collector emits `Story`, revert if the `name` and `story` strings contain any unexpected special characters
* When minting tokens revert if `TokenURISet::uriWhenRedeemable` and `uriWhenNotRedeemable` contain any unexpected special characters - though this must be done using off-chain components controlled by the protocol so risk here is minimal
* In off-chain code don't trust any user-supplied strings but sanitize them or check them for unexpected special characters

**CryptoArt:**
Acknowledged; mitigation handled off-chain via URI validation pre-signing, Story string sanitization/encoding post-event.


### Allow users to increment their nonce to void their signatures

**Description:** Currently users are unable to void their signatures by incrementing their nonce, since `NoncesUpgradeable::_useNonce` is `internal` and only called during actions which verify user signatures.

A user may want to invalidate a previous signature to prevent it from being used but is unable to.

**Impact:** Users are unable to invalidate previous signatures before they are used.

**Recommended Mitigation:** Expose `NoncesUpgradeable::_useNonce` via a `public` function that allows users to increment their own nonce.

**CryptoArt:**
Fixed in commit [cf82aeb](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/cf82aeb30d6a262cde51897f52c302be995d0202).

**Cyfrin:** Verified.


### `IERC7160` specification requires `hasPinnedTokenURI` to revert for non-existent `tokenId`

**Description:** Per the specification of `IERC7160`:
```solidity
/// @notice Check on-chain if a token id has a pinned uri or not
/// @dev This call MUST revert if the token does not exist
function hasPinnedTokenURI(uint256 tokenId) external view returns (bool pinned);
```

But the implementation of `hasPinnedTokenURI` doesn't revert for tokens which don't exist, instead it will simply return `false` or even return `true` if a token was burned when the value was true since burning doesn't delete `_hasPinnedTokenURI` (another issue has been created to track this):
```solidity
function hasPinnedTokenURI(uint256 tokenId) external view returns (bool) {
    return _hasPinnedTokenURI[tokenId];
}
```

**Recommended Mitigation:** Use the `onlyIfTokenExists` modifier:
```diff
-    function hasPinnedTokenURI(uint256 tokenId) external view returns (bool) {
+    function hasPinnedTokenURI(uint256 tokenId) external view onlyIfTokenExists(tokenId) returns (bool) {
```

**CryptoArt:**
Fixed in commit [56d0e22](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/56d0e222cdf25a971cd6466fd4757185a4362069).

**Cyfrin:** Verified.


### `IERC7160` specification requires `pinTokenURI` to revert for non-existent `tokenId`

**Description:** Per the specification of `IERC7160`:
```solidity
/// @notice Pin a specific token uri for a particular token
/// @dev This call MUST revert if the token does not exist
function pinTokenURI(uint256 tokenId, uint256 index) external;
```

But the implementation of `pinTokenURI` doesn't revert for tokens which don't exist, since `_tokenURIs[tokenId].length` will always equal 2 even for non-existent `tokenId`:
```solidity
// mapping value always has fixed array size of 2
mapping(uint256 tokenId => string[2] tokenURIs) private _tokenURIs;

function pinTokenURI(uint256 tokenId, uint256 index) external onlyOwner {
    if (index >= _tokenURIs[tokenId].length) {
        revert Error.Token_IndexOutOfBounds(tokenId, index, _tokenURIs[tokenId].length - 1);
    }

    _pinnedURIIndex[tokenId] = index;

    emit TokenUriPinned(tokenId, index);
    emit MetadataUpdate(tokenId);
}
```

**Recommended Mitigation:** Use the `onlyIfTokenExists` modifier:
```diff
-    function pinTokenURI(uint256 tokenId, uint256 index) external onlyOwner {
+    function pinTokenURI(uint256 tokenId, uint256 index) external onlyIfTokenExists(tokenId) onlyOwner {
```

**CryptoArt:**
Fixed in commit [0409ae4](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/0409ae4d81225a351c4d42620502843242f2604f).

**Cyfrin:** Verified.


### Inconsistent pause functionality allows certain state-changing operations when contract is paused

**Description:** The `CryptoartNFT` contract implements a pause mechanism using OpenZeppelin's `PausableUpgradeable` contract. However, the pause functionality is inconsistently applied across the contract's functions. While minting and burning operations are properly protected with the `whenNotPaused` modifier, several other state-changing functions remain accessible even when the contract is paused, including token transfers, metadata management, and story-related functions.

The following state-changing functions lack the `whenNotPaused` modifier:

1. Token transfers and approvals (inherited from ERC721)
2. Metadata management functions:
   - `updateMetadata`
   - `pinTokenURI`
   - `markAsRedeemable`
3. Story-related functions:
   - `addCollectionStory`
   - `addCreatorStory`
   - `addStory`
   - `toggleStoryVisibility`

**Impact:** When the contract is paused (typically during emergencies or upgrades), users can still perform various state-changing operations that might be undesirable during a pause period. It could lead to unexpected state changes during contract upgrades or emergency situations.

**Recommended Mitigation:** Add the `whenNotPaused` modifier to all state-changing functions to ensure consistent behavior when the contract is paused. For example:

**Cryptoart:**
Fixed in commit [e7d7e5b](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/e7d7e5b3b1c8976a11d49f889b4168ce649be2ee).

**Cyfrin:** Verified.

\clearpage
## Informational


### Protocol vulnerable to cross-chain signature replay

**Description:** As signatures do not include`chainId`, signature verification is vulnerable to [cross-chain replay](https://dacian.me/signature-replay-attacks#heading-cross-chain-replay).

**Impact:** Although the protocol plans to deploy cross-chain in the future, the specification of this audit is to only consider deployment to one chain. Hence this finding is only Informational as this attack path is not possible when the protocol is only deployed on one chain.

**Recommended Mitigation:** Include `block.chainid` as a signature parameter.

**CryptoArt:**
Fixed in commit [1e25f8c](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/1e25f8cd172a32e3e35ccf8a86e7af9fe1ed47fe).

**Cyfrin:** Verified.


### Signatures have no expiration deadline

**Description:** Signatures which have [no expiration parameter](https://dacian.me/signature-replay-attacks#heading-no-expiration) effectively grant a lifetime license. Consider adding an expiration parameter to the signature that if used after that time results in the signature being invalid.

**CryptoArt:**
Fixed in commit [a93977d](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/a93977d2ef0b54319c7668d9fc6abda688b355c1).

**Cyfrin:** Verified.


### Consider limiting max royalty to prevent large amount or all of the sale fee being taken as royalty

**Description:** Currently `updateRoyalties` and `setTokenRoyalty` allow the contract owner to set a royalty up to `10_000` which would take the entire sale fee as a royalty. Consider limiting these functions to set the max royalty to something more reasonable like 1000 (10%).

**CryptoArt:**
Fixed in commit [1d1125e](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/1d1125e5a021f2926dc2a2e39e05c065e3bd207c).

**Cyfrin:** Verified.


### `MintType` is almost never enforced

**Description:** The contract has an enumeration `MintType` which defines several types of mints:
```solidity
enum MintType {
    OpenMint,
    Whitelist,
    Claim,
    Burn
}
```

But there are never any checks for these mint types, for example:
* there is no check for `MintType.Whitelist` and no corresponding whitelist enforcement
* the `claim` function doesn't enforce input `data.mintType == MintType.Claim`
* similarly `burnAndMint` doesn't enforce input `data.mintType == MintType.Burn`

The only place input `data.mintType` is used is in `_validateSignature` to validate that the input parameter matches what was signed, but there is no other validation that the correct mint types are being used for the correct operations.

**CryptoArt:**
Fixed in commit [deaf964](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/deaf96420b3176be09c1522ea8c79a211f77ef82).

**Cyfrin:** Verified.


### Remove unused constant `CryptoartNFT::ROYALTY_BASE`

**Description:** The `CryptoartNFT` contract defines a constant `ROYALTY_BASE` with a value of 10,000 that is never used in the contract. This constant is intended to represent the denominator for royalty percentage calculations (where 10,000 = 100%), but it's not referenced anywhere in the contract's implementation.

**Recommended Mitigation:** Remove the unused constant to improve code clarity and reduce deployment gas costs.

**Cryptoart:**
Fixed in commit [0c0dd8c](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/0c0dd8c8d01e1b5b396852d38faceee007b37891).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Prefer named return parameters, especially for `memory` returns

**Description:** Prefer named return parameters, especially for memory returns. For example `tokenURIs` can be refactored to remove local variables and explicit return:
```solidity
function tokenURIs(uint256 tokenId)
    external
    view
    override
    onlyIfTokenExists(tokenId)
    returns (uint256 index, string[2] memory uris, bool isPinned)
{
    index = _getTokenURIIndex(tokenId);
    uris = _tokenURIs[tokenId];
    isPinned = _hasPinnedTokenURI[tokenId];
}
```

**CryptoArt:**
Fixed in commit [bdd28fa](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/bdd28fa71f8d445fb3306a1fdc16b49fa5b5d1e4).

**Cyfrin:** Verified.


### Use named constants to indicate purpose of magic numbers

**Description:** Use named constants to indicate purpose of magic numbers. For example in reference to the value of the `_tokenURIs` mapping:
* instead of using literal `2`, use existing named constant `URIS_PER_TOKEN`:
```solidity
CryptoartNFT.sol
72:    mapping(uint256 tokenId => string[2] tokenURIs) private _tokenURIs;
358:        returns (uint256, string[2] memory, bool)
361:        string[2] memory uris = _tokenURIs[tokenId];
698:        string[2] memory uris = _tokenURIs[tokenId];
```

* when setting uris in `updateMetadata` and `_setTokenURIs`, use named constants for the indexes:
```solidity
function updateMetadata(uint256 tokenId, string calldata newRedeemableURI, string calldata newNotRedeemableURI)
    external
    onlyOwner
    onlyIfTokenExists(tokenId)
{
    _tokenURIs[tokenId][URI_REDEEMABLE_INDEX] = newRedeemableURI;
    _tokenURIs[tokenId][URI_NOT_REDEEMABLE_INDEX] = newNotRedeemableURI;
    emit MetadataUpdate(tokenId); // ERC4906
}
```

This can also save gas for example in `pinTokenURI`, instead of using `_tokenURIs[tokenId].length` just use the constant `URIS_PER_TOKEN` since it never changes:
```solidity
function pinTokenURI(uint256 tokenId, uint256 index) external onlyOwner {
    if (index >= URIS_PER_TOKEN) {
        revert Error.Token_IndexOutOfBounds(tokenId, index, URIS_PER_TOKEN - 1);
    }
```

**CryptoArt:**
Fixed in commit [97ef0ad](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/97ef0add6848540e158927092d0a1af820e840fe).

**Cyfrin:** Verified.


### Remove obsolete `onlyTokenOwner` from `_transferToNftReceiver`

**Description:** Since `_transferToNftReceiver` calls `ERC721Upgradeable::safeTransferFrom`, the `onlyTokenOwner` modifier is obsolete and inefficient as:
* `safeTransferFrom` [calls](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.1/contracts/token/ERC721/ERC721Upgradeable.sol#L183) `transferFrom`
* `transferFrom` [calls](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.1/contracts/token/ERC721/ERC721Upgradeable.sol#L166) `_update` passing `_msgSender()` as the last `auth` parameter
* `_update` [calls](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.1/contracts/token/ERC721/ERC721Upgradeable.sol#L274) `_checkAuthorized` since the `auth` parameter was valid
* `_checkAuthorized` [calls](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v5.1/contracts/token/ERC721/ERC721Upgradeable.sol#L215-L238) `_isAuthorized` which verifies the caller is either the token's owner or someone who the token owner has approved

**CryptoArt:**
Fixed in commit [75e179b](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/75e179b3cea8855977a391ace169313053bc2de5).

**Cyfrin:** Verified.


### In `tokenURI` avoid copying entire `_tokenURIs[tokenId]` from `storage` into `memory`

**Description:** `tokenURI` only uses the "pinned" URI index so there's no reason to copy both token URIs from `storage` to `memory`. Simply use a `storage` reference like this:
```diff
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721Upgradeable)
        onlyIfTokenExists(tokenId)
        returns (string memory)
    {
-       string[2] memory uris = _tokenURIs[tokenId];
+       string[2] storage uris = _tokenURIs[tokenId];
        string memory uri = uris[_getTokenURIIndex(tokenId)];

        if (bytes(uri).length == 0) {
            revert Error.Token_NoURIFound(tokenId);
        }

        return string.concat(_baseURI(), uri);
    }
```

**CryptoArt:**
Fixed in commit [591fed0](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/591fed0798ab0cd61fe965c9a4d0b3e8461e0f12).

**Cyfrin:** Verified.


### `burn` should delete `tokenURI` related data and emit `TokenUriUnpinned` event

**Description:** The `burn` function should delete `tokenURI` related data and emit `TokenUriUnpinned` event:
```diff
    function burn(uint256 tokenId) public override whenNotPaused {
        // require sender is owner or approved has been removed as the internal burn function already checks this
        ERC2981Upgradeable._resetTokenRoyalty(tokenId);
        ERC721BurnableUpgradeable.burn(tokenId);
        emit Burned(tokenId);
+       emit TokenUriUnpinned(tokenId);
+       delete _tokenURIs[tokenId];
+       delete _pinnedURIIndex[tokenId];
+       delete _hasPinnedTokenURI[tokenId];
    }
```

This provides a gas refund as part of the burn and also removes token data that should no longer exist. It also prevents `hasPinnedTokenURI` from returning `true` for a burned token since that function doesn't check for valid token id (another issue has been created to track this).

**CryptoArt:**
Fixed in commit [b554763](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/b5547630515c8da112db6754a3e25dda1e69b4a7).

**Cyfrin:** Verified.


### To prevent duplicate ids in `_batchBurn`, enforce ascending order instead of nested `for` loops

**Description:** In `_batchBurn` to prevent duplicate ids, instead of using nested `for` loops it is more efficient to [enforce ascending order of ids](https://x.com/DevDacian/status/1734885772829045205) using only 1 `for` loop.

Additionally, the duplicate id check can be completely removed since if there is a duplicate id the second `burn` call will revert. For example this test added to `test/unit/BurnOperationsTest.t.sol`:
```solidity
    function test_DoubleBurn() public {
        // Mint a token to user1
        mintNFT(user1, TOKEN_ID, TOKEN_PRICE, TOKEN_PRICE);
        testAssertions.assertTokenOwnership(nft, TOKEN_ID, user1);

        // First burn should succeed
        vm.prank(user1);
        nft.burn(TOKEN_ID);

        // Second burn should revert since token no longer exists
        vm.prank(user1);
        // vm.expectRevert();
        nft.burn(TOKEN_ID);
    }
```

Results in:
```solidity
    ├─ [4294] TransparentUpgradeableProxy::fallback(1)
    │   ├─ [3940] CryptoartNFT::burn(1) [delegatecall]
    │   │   └─ ← [Revert] ERC721NonexistentToken(1)
    │   └─ ← [Revert] ERC721NonexistentToken(1)
    └─ ← [Revert] ERC721NonexistentToken(1)
```

**CryptoArt:**
Fixed in commit [3c39fb8](https://github.com/cryptoartcom/cryptoart-smart-contracts/commit/3c39fb86db6b92424a0cf55c315d0d6284c267bf).

**Cyfrin:** Verified.

\clearpage