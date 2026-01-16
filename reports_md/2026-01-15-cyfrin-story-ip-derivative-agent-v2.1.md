**Lead Auditors**

[Immeas](https://x.com/0ximmeas)

[JesJupyter](https://x.com/jesjupyter)

**Assisting Auditors**



---

# Findings
## Low Risk


### Actual minting fee can differ from predicted fee

**Description:** `IPDerivativeAgent::registerDerivativeViaAgent` relies on `predictMintingLicenseFee(...)` to determine `tokenAmount`, transfers that amount from the caller, and approves the Royalty Module for exactly that amount. However, the fee ultimately paid during `registerDerivative(...)` may differ from the predicted value (e.g., due to hook logic or other execution-time conditions). The agent does not reconcile the predicted amount with the actual amount spent.

**Impact:**
- If the actual fee is higher than the predicted amount, the Royalty Module may attempt to pull more than the agent approved/holds, causing `registerDerivative(...)` to revert (DoS) despite the user providing a sufficiently high `maxMintingFee`.
- If the actual fee is lower than the predicted amount, the excess tokens remain in the agent contract with no automatic refund path, potentially leading to stranded user funds (recoverable only via privileged/admin withdrawal, if at all).

**Recommended mitigation:**
Consider approving (and fund) `maxMintingFee`, then refund any remaining token balance to the caller after a successful registration:

```diff

        // Handle token payment if required
        if (currencyToken != address(0) && tokenAmount > 0) {
            IERC20 token = IERC20(currencyToken);

            // Transfer tokens from licensee to this contract
            token.safeTransferFrom(msg.sender, address(this), tokenAmount);

            // Increase allowance for RoyaltyModule to pull tokens during registerDerivative
+           token.safeIncreaseAllowance(ROYALTY_MODULE, maxMintingFee);
-           token.safeIncreaseAllowance(ROYALTY_MODULE, tokenAmount);
        }

        // ...

        // Clean up any remaining allowance for RoyaltyModule
        if (currencyToken != address(0) && tokenAmount > 0) {
            IERC20 token = IERC20(currencyToken);
            uint256 remainingAllowance = token.allowance(address(this), ROYALTY_MODULE);
            if (remainingAllowance > 0) {
+               token.safeTransfer(msg.sender, token.balanceOf(address(this)));
                token.forceApprove(ROYALTY_MODULE, 0);
            }
        }

```

**Story:** Fixed in [PR#5](https://github.com/piplabs/story-ecosystem/pull/5)

**Cyfrin:** Verified. Allowance is done for `maxMintingFee` together with transfer to the agent. Left over tokens are then returned after the call to the license module.

\clearpage
## Informational


### `IPDerivativeAgent` only supports single parent IP, limiting `Multi-Parent Derivative` use cases

**Description:** The `IPDerivativeAgent::registerDerivativeViaAgent` is hardcoded to support only a single parent IP by constructing fixed-length(`1`) arrays for `parentIpIds` and `licenseTermsIds`.

```solidity
        // Prepare arrays for LicensingModule call (single parent)
        address[] memory parents = new address[](1);
        parents[0] = parentIpId;
        uint256[] memory licenseTermsIds = new uint256[](1);
        licenseTermsIds[0] = licenseTermsId;
```

However, the underlying `LicensingModule::registerDerivative` explicitly supports registering derivatives with multiple parent IPs.

```solidity
    function registerDerivative(
        address childIpId,
        address[] calldata parentIpIds,
        uint256[] calldata licenseTermsIds,
```

According to the protocol [documentation](https://docs.story.foundation/concepts/licensing-module/license-token#registering-a-derivative), an IP Asset can only register as a derivative once. If it has multiple parents, all parent IPs must be registered atomically in the same call, and once registered, no additional parents can be linked later.
> An IP Asset can only register as a derivative one time. If an IP Asset has multiple parents, it must register both at the same time.
> Once an IP Asset is a derivative, it cannot link any more parents.

Given this constraint, the agent’s single-parent design is not a recoverable limitation. Instead, it permanently prevents registering any multi-parent derivative through `IPDerivativeAgent`, even though such derivatives are explicitly supported at the core protocol level.

As a result, the agent abstraction introduces an implicit and restriction that materially diverges from the capabilities and guarantees of `LicensingModule`.

This single-parent assumption also propagates to:
- Fee estimation via `predictMintingLicenseFee()`, which only accepts a single parent IP, preventing accurate fee prediction for multi-parent derivatives.
- The whitelist mechanism, which is keyed by a single `parentIpId`, making it impossible to express authorization rules for combinations of multiple parent IPs.

**Impact:** This limits the agent’s applicability for cross-parent derivative use cases.

**Recommended Mitigation:**
- If multi-parent derivatives are intended to be supported via the agent, extend `IPDerivativeAgent` to accept arrays of parent IPs and license terms, and update fee prediction and whitelist logic accordingly.

- If single-parent support is an intentional design decision, explicitly document this limitation and clarify that multi-parent derivatives are not supported and must be registered directly through `LicensingModule`.

**Story:** Acknowledged.


### Fee-on-transfer ERC20 tokens not supported

**Description:** `IPDerivativeAgent::registerDerivativeViaAgent` assumes the fee token is transferred 1:1. It pulls `tokenAmount` from the caller via `transferFrom`, then later the Royalty Module pulls the required minting fee from the agent via `transferFrom`.

For fee-on-transfer/deflationary ERC20s, the agent may receive less than `tokenAmount` on the initial transfer, causing the subsequent Royalty Module pulls to fail due to insufficient balance (and the derivative registration to revert).

Consider restricting fee tokens to non–fee-on-transfer ERC20s, or if add a parameter `amountIn`, transfer this and measure the agent’s received balance delta and only proceed/approve when it covers the required fee, while refunding the delta.


**Story:** Acknowledged.


### `CommercializerChecker` Access Control Bypass via `IPDerivativeAgent`

**Description:** When `IPDerivativeAgent::registerDerivativeViaAgent` is used, the agent contract acts as an intermediary and calls `LicensingModule::registerDerivative` on behalf of the user. As a result, the agent contract address is propagated as the caller / licensee throughout the verification flow.

In LicensingModule:
```solidity
   if (
       !ILicenseTemplate(licenseTemplate).verifyRegisterDerivativeForAllParents(
           childIpId,
           parentIpIds,
           licenseTermsIds,
           msg.sender  // This is the agent contract address
       )
   ) {
       revert Errors.LicensingModule__LicenseNotCompatibleForDerivative(childIpId);
   }
```

In `LicensingModule::verifyRegisterDerivativeForAllParents`, the caller parameter is derived from `msg.sender`, which in this case is the agent contract. This value is then forwarded to the `commercializerChecker` hook and used as the licensee parameter during verification.

```solidity
  // Check if the commercializerChecker allows the link
   if (terms.commercializerChecker != address(0)) {
       if (
           !IHookModule(terms.commercializerChecker).verify(
               parentIpId,
               licensee,  // This is the agent address, not the actual user
               terms.commercializerCheckerData
           )
       ) {
           return false;
       }
   }
```


Consequently, `commercializerChecker` implementations observe and validate the agent address rather than the actual end user initiating the request. Hook logic that assumes the licensee corresponds to the end user (e.g., blacklists, allowlists, or compliance checks) may therefore behave differently when invoked via the agent.

It is unclear whether this behavior is an intentional design decision or an implicit consequence of the agent abstraction.


**Impact:** This behavior does not represent a direct vulnerability and may be intended. The practical impact is limited to a semantic difference between agent-based and direct interactions with LicensingModule.

In the worst case, a restricted end user could register a derivative through the agent for a parent–child IP combination that is otherwise globally allowed. This does not bypass parent-level authorization, but may differ from expectations of hook implementations that assume end-user–level enforcement.

**Recommended Mitigation:** The relevant behavior could be explicitly documented, such as " the agent overrides the hook".

**Story:** Acknowledged.

\clearpage
## Gas Optimization


### `IPDerivativeAgent::constructor` `owner` check redundant

**Description:** The `IPDerivativeAgent::constructor` checks `owner == address(0)` after calling `Ownable(owner)` in the initializer list. Since OpenZeppelin’s `Ownable` constructor already reverts on a zero owner, this custom check is redundant and will never be reached. Consider removing it.

**Story:** Fixed in [PR#5](https://github.com/piplabs/story-ecosystem/pull/5)

**Cyfrin:** Verified.

\clearpage