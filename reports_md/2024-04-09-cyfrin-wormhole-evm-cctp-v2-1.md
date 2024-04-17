**Lead Auditors**

[Giovanni Di Siena](https://twitter.com/giovannidisiena)

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**

[Hans](https://twitter.com/hansfriese)


---

# Findings
## Medium Risk


### Redemptions are blocked when L2 sequencers are down

**Description:** Given that rollups such as [Optimism](https://docs.optimism.io/chain/differences#address-aliasing) and [Arbitrum](https://docs.arbitrum.io/arbos/l1-to-l2-messaging#address-aliasing) offer methods for forced transaction inclusion, it is important that the aliased sender address is also [checked](https://solodit.xyz/issues/m-8-operator-is-blocked-when-sequencer-is-down-on-arbitrum-sherlock-none-index-git) within [`Logic::redeemTokensWithPayload`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Logic.sol#L88-L91) when verifying the sender is the specified `mintRecipient` to allow for maximum uptime in the event of sequencer downtime.

```solidity
// Confirm that the caller is the `mintRecipient` to ensure atomic execution.
require(
    msg.sender.toUniversalAddress() == deposit.mintRecipient, "caller must be mintRecipient"
);
```

**Impact:** Failure to consider the aliased `mintRecipient` address prevents the execution of valid VAAs on a target CCTP domain where transactions are batched by a centralized L2 sequencer. Since this VAA could carry a time-sensitive payload, such as the urgent cross-chain liquidity infusion to a protocol, this issue has the potential to have a high impact with reasonable likelihood.

**Proof of Concept:**
1. Protocol X attempts to transfer 10,000 USDC from CCTP Domain A to CCTP Domain B.
2. CCTP Domain B is an L2 rollup that batches transactions for publishing onto the L1 chain via a centralized sequencer.
3. The L2 sequencer goes down; however, transactions can still be executed via forced inclusion on the L1 chain.
4. Protocol X implements the relevant functionality and attempts to redeem 10,000 USDC via forced inclusion.
5. The Wormhole CCTP integration does not consider the contract's aliased address when validating the `mintRecipient`, so the redemption fails.
6. Cross-chain transfer of this liquidity will remain blocked so long as the sequencer is down.

**Recommended Mitigation:** Validation of the sender address against the `mintRecipient` should also consider the aliased `mintRecipient` address to allow for maximum uptime when [`Logic::redeemTokensWithPayload`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Logic.sol#L88-L91) is called via forced inclusion.

**Wormhole Foundation:** Since CCTP [doesn’t deal with this aliasing](https://github.com/circlefin/evm-cctp-contracts/blob/adb2a382b09ea574f4d18d8af5b6706e8ed9b8f2/src/MessageTransmitter.sol#L270-L277), we don’t feel strongly that we should either.

**Cyfrin:** Acknowledged.


### Loss of funds due to malicious forcing of `mintRecipient` onto Circle blacklist when CCTP message is in-flight

**Description:** A scenario has been identified in which it may not be possible for the `mintRecipient` to execute redemption on the target domain due to the actions of a bad actor while an otherwise valid CCTP message is in-flight. It is ostensibly the responsibility of the user to correctly configure the `mintRecipient`; however, one could reasonably assume the case where an attacker dusts the `mintRecipient` address with funds stolen in a recent exploit, that may have been deposited to and subsequently withdrawn from an external protocol, or an OFAC-sanctioned token such as TORN, to force this address to become blacklisted by Circle on the target domain while the message is in-flight, thereby causing both the original sender and their intended target recipient to lose access to the tokens.

In the current design, it is not possible to update the `mintRecipient` for a given deposit due to the multicast nature of VAAs. CCTP exposes [`MessageTransmitter::replaceMessage`](https://github.com/circlefin/evm-cctp-contracts/blob/1662356f9e60bb3f18cb6d09f95f628f0cc3637f/src/MessageTransmitter.sol#L129-L181) which allows the original source caller to update the destination caller for a given message and its corresponding attestation; however, the Wormhole CCTP integration currently provides no access to this function and has no similar functionality of its own to allow updates to the target `mintRecipient` of the VAA. Without any method for replacing potentially affected VAAs with new VAAs specifying an updated `mintRecipient`, this could result in permanent denial-of-service on the `mintRecipient` receiving tokens on the target domain – the source USDC/EURC will be burnt, but it may be very unlikely that the legitimate recipient is ever able to mint the funds on the destination domain, and once the tokens are burned, there is no path to recovery on the source domain.

This type of scenario is likely to occur primarily where a bad actor intentionally attempts to sabotage a cross-chain transfer of funds that the source caller otherwise expects to be successful. A rational actor would not knowingly attempt a cross-chain transfer to a known blacklisted address, especially if the intended recipient is not a widely-used protocol, which tend to be exempt from sanctions even when receiving funds from a known attacker, but rather an independent EOA. In this case, the destination call to [`Logic::redeemTokensWithPayload`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Logic.sol#L61-L108) will fail when the CCTP contracts attempt to mint the tokens and can only be retried if the `mintRecipient` address somehow comes back off the Circle blacklist, the [mechanics of which](https://www.circle.com/hubfs/Blog%20Posts/Circle%20Stablecoin%20Access%20Denial%20Policy_pdf.pdf) are not overly clear. It is also possible that request(s) made by law-enforcement agencies for the blacklisting of an entire protocol X, as the mint recipient on target domain Y, will cause innocent users to also lose access to their bridged funds.

It is understood that the motivation for restricting message replacement functionality is due to the additional complexity in handling this edge case and ensuring that the VAA of the original message cannot be redeemed with the replaced CCTP attestation, given the additional attack surface. Given that it is not entirely clear how the Circle blacklisting policy would apply in this case, it would be best for someone with the relevant context to aid in making the decision based on this cost/benefit analysis. If it is the case that a victim can be forced onto the blacklist without a clear path to resolution, then this clearly is not ideal. Even if they are eventually able to have this issue resolved, the impact could be time-sensitive in nature, thinking in the context of cross-chain actions that may need to perform some rebalancing/liquidation function, plus a sufficiently motivated attacker could potentially repeatedly front-run any subsequent attempts at minting on the target domain. It is not entirely clear how likely this final point is in practice, once the messages are no longer in-flight and simply ready for execution on the destination, since it is assumed the blacklist would not likely be updated that quickly. In any case, it is agreed that allowing message replacement will add a non-trivial amount of complexity and does indeed increase the attack surface, as previously identified. So depending on how the blacklist is intended to function, it may be worth allowing message replacement, but it is not possible to say with certainty whether this issue is worth addressing.

**Impact:** There is only a single address that is permitted to execute a given VAA on the target domain; however, there exists a scenario in which this `mintReceipient` may be permanently unable to perform redemption due to the malicious addition of this address to the Circle blacklist. In this case, there is a material loss of funds with reasonable likelihood.

**Proof of Concept:**
1. Alice burns 10,000 USDC on CCTP Domain A to be transferred to her EOA on CCTP Domain B.
2. While this CCTP message is in-flight, an attacker withdraws a non-trivial amount of USDC, that was previously obtained from a recent exploit, from protocol X to Alice's EOA on CCTP domain B.
3. Law enforcement notifies Circle to blacklist Alice's EOA, which now holds stolen funds.
4. Alice attempts to redeem 10,000 USDC on CCTP Domain B, but minting fails because her EOA is now blacklisted on the USDC contract.
5. The 10,000 USDC remains burnt and cannot be minted on the target domain since the VAA containing the attested CCTP message can never be executed without the USDC mint reverting.

**Recommended Mitigation:** Consider allowing VAAs to be replaced by new VAAs for a given CCTP message and corresponding attestation, so long as they have not already been consumed on the target domain. Alternatively, consider adding an additional Governance action dedicated to the purpose of recovering the USDC burnt by a VAA that has not yet been consumed on the target domain due to malicious blacklisting.

**Wormhole Foundation:** Although CCTP has the ability to replace messages, it is also subject to this same issue since the original message recipient [can’t be changed](https://github.com/circlefin/evm-cctp-contracts/blob/adb2a382b09ea574f4d18d8af5b6706e8ed9b8f2/src/MessageTransmitter.sol#L170-L175).

**Cyfrin:** Acknowledged.

\clearpage
## Low Risk


### Potentially dangerous out-of-bounds memory access in `BytesParsing::sliceUnchecked`

**Description:** [`BytesParsing::sliceUnchecked`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/libraries/BytesParsing.sol#L16-L57) currently[ bails early](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/libraries/BytesParsing.sol#L21-L24) for the degenerate case when the slice length is zero; however, there is no validation on the length of the encoded bytes parameter `encoded` itself. If the length of `encoded` is less than the slice `length`, then it is possible to access memory out-of-bounds.

```solidity
function sliceUnchecked(bytes memory encoded, uint256 offset, uint256 length)
    internal
    pure
    returns (bytes memory ret, uint256 nextOffset)
{
    //bail early for degenerate case
    if (length == 0) {
        return (new bytes(0), offset);
    }

    assembly ("memory-safe") {
        nextOffset := add(offset, length)
        ret := mload(freeMemoryPtr)

        /* snip: inline dev comments */

        let shift := and(length, 31) //equivalent to `mod(length, 32)` but 2 gas cheaper
        if iszero(shift) { shift := wordSize }

        let dest := add(ret, shift)
        let end := add(dest, length)
        for { let src := add(add(encoded, shift), offset) } lt(dest, end) {
            src := add(src, wordSize)
            dest := add(dest, wordSize)
        } { mstore(dest, mload(src)) }

        mstore(ret, length)
        //When compiling with --via-ir then normally allocated memory (i.e. via new) will have 32 byte
        //  memory alignment and so we enforce the same memory alignment here.
        mstore(freeMemoryPtr, and(add(dest, 31), not(31)))
    }
}
```

Since the `for` loop begins at the offset of `encoded` in memory, accounting for its length and accompanying `shift` calculation depending on the `length` supplied, and execution continues so long as `dest` is less than `end`, it is possible to continue loading additional words out of bounds simply by passing larger `length` values. Therefore, regardless of the length of the original bytes, the output slice will always have a size defined by the `length` parameter.

It is understood that this is known behavior due to the unchecked nature of this function and the accompanying checked version, which performs validation on the `nextOffset` return value compared with the length of the encoded bytes.

```solidity
function slice(bytes memory encoded, uint256 offset, uint256 length)
    internal
    pure
    returns (bytes memory ret, uint256 nextOffset)
{
    (ret, nextOffset) = sliceUnchecked(encoded, offset, length);
    checkBound(nextOffset, encoded.length);
}
```

It has not been possible within the constraints of this review to identify a valid scenario in which malicious calldata can make use of this behavior to launch a successful exploit; however, this is not a guarantee that the usage of this library function is bug-free since there do [exist](https://solodit.xyz/issues/h-04-incorrect-implementation-of-access-control-in-mimoproxyexecute-code4rena-mimo-defi-mimo-august-2022-contest-git) [certain](https://solodit.xyz/issues/m-2-high-risk-checks-can-be-bypassed-with-extra-calldata-padding-sherlock-olympus-on-chain-governance-git) [quirks](https://solodit.xyz/issues/opcalldataload-opcalldatacopy-reading-position-out-of-calldata-bounds-spearbit-none-polygon-zkevm-pdf) related to the loading of calldata.

**Impact:** The impact is limited in the context of the library function's usage in the scope of this review; however, it is advisable to check any other usage elsewhere and in the future to ensure that this behavior cannot be weaponized. `BytesParsing::sliceUnchecked` is currently only used in [`WormholeCctpMessages::_decodeBytes`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/libraries/WormholeCctpMessages.sol#L227-L235), which itself is called in [`WormholeCctpMessages::decodeDeposit`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/libraries/WormholeCctpMessages.sol#L196-L223). This latter function is utilized in two places:
1. [`Logic::decodeDepositWithPayload`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Logic.sol#L126-L148): here, any issues in slicing the encoded bytes would impact users' ability to decode payloads, potentially stopping them from correctly retrieving the necessary information for redemptions.
2. [`WormholeCctpTokenMessenger::verifyVaaAndMint`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/WormholeCctpTokenMessenger.sol#L144-L197)/[`WormholeCctpTokenMessenger::verifyVaaAndMintLegacy`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/WormholeCctpTokenMessenger.sol#L199-L253): these functions verify and reconcile CCTP and Wormhole messages in order to mint tokens for the encoded mint recipient. Fortunately, for a malicious calldata payload, Wormhole itself will revert when [`IWormhole::parseAndVerifyVM`](https://github.com/wormhole-foundation/wormhole/blob/eee4641f55954d2d0db47831688a2e97eb20f7ee/ethereum/contracts/Messages.sol#L15-L20) is called via [`WormholeCctpTokenMessenger::_parseAndVerifyVaa`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/WormholeCctpTokenMessenger.sol#L295-L311) since it will be unable to [retrieve a valid version number](https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/Messages.sol#L150) when [casting](https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/libraries/external/BytesLib.sol#L309) to `uint8`.

**Proof of Concept:** Apply the following git diff to differential test against a Python implementation:
```diff
diff --git a/evm/.gitignore b/evm/.gitignore
--- a/evm/.gitignore
+++ b/evm/.gitignore
@@ -7,3 +7,4 @@ lib
 node_modules
 out
 ts/src/ethers-contracts
+venv/
diff --git a/evm/forge/tests/differential/BytesParsing.t.sol b/evm/forge/tests/differential/BytesParsing.t.sol
new file mode 100644
--- /dev/null
+++ b/evm/forge/tests/differential/BytesParsing.t.sol
@@ -0,0 +1,72 @@
+// SPDX-License-Identifier: Apache 2
+pragma solidity ^0.8.19;
+
+import "forge-std/Test.sol";
+import "forge-std/console.sol";
+
+import {BytesParsing} from "src/libraries/BytesParsing.sol";
+
+contract BytesParsingTest is Test {
+    using BytesParsing for bytes;
+
+    function setUp() public {}
+
+    function test_sliceUncheckedFuzz(bytes memory encoded, uint256 offset, uint256 length) public {
+        bound(offset, 0, type(uint8).max);
+        bound(length, 0, type(uint8).max);
+        if (offset > encoded.length || length > encoded.length || offset + length > encoded.length) {
+            return;
+        }
+
+        sliceUncheckedBase(encoded, offset, length);
+    }
+
+    function test_sliceUncheckedConcreteReadOOB() public {
+        bytes memory encoded = bytes("");
+        bytes32 dirty = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
+        assembly {
+            mstore(add(encoded, 0x20), dirty)
+        }
+        uint256 offset = 0;
+        uint256 length = 32;
+
+        sliceUncheckedBase(encoded, offset, length);
+    }
+
+    function sliceUncheckedBase(bytes memory encoded, uint256 offset, uint256 length)
+        internal
+        returns (
+            bytes memory soliditySlice,
+            uint256 solidityNextOffset,
+            bytes memory pythonSlice,
+            uint256 pythonNextOffset
+        )
+    {
+        (soliditySlice, solidityNextOffset) = encoded.sliceUnchecked(offset, length);
+        assertEq(soliditySlice.length, length, "wrong length");
+
+        string[] memory inputs = new string[](9);
+        inputs[0] = "python";
+        inputs[1] = "forge/tests/differential/python/bytes_parsing.py";
+        inputs[2] = "slice_unchecked";
+        inputs[3] = "--encoded";
+        inputs[4] = vm.toString(encoded);
+        inputs[5] = "--offset";
+        inputs[6] = vm.toString(offset);
+        inputs[7] = "--length";
+        inputs[8] = vm.toString(length);
+
+        (pythonSlice, pythonNextOffset) = abi.decode(vm.ffi(inputs), (bytes, uint256));
+
+        emit log_named_uint("soliditySlice.length", soliditySlice.length);
+        emit log_named_uint("pythonSlice.length", pythonSlice.length);
+
+        emit log_named_bytes("soliditySlice", soliditySlice);
+        emit log_named_bytes("pythonSlice", pythonSlice);
+        emit log_named_uint("solidityNextOffset", solidityNextOffset);
+        emit log_named_uint("pythonNextOffset", pythonNextOffset);
+
+        assertEq(soliditySlice, pythonSlice, "wrong slice");
+        assertEq(solidityNextOffset, pythonNextOffset, "wrong next offset");
+    }
+}
diff --git a/evm/forge/tests/differential/python/bytes_parsing.py b/evm/forge/tests/differential/python/bytes_parsing.py
new file mode 100644
--- /dev/null
+++ b/evm/forge/tests/differential/python/bytes_parsing.py
@@ -0,0 +1,42 @@
+from eth_abi import encode
+import argparse
+
+
+def main(args):
+    if args.function == "slice_unchecked":
+        slice, next_offset = slice_unchecked(args)
+        encode_and_print(slice, next_offset)
+
+
+def slice_unchecked(args):
+    if args.length == 0:
+        return (b"", args.offset)
+
+    next_offset = args.offset + args.length
+
+    encoded_bytes = (
+        bytes.fromhex(args.encoded[2:])
+        if args.encoded.startswith("0x")
+        else bytes.fromhex(args.encoded)
+    )
+    return (encoded_bytes[args.offset : next_offset], next_offset)
+
+
+def encode_and_print(slice, next_offset):
+    encoded_output = encode(["bytes", "uint256"], (slice, next_offset))
+    ## append 0x for FFI parsing
+    print("0x" + encoded_output.hex())
+
+
+def parse_args():
+    parser = argparse.ArgumentParser()
+    parser.add_argument("function", choices=["slice_unchecked"])
+    parser.add_argument("--encoded", type=str)
+    parser.add_argument("--offset", type=int)
+    parser.add_argument("--length", type=int)
+    return parser.parse_args()
+
+
+if __name__ == "__main__":
+    args = parse_args()
+    main(args)
diff --git a/evm/forge/tests/differential/python/requirements.txt b/evm/forge/tests/differential/python/requirements.txt
new file mode 100644
--- /dev/null
+++ b/evm/forge/tests/differential/python/requirements.txt
@@ -0,0 +1 @@
+eth_abi==5.0.0
\ No newline at end of file
diff --git a/evm/foundry.toml b/evm/foundry.toml
--- a/evm/foundry.toml
+++ b/evm/foundry.toml
@@ -31,4 +31,7 @@ gas_reports = ["*"]

 gas_limit = "18446744073709551615"

+[profile.ffi]
+ffi = true
+
```

**Recommended Mitigation:** Consider bailing early if the length of the bytes from which to construct a slice is zero, and always ensure the resultant offset is correctly validated against the length when using the unchecked version of the function.

**Wormhole Foundation:** The [slice method](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/7599cbe984ce17dd9e87c81fb0b6ea12ff1635ba/evm/src/libraries/BytesParsing.sol#L59) does this checking for us. Since we’re controlling the length specified in the wire format, we can safely use the unchecked variant.

**Cyfrin:** Acknowledged.


### A given CCTP domain can be registered for multiple foreign chains due to insufficient validation in `Governance::registerEmitterAndDomain`

**Description:** [`Governance::registerEmitterAndDomain`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Governance.sol#L48-L84) is a Governance action that is used to register the emitter address and corresponding CCTP domain for a given foreign chain. Validation is currently performed to ensure that the registered CCTP domain of the foreign chain is not equal to that of the local chain; however, there is no such check to ensure that the given CCTP domain has not already been registered for a different foreign chain. In this case, where the CCTP domain of an existing foreign chain is mistakenly used in the registration of a new foreign chain, the [`getDomainToChain`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Governance.sol#L83) mapping of an existing CCTP domain will be overwritten to the most recently registered foreign chain. Given the validation that prevents foreign chains from being registered again, without a method for updating an already registered emitter, it will not be possible to correct this corruption of state.

```solidity
function registerEmitterAndDomain(bytes memory encodedVaa) public {
    /* snip: parsing of Governance VAA payload */

    // For now, ensure that we cannot register the same foreign chain again.
    require(registeredEmitters[foreignChain] == 0, "chain already registered");

    /* snip: additional parsing of Governance VAA payload */

    // Set the registeredEmitters state variable.
    registeredEmitters[foreignChain] = foreignAddress;

    // update the chainId to domain (and domain to chainId) mappings
    getChainToDomain()[foreignChain] = cctpDomain;
    getDomainToChain()[cctpDomain] = foreignChain;
}
```

**Impact:** The impact of this issue in the current scope is limited since the corrupted state is only ever queried in a public view function; however, if it is important for third-party integrators, then this has the potential to cause downstream issues.

**Proof of Concept:**
1. CCTP Domain A is registered for foreign chain identifier X.
2. CCTP Domain A is again registered, this time for foreign chain identifier Y.
3. The `getDomainToChain` mapping for CCTP Domain A now points to foreign chain identifier Y, while the `getChainToDomain` mapping for both X and Y now points to CCTP domain A.

**Recommended Mitigation:** Consider adding the following validation when registering a CCTP domain for a foreign chain:

```diff
+ require (getDomainToChain()[cctpDomain] == 0, "CCTP domain already registered for a different foreign chain");
```

**Wormhole Foundation:** We are comfortable that governance messages are sufficiently validated before being signed by the guardians and submitted on-chain.

**Cyfrin:** Acknowledged.


### Lack of Governance action to update registered emitters

**Description:** The Wormhole CCTP integration contract currently exposes a function [`Governance::registerEmitterAndDomain`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Governance.sol#L48-L84) to register an emitter address and its corresponding CCTP domain on the given foreign chain; however, no such function currently exists to update this state. Any mistake made when registering the emitter and CCTP domain is irreversible unless an upgrade is performed on the entirety of the integration contract itself. Deployment of protocol upgrades comes with its own risks and should not be performed as a necessary fix for trivial human errors. Having a separate governance action to update the emitter address, foreign chain identifier, and CCTP domain is a preferable pre-emptive measure against any potential human errors.

```solidity
function registerEmitterAndDomain(bytes memory encodedVaa) public {
    /* snip: parsing of Governance VAA payload */

    // Set the registeredEmitters state variable.
    registeredEmitters[foreignChain] = foreignAddress;

    // update the chainId to domain (and domain to chainId) mappings
    getChainToDomain()[foreignChain] = cctpDomain;
    getDomainToChain()[cctpDomain] = foreignChain;
}
```

**Impact:** In the event an emitter is registered with an incorrect foreign chain identifier or CCTP domain, then a protocol upgrade will be required to mitigate this issue. As such, the risks associated with the deployment of protocol upgrades and the potential time-sensitive nature of this issue designate a low severity issue.

**Proof of Concept:**
1. A Governance VAA erroneously registers an emitter with the incorrect foreign chain identifier.
2. A Governance upgrade is now required to re-initialize this state so that the correct foreign chain identifier can be associated with the given emitter address.

**Recommended Mitigation:** The addition of a `Governance::updateEmitterAndDomain` function is recommended to allow Governance to more easily respond to any issues with the registered emitter state.

**Wormhole Foundation:** Allowing existing emitters to be updated comes with similar impacts of admin mistakes. But allowing updates is indeed easier than coordinating a whole contract upgrade. However we won’t change this since we can’t easily enforce that governance messages to perform these updates are played in sequence.

**Cyfrin:** Acknowledged.

\clearpage
## Informational


### Use `SafeERC20::safeIncreaseAllowance` in the place of `IERC20::approve` in `WormholeCctpTokenMessenger::setTokenMessengerApproval`

Although the `SafeERC20` library is [declared](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/bbc593d7f4caf2b59bf9de18a870e2df37ed6fd4/evm/src/contracts/WormholeCctpTokenMessenger.sol#L26) as being used for the `IERC20` interface, [`WormholeCctpTokenMessenger::setTokenMessengerApproval`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/bbc593d7f4caf2b59bf9de18a870e2df37ed6fd4/evm/src/contracts/WormholeCctpTokenMessenger.sol#L92-L98) uses `IERC20::approve` directly instead of `SafeERC20::safeApprove`. Whilst the `FiatTokenV2_2` implementation of `IERC20::approve` does return the `true` boolean, reverting otherwise, some tokens can silently fail when this function is called; therefore, it may be necessary to check the return value of this call if the protocol ever intends to work with other ERC20 tokens. Also, note that OpenZeppelin discourages the use of `SafeERC20::safeApprove` (deprecated in v5) and instead recommends the use of `safeERC20::safeIncreaseAllowance`.

**Wormhole Foundation:** Fixed in [PR \#52](https://github.com/wormhole-foundation/wormhole-circle-integration/pull/52).

**Cyfrin:** Verified. The direct use of `ERC20::approve` has been modified to instead use `safeERC20::safeIncreaseAllowance`.


### Potential accounting error when the decimals of bridged assets differ between CCTP domains

The `FiatTokenV2_2` contract deployed to target CCTP domains typically has 6 decimals; however, on some chains, such as BNB Smart Chain, a decimal value of 18 is used. The Wormhole CCTP integration contract and the core CCTP contracts themselves do not reconcile any differences in the source/destination token decimals, which would cause critical issues in the amount to be minted on the target domain since these contracts are not working with Wormhole x-assets (where this issue is sufficiently mitigated) but rather native USDC/EURC on the respective chains.

For example, assuming both CCTP domains are intended to be supported, burning 20 tokens on BNB Smart Chain where USDC has 18 decimals, encoded as `20e18`, then trying to mint this amount on the destination chain where USDC has 6 decimals (e.g. Ethereum), then there is a problem because the recipient has not, in fact, minted `20e12` tokens instead of 20.

Since BNB Smart Chain is not one of the currently supported domains, and all currently supported CCTP domains use a version of the `FiatTokenV2_2` contract with 6 decimals, this is not an issue at present. If a non-standard domain is ever intended to be supported for cross-chain transfers, then it is important that any differences in the token decimals are correctly reconciled.

**Wormhole Foundation:** No need to change anything now but will have to make changes if CCTP introduces other chains. One to be aware of and keep and eye on going forwards.

**Cyfrin:** Acknowledged.


### `Setup` unnecessarily inherits OpenZeppelin `Context`

The `Setup` contract currently inherits OpenZeppelin `Context`; however, this is unnecessary as none of its functionality is used anywhere within the logic.

**Wormhole Foundation:** Fixed in [PR \#52](https://github.com/wormhole-foundation/wormhole-circle-integration/pull/52).

**Cyfrin:** Acknowledged.


### Potential dangers for inheriting applications executing the Wormhole payload

The Wormhole CCTP contracts are written to allow integration by both composition and inheritance. When calling `Logic::transferTokensWithPayload`, users are able to pass an arbitrary [Wormhole payload](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/bbc593d7f4caf2b59bf9de18a870e2df37ed6fd4/evm/src/contracts/CircleIntegration/Logic.sol#L34) that gets [parsed from the VAA](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/bbc593d7f4caf2b59bf9de18a870e2df37ed6fd4/evm/src/contracts/CircleIntegration/Logic.sol#L83) on the destination chain. It is our understanding that, if required, execution of this payload is intended to be the responsibility of the integrating application. As such, it has been noted that the behavior of payload execution has not been tested; however, the Wormhole payload does not necessarily need to be executed with an external call, since it could simply contain information that is useful to the inheriting contract.

In the case the payload is used as the input for an arbitrary external call, there is a risk here for the integrator. For applications inheriting the Wormhole CCTP contracts, execution of the payload will occur in the context of these contracts, which could be potentially dangerous. It is, therefore, the responsibility of the integrator to perform sufficient application-specific validation on the payload. This should be clearly documented.

**Wormhole Foundation:** The existing functionality is as intended.

**Cyfrin:** Acknowledged.


### Sequencing considerations should be clearly documented and communicated to integrators

The Wormhole CCTP integration contracts do not enforce in-sequence message execution by default as a design choice to prevent one message from blocking subsequent messages, instead opting to give integrators the ability to order transactions if they so need. Given it is the responsibility of integrating protocols to execute or otherwise consume the Wormhole payload transmitted by the integration contracts, it is possible for out-of-order executions to cause issues with both high severity and high likelihood if the ordering of message execution is not correctly handled. Wormhole VAAs do not have to be ordered and are effectively multicast, so this does not affect the integration insofar as the contracts in scope for this audit are concerned.

When it comes to handling generic payloads along with token transfers across different chains, corruption of the intended order could have non-trivial consequences for operations that are sensitive to order or timing, such as in lending or derivatives, given how deeply USDC is entrenched within the whole of DeFi. Consider the following scenario:
1. Alice transfers 1000 USDC from CCTP Domain A to Perp X on CCTP Domain B.
2. Alice sends another 100 USDC to Perp X, with a payload to open a 5000 USDC position at 5X leverage.
3. Alice's messages are executed on CCTP Doman B:
    1. If the first message is executed before the second, Alice has a margin of 1100, and the trade is correctly created on X.
    2. If the second message is executed before the first, the trade cannot be opened due to insufficient margin. Factoring in liquidations, auctions, and so on, out-of-sequence execution can have a plethora of unintended consequences.

As noted above, the sender has the ability to specify a Wormhole nonce, and there is also a Wormhole sequence number that is auto-incremented. These are both received on the destination chain in the VAA, so integrators wishing to enforce order can do so either by auto-incrementing the Wormhole nonce on the source domain or by using the Wormhole sequence number and then enforcing ordering on the target domain by checking the source chain, sender address, and nonce/sequence. This should be clearly documented and communicated to users.

**Wormhole Foundation:** Integrators requiring ordered transactions will have to enforce this themselves, which is intended behavior.

**Cyfrin:** Acknowledged.


### Calldata restriction on Wormhole payload should not be modified

Based on an end-to-end fork test written between Arbitrum and Avalanche C-Chain (15M block gas limit), a gas usage of ~2.5M units has been observed using the maximum allowed payload length of `type(uint16).max`. It is important that this calldata restriction is not modified; otherwise, a scenario could exist where it may not be possible for the `mintRecipient` to execute redemptions on the target domain due to an out-of-gas error caused by an [excessively large Wormhole payload](https://solodit.xyz/issues/h-2-malicious-user-can-use-an-excessively-large-_toaddress-in-oftcoresendfrom-to-break-layerzero-communication-sherlock-uxd-uxd-protocol-git). Even in the current state, integrators should be careful to ensure that any additional calls wrapping those to `Logic::redeemTokensWithPayload` cannot be made susceptible to this issue.

**Wormhole Foundation:** Acknowledged.

**Cyfrin:** Acknowledged.


### Temporary denial-of-service when in-flight messages are not executed before a deprecated Wormhole Guardian set expires

**Description:** Wormhole exposes a governance action in [`Governance::submitNewGuardianSet`](https://github.com/wormhole-foundation/wormhole/blob/eee4641f55954d2d0db47831688a2e97eb20f7ee/ethereum/contracts/Governance.sol#L76-L112) to update the Guardian set via Governance VAA.

```solidity
function submitNewGuardianSet(bytes memory _vm) public {
    ...

    // Trigger a time-based expiry of current guardianSet
    expireGuardianSet(getCurrentGuardianSetIndex());

    // Add the new guardianSet to guardianSets
    storeGuardianSet(upgrade.newGuardianSet, upgrade.newGuardianSetIndex);

    // Makes the new guardianSet effective
    updateGuardianSetIndex(upgrade.newGuardianSetIndex);
}
```

When this function is called, [`Setters:: expireGuardianSet`](https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/Setters.sol#L13-L15) initiates a 24-hour timeframe after which the current guardian set expires.

```solidity
function expireGuardianSet(uint32 index) internal {
    _state.guardianSets[index].expirationTime = uint32(block.timestamp) + 86400;
}
```

Hence, any in-flight VAAs that utilize the deprecated Guardian set index will fail to be executed given the validation present in [`Messages::verifyVMInternal`](https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/Messages.sol).

```solidity
/// @dev Checks if VM guardian set index matches the current index (unless the current set is expired).
if(vm.guardianSetIndex != getCurrentGuardianSetIndex() && guardianSet.expirationTime < block.timestamp){
    return (false, "guardian set has expired");
}
```

Considering there is no automatic relaying of Wormhole CCTP messages, counter to what is specified in the [documentation](https://docs.wormhole.com/wormhole/quick-start/tutorials/cctp) (unless an integrator implements their own relayer), there are no guarantees that an in-flight message which utilizes an old Guardian set index will be executed by the `mintRecipient` on the target domain within its 24-hour expiration period. This could occur, for example, in cases such as:
1. Integrator messages are blocked by their use of the Wormhole nonce/sequence number.
2. CCTP contracts are paused on the target domain, causing all redemptions to revert.
3. L2 sequencer downtime, since the Wormhole CCTP integration contracts do not consider aliased addresses for forced inclusion.
4. The `mintRecipient` is a contract that has been paused following an exploit, temporarily restricting all incoming and outgoing transfers.

In the current design, it is not possible to update the `mintRecipient` for a given deposit due to the multicast nature of VAAs. CCTP exposes [`MessageTransmitter::replaceMessage`](https://github.com/circlefin/evm-cctp-contracts/blob/1662356f9e60bb3f18cb6d09f95f628f0cc3637f/src/MessageTransmitter.sol#L129-L181) which allows the original source caller to update the destination caller for a given message and its corresponding attestation; however, the Wormhole CCTP integration currently provides no access to this function and has no similar functionality of its own to allow updates to the target `mintRecipient` of the VAA.

Additionally, there is no method for forcibly executing the redemption of USDC/EURC to the `mintRecipient`, which is the only address allowed to execute the VAA on the target domain, as validated in [`Logic::redeemTokensWithPayload`](https://github.com/wormhole-foundation/wormhole-circle-integration/blob/f7df33b159a71b163b8b5c7e7381c0d8f193da99/evm/src/contracts/CircleIntegration/Logic.sol#L61-L108).

```solidity
// Confirm that the caller is the `mintRecipient` to ensure atomic execution.
require(
    msg.sender.toUniversalAddress() == deposit.mintRecipient, "caller must be mintRecipient"
);
```

Without any programmatic method for replacing expired VAAs with new VAAs signed by the updated Guardian set, the source USDC/EURC will be burnt, but it will not be possible for the expired VAAs to be executed, leading to denial-of-service on the `mintRecipient` receiving tokens on the target domain. The Wormhole CCTP integration does, however, inherit some mitigations already in place for this type of scenario where the Guardian set is updated, as explained in the [Wormhole whitepaper](https://github.com/wormhole-foundation/wormhole/blob/eee4641f55954d2d0db47831688a2e97eb20f7ee/whitepapers/0003_token_bridge.md#caveats), meaning that it is possible to repair or otherwise replace the expired VAA for execution using signatures from the new Guardian set. In all cases, the original VAA metadata remains intact since the new VAA Guardian signatures refer to an event that has already been emitted, so none of the contents of the VAA payload besides the Guardian set index and associated signatures change on re-observation. This means that the new VAA can be safely paired with the existing Circle attestation for execution on the target domain by the original `mintRecipient`.

**Impact:** There is only a single address that is permitted to execute a given VAA on the target domain; however, there are several scenarios that have been identified where this `mintReceipient` may be unable to perform redemption for a period in excess of 24 hours following an update to the Guardian set while the VAA is in-flight. Fortunately, Wormhole Governance has a well-defined path to resolution, so the impact is limited.

**Proof of Concept:**
1. Alice burns 100 USDC to be transferred to dApp X from CCTP Domain A to CCTP Domain B.
2. Wormhole executes a Governance VAA to update the Guardian set.
3. 24 hours pass, causing the previous Guardian set to expire.
4. dApp X attempts to redeem 100 USDC on CCTP Domain B, but VAA verification fails because the message was signed using the expired Guardian set.
5. The 100 USDC remains burnt and cannot be minted on the target domain by executing the attested CCTP message until the expired VAA is reobserved by members of the new Guardian set.

**Recommended Mitigation:** The practicality of executing the proposed Governance mitigations at scale should be carefully considered, given the extent to which USDC is entrenched within the wider DeFi ecosystem. There is a high likelihood of temporary widespread, high-impact DoS, although this is somewhat limited by the understanding that Guardian set updates are expected to occur relatively infrequently, given there have only been three updates in the lifetime of Wormhole so far. There is also potentially insufficient tooling for the detailed VAA re-observation scenarios, which should handle the recombination of the signed CCTP message with the new VAA and clearly communicate these considerations to integrators.

**Wormhole Foundation:** This is the same as how the Wormhole token bridge operates.

**Cyfrin:** Acknowledged.


### The `mintRecipient` address should be required to indicate interface support to prevent potential loss of funds

If the destination `mintRecipient` is a smart contract, it should be required to implement `IERC165` and another Wormhole/CCTP-specific interface to ensure that it has the necessary functionality to transfer/approve USDC/EURC tokens. Whilst it is ultimately the responsibility of the integrator to ensure that they correctly handle the receipt of tokens, this recommendation should help to avoid situations where the tokens become irreversibly stuck after calling `Logic::redeemTokenWithPayload`.

**Wormhole Foundation:** Responsibility lies with the integrator to ensure their code works with the `CircleIntegration` logic.

**Cyfrin:** Acknowledged.

\clearpage