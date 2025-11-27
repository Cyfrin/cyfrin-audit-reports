**Lead Auditors**

[Hans](https://twitter.com/hansfriese)

**Assisting Auditors**



---

# Findings
## Medium Risk


### Allow message value to be more than the quote cost

**Description:** The `SecuritizeBridge` contract's `bridgeDSTokens()` function requires users to provide an exact value that matches the quote obtained from `quoteBridge()`. This strict matching requirement creates issues because the actual cost can change between when a user checks the quote and when they submit their transaction.
```solidity
    function bridgeDSTokens(uint16 targetChain, uint256 value) public override payable whenNotPaused {
        uint256 cost = quoteBridge(targetChain);
        require(msg.value == cost, "Transaction value should be equal to quoteBridge response");
...
    }
```
The cost calculation depends on multiple factors as shown in Wormhole's `DeliveryProvider` contract [here](https://github.com/wormhole-foundation/wormhole/blob/abd0b330efa0a1bc86f0914396cbd570c99cdf1a/relayer/ethereum/contracts/relayer/deliveryProvider/DeliveryProvider.sol#L28), including gas prices on the target chain and asset conversion rates. These values can fluctuate frequently based on network conditions.

```solidity
    function quoteEvmDeliveryPrice(
        uint16 targetChain,
        Gas gasLimit,
        TargetNative receiverValue
    )
        public
        view
        returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerUnitGasUnused)
    {
        // Calculates the amount to refund user on the target chain, for each unit of target chain gas unused
        // by multiplying the price of that amount of gas (in target chain currency)
        // by a target-chain-specific constant 'denominator'/('denominator' + 'buffer'), which will be close to 1

        (uint16 buffer, uint16 denominator) = assetConversionBuffer(targetChain);
        targetChainRefundPerUnitGasUnused = GasPrice.wrap(gasPrice(targetChain).unwrap() * (denominator) / (uint256(denominator) + buffer));

        // Calculates the cost of performing a delivery with 'gasLimit' units of gas and 'receiverValue' wei delivered to the target contract

        LocalNative gasLimitCostInSourceCurrency = quoteGasCost(targetChain, gasLimit);
        LocalNative receiverValueCostInSourceCurrency = quoteAssetCost(targetChain, receiverValue);
        nativePriceQuote = quoteDeliveryOverhead(targetChain) + gasLimitCostInSourceCurrency + receiverValueCostInSourceCurrency;

        // Checks that the amount of wei that needs to be sent into the target chain is <= the 'maximum budget' for the target chain

        TargetNative gasLimitCost = gasLimit.toWei(gasPrice(targetChain)).asTargetNative();
        if(receiverValue.asNative() + gasLimitCost.asNative() > maximumBudget(targetChain).asNative()) {
            revert ExceedsMaximumBudget(targetChain, receiverValue.unwrap() + gasLimitCost.unwrap(), maximumBudget(targetChain).unwrap());
        }
    }
```
When the cost changes even slightly between the quote check and transaction submission, the transaction fails. This creates a poor user experience where transactions frequently revert despite users attempting to pay the correct amount.

A malicious actor could worsen this issue by manipulating network conditions to cause price fluctuations, effectively preventing other users from successfully bridging their assets.

**Impact:** Users face failed transactions when attempting to bridge assets causing frustration. In extreme cases, attackers could temporarily prevent specific users from bridging assets by manipulating conditions to cause price fluctuations.

**Recommended Mitigation:** Modify the function to accept value that exceed the current quote and automatically refund any excess amount back to the user. This approach provides flexibility to handle minor price fluctuations while ensuring users don't overpay.

**Securitize:** Fixed in commit [d3b97a](https://bitbucket.org/securitize_dev/bc-securitize-bridge-sc/commits/d3b97a76f93fd80ed6401372eadf206e1fb5d864) and [221759](https://bitbucket.org/securitize_dev/bc-securitize-bridge-sc/commits/2217591277f5a52913e0cd82136de13607608123).

**Cyfrin:** Verified.

\clearpage
## Low Risk


### Make the gas limit configurable

**Description:** The `SecuritizeBridge` contract currently uses a fixed (hardcoded) gas limit of 2,500,000 for all cross-chain message transactions through the Wormhole protocol. This value represents the maximum computational units (gas) allowed for the execution of the transaction on the target chain.

While this value works under current implementation, having it as a hardcoded constant makes it difficult to adjust if future upgrades or changes to the contract's functionality require different gas consumption. For example, if the contract's logic is upgraded and requires more computational steps, the current gas limit might become insufficient, requiring a full contract redeployment just to adjust this value.

**Recommended Mitigation:** Make the gas limit configurable by adding an owner-controlled function to update the value. This would allow the protocol administrators to adjust the gas limit if future contract upgrades require different gas consumption, without requiring a full contract redeployment.

Replace:
```solidity
uint256 public constant GAS_LIMIT = 2500_000;
```
with:
```solidity
uint256 public gasLimit;

function setGasLimit(uint256 _gasLimit) external onlyOwner {
    gasLimit = _gasLimit;
}
```

**Securitize:** Fixed in commit [525d86](https://bitbucket.org/securitize_dev/bc-securitize-bridge-sc/commits/525d8626ac53ab6ab38689e36d9d598c0626c90e).

**Cyfrin:** Verified.

\clearpage
## Informational


### Add a validation to check the message sender and the token value

**Description:** The `SecuritizeBridge` contract has a potential concern in its token bridging functionality.
While the contract is designed to work with compliance-verified investors, there's a gap in the validation process:

In the current Implementation:
- The contract checks if users have enough tokens to bridge (`balanceOf` check).
- It validates if tokens are not locked (`validateLockedTokens` check).
However, it doesn't explicitly verify if the sender is a valid investor.

As a result, when a user attempts to bridge 0 tokens, both validation checks will pass.
This means non-validated investors could successfully execute bridge transactions with 0 tokens.
While this doesn't result in any token transfer, it creates unnecessary cross-chain messages and potentially create noise in system monitoring and event logs

**Securitize:** Fixed in commit [6529fe](https://bitbucket.org/securitize_dev/bc-securitize-bridge-sc/commits/6529fe67789adab2266590f8581ef594e162aec5).

**Cyfrin:** Verified.


\clearpage