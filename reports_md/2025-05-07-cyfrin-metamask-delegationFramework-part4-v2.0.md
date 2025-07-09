**Lead Auditors**

[0kage](https://twitter.com/0kage_eth)

**Assisting Auditors**



---

# Findings
## Informational


### Execution mode restriction in `LogicalOrWrapperEnforcer` can be removed

**Description:** The `LogicalOrWrapperEnforcer` contract currently includes the `onlyDefaultExecutionMode` modifier on all of its hook functions. This creates an unnecessary restriction since the individual enforcers being wrapped already apply their own execution mode restrictions. This design decision could limit the wrapper's flexibility and prevent it from working with caveats that might support non-default execution modes.


**Recommended Mitigation:** Consider removing the `onlyDefaultExecutionMode` modifier from all hook functions in the `LogicalOrWrapperEnforcer` and let the individual wrapped caveat enforcers handle their own execution mode restrictions.

Not only is this gas efficient, this change would also allow the `LogicalOrWrapperEnforcer` to be more flexible and forward-compatible with future caveats, while still maintaining the appropriate execution mode restrictions through the wrapped enforcer contracts themselves.

**Metamask:** Fixed in commit [d38d53d](https://github.com/MetaMask/delegation-framework/commit/d38d53dc467cc3b4faa7047cfca1844ea9cbc3be).

**Cyfrin:** Resolved.


### Delegate controlled privilege escalation risk in `LogicalOrWrapperEnforcer`

**Description:** When using the `LogicalOrWrapperEnforcer` enforcer, delegators may define multiple caveat groups with different security properties, expecting that all groups provide adequate security boundaries.

However, since delegates control which group is evaluated during execution, they can select the least restrictive group to bypass stricter security requirements defined in other groups.

For example, if a delegator defines two groups:

- Group 0: Requires minimum balance change of 100 tokens
- Group 1: Requires minimum balance change of 50 tokens

A delegate can choose Group 1 at execution time, allowing them to transfer only 50 tokens when the delegator may have expected the 100 token minimum to apply.

While this behavior is by design, it creates a scenario where delegates can bypass intended security restrictions by selecting the least restrictive caveat group. Since this enforcer's behavior gives such control to the delegate, it effectively allows them to elevate their privileges to the least restrictive option available across all defined groups.

**Recommended Mitigation:** Consider adding a security notice similar to the one added in all balance change enforcers.

```solidity
/**
 * @dev Security Notice: This enforcer allows delegates to choose which caveat group to use at execution time
 * via the groupIndex parameter. If multiple caveat groups are defined with varying levels of restrictions,
 * delegates can select the least restrictive group, bypassing stricter requirements in other groups.
 *
 * To maintain proper security:
 * 1. Ensure each caveat group represents a complete and equally secure permission set
 * 2. Never assume delegates will select the most restrictive group
 * 3. Design caveat groups with the understanding that delegates will choose the path of least resistance
 *
 * Use this enforcer at your own risk and ensure it aligns with your intended security model.
 */
```


**Metamask:** Fixed in commit [d38d53d](https://github.com/MetaMask/delegation-framework/commit/d38d53dc467cc3b4faa7047cfca1844ea9cbc3be).

**Cyfrin:** Resolved.


\clearpage