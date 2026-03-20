**Lead Auditors**

[qpzm](https://x.com/qpzmly)

[Fresco](https://x.com/fresco_io)

[Ironside](https://x.com/IronsideSec)
**Assisting Auditors**

[Dacian](https://x.com/DevDacian) (Gas Optimization) 

---

# Findings
## Low Risk


### No order expiration — stale orders become free options for takers

**Description:** [`Swapboard::createOrder`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L55) and [`Swapboard::createOrderWithEth`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L140) create orders with no expiration timestamp. Once created, an order remains fillable indefinitely until explicitly cancelled. This creates a free option problem.

- The `Order` struct has no `deadline` field
- [`Swapboard::fillOrder`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L102), [`Swapboard::fillOrderWithEth`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L170), and [`Swapboard::fillOrderUnwrap`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L212) enforce no time-based check
- The subgraph tracks `createdAt` but the contract enforces no deadline
- The frontend shows when an order was created but cannot warn about stale orders

Scenario:
1. Maker creates an order selling 1 WETH for 2,000 USDC when ETH is at $2,000
2. ETH price rises to $4,000 over the next month
3. The order is still active — any taker can buy 1 WETH for 2,000 USDC (50% below market)
4. The maker must actively monitor and cancel, but if they lose wallet access, go offline, or miss the price movement, the order is a sitting target

From the taker's perspective, every open order is a **free call option**: they can wait and only execute when the market moves in their favor, at no cost. In traditional OTC and DeFi limit-order systems (e.g., 0x, CoW Protocol, 1inch Limit Orders), orders include a `deadline` or `expiry` parameter to mitigate this.

**Impact:** Makers suffer economic loss from stale orders being filled at outdated prices. The risk scales with market volatility and the duration orders remain open.

**Proof of Concept:**
- Any active order can be filled at any time regardless of how old it is
- No on-chain mechanism to auto-expire orders
- Maker's only option is to manually cancel, which requires wallet access and gas

**Recommended Mitigation:** Add an optional `deadline` parameter to `createOrder` and `createOrderWithEth`:

```solidity
struct Order {
    address maker;
    address tokenA;
    uint256 amountA;
    address tokenB;
    uint256 amountB;
    uint256 deadline;   // 0 = no expiry
    bool active;
}
```

Then in [`Swapboard::fillOrder`] (and all fill variants):

```solidity
if (order.deadline != 0 && block.timestamp > order.deadline) revert OrderExpired(orderId);
```

This gives makers opt-in time-bounding while preserving backwards compatibility (deadline=0 means no expiry).

**Ethcf:**
Acknowledged; this is a design choice.


### No fill deadline parameter exposes takers to stale transaction execution

**Description:** [`Swapboard::fillOrder`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L102), [`Swapboard::fillOrderWithEth`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L170), and [`Swapboard::fillOrderUnwrap`](https://github.com/ETHCF/swapboard/blob/c43406f/contracts/src/Swapboard.sol#L212) accept no deadline parameter. In a congested network, a taker's fill transaction could sit in the mempool for extended periods and execute when conditions have changed (e.g., the token price has moved significantly).

This is distinct from M-01 (maker-side order expiry) — this is **taker-side** protection. Even if the order itself has no expiry, the taker should be able to specify "execute my fill only if it happens within N seconds."

This is standard practice in DeFi swap protocols. For example, [Uniswap V2 Router02](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/router-02) includes a `deadline` parameter on all swap functions:

```solidity
// Uniswap V2 Router02
function swapExactTokensForTokens(
    uint amountIn,
    uint amountOutMin,
    address[] calldata path,
    address to,
    uint deadline    // UNIX timestamp
) external returns (uint[] memory amounts);
```

The `deadline` prevents miners/block builders from holding a transaction and executing it later at a more favorable price. Uniswap V2, V3, and V4 all include it.

**Impact:** Takers may have their fill transactions execute at an outdated and unfavorable rate after sitting in the mempool during network congestion.

**Proof of Concept:**
- Taker submits `fillOrder(orderId)` during congestion
- Transaction sits in mempool for hours
- Token price moves significantly
- Transaction finally executes at the now-unfavorable rate
- Taker had no way to set a deadline to prevent this

**Recommended Mitigation:** Add a `deadline` parameter to fill functions:

```solidity
function fillOrder(uint256 orderId, uint256 deadline) external nonReentrant {
    if (deadline != 0 && block.timestamp > deadline) revert DeadlineExpired();
    // ...
}
```

**Ethcf:**

Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d). Added `uint256 deadline` parameter to `fillOrder, fillOrderWithEth, and fillOrderUnwrap`. When `deadline == 0`, no expiry is enforced. When `deadline != 0 && block.timestamp > deadline`, the call reverts with `DeadlineExpired`.

**Cyfrin:** Verified. Deadline check is correct — early revert before storage reads, `deadline == 0` allows takers to opt out of deadline enforcement.

\clearpage
## Informational


### Address-based token identity checks can be bypassed by alias tokens and native ERC20 mirrors


**Description:** The protocol treats token identity as address equality (`tokenA == tokenB` and `tokenB == weth`). This assumption breaks when one economic asset has [multiple valid addresses (proxy aliases/wrapper aliases)](https://github.com/d-xo/weird-erc20?tab=readme-ov-file#multiple-token-addresses) or when [a chain exposes the native gas token as an ERC20](https://github.com/d-xo/weird-erc20?tab=readme-ov-file#erc-20-representation-of-native-currency).

**Impact:** Informational. Enabling orders that are "same asset, different address".

**Proof of Concept:** In `createOrder`, only `if (tokenA == tokenB) revert SameToken();` is enforced. In `createOrderWithEth`, only `if (tokenB == weth) revert SameToken();` is enforced. Both checks are address-only, so alias contracts for the same underlying asset can bypass these guards.

```solidity
audit-2026-02-ethcf-swapboard/contracts/src/Swapboard.sol
57:     function createOrder(
58:         address tokenA,
59:         uint256 amountA,
60:         address tokenB,
61:         uint256 amountB
62:     ) external nonReentrant returns (uint256 orderId) {
63:         if (tokenA == address(0)) revert ZeroAddress();
64:         if (tokenB == address(0)) revert ZeroAddress();
65:         if (amountA == 0) revert ZeroAmount();
66:         if (amountB == 0) revert ZeroAmount();
67:  >>>    if (tokenA == tokenB) revert SameToken();
68:         if (tokenA.code.length == 0) revert NotAContract(tokenA);
69:         if (tokenB.code.length == 0) revert NotAContract(tokenB);

--------- skipped -------

99:         emit OrderCreated(orderId, msg.sender, tokenA, amountA, tokenB, amountB);
100:     }


150:     function createOrderWithEth(
151:         address tokenB,
152:         uint256 amountB
153:     ) external payable nonReentrant returns (uint256 orderId) {
154:         if (msg.value == 0) revert ZeroETH();
155:         if (tokenB == address(0)) revert ZeroAddress();
156:         if (amountB == 0) revert ZeroAmount();
157:  >>>    if (tokenB == weth) revert SameToken();
158:         if (tokenB.code.length == 0) revert NotAContract(tokenB);

----- skipped -----

176:         emit OrderCreated(orderId, msg.sender, weth, msg.value, tokenB, amountB);
177:     }

```

**Recommended Mitigation:** No mitigation needed becasue of no impact. Just documentation / info.



**ETHCF:** Acknowledged; by design.






### Use named mappings parameters to explicitly indicate the purpose of keys and values

**Description:** Use named mappings parameters to explicitly indicate the purpose of keys and values:
```solidity
Swapboard.sol
39:    mapping(uint256 => Order) public orders;
```

**ETHCF:** Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d).

**Cyfrin:** Verified.


### Use read-then-increment in `Swapboard::createOrder, createOrderWithEth`

**Description:** Use read-then-increment in `Swapboard::createOrder, createOrderWithEth`:
```diff
-       orderId = nextOrderId;
-       unchecked {
-           ++nextOrderId;
-       }
+       unchecked { orderId = nextOrderId++; }
```

**ETHCF:** Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### Use `ReentrancyGuardTransient` instead of `ReentrancyGuard` for faster `nonReentrant` modifiers

**Description:** Use [ReentrancyGuardTransient](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuardTransient.sol) instead of `ReentrancyGuard` for faster `nonReentrant` modifiers:
```solidity
Swapboard.sol
4:import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
19:///      - Reentrancy protected via OpenZeppelin ReentrancyGuard
27:contract Swapboard is ISwapboard, ReentrancyGuard {
```

**ETHCF:** Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d).

**Cyfrin:** Verified.


### Don't initialize `received` to default value in `Swapboard::createOrder`

**Description:** Don't initialize `received` to default value in `Swapboard::createOrder`:
```diff
-       uint256 received;
        unchecked {
-           received = balanceAfter - balanceBefore;
+           uint256 received = balanceAfter - balanceBefore;
-       }
        if (received != amountA) {
            revert BalanceMismatch(amountA, received);
        }
+       }
```

**ETHCF:** Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d).

**Cyfrin:** Verified.


### Cache storage to prevent identical storage reads

**Description:** In EVM reading from storage is expensive; cache storage to prevent identical storage reads when known values can't change:
* `fillOrder, cancelOrder` - cache `order.maker`
* `fillOrderWithEth` - cache `order.maker, order.amountB`
* `cancelOrderUnwrap, fillOrderUnwrap` - cache `order.maker, order.amountA`

**ETHCF:** Fixed in commits [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d), [3a9e06e](https://github.com/ETHCF/swapboard/commit/3a9e06eb2493b0c501b484c05e3d1033d7e56ba2).

**Cyfrin:** Verified.


### When sending ETH, use `SafeTransferLib::safeTransferETH` instead Of Solidity `call`

**Description:** When sending ETH, use [SafeTransferLib::safeTransferETH](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L95-L103) instead Of Solidity `call` which is more [gas efficient](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#10-use-safetransferlibsafetransfereth-instead-of-solidity-call-effective-035-cheaper):
```solidity
Swapboard.sol
205:        (bool success,) = payable(order.maker).call{value: order.amountA}("");
227:        (bool success,) = payable(msg.sender).call{value: order.amountA}("");
```

Another alternative "stand-alone" pattern which is also more efficient and prevents "return-bomb" style attacks is for example in `cancelOrderUnwrap`:
```solidity
-       (bool success,) = payable(maker).call{value: amountA}("");
+       bool success;
+       assembly {
+           success := call(gas(), maker, amountA, 0, 0, 0, 0)
+       }
        if (!success) revert ETHTransferFailed(maker);
```

**ETHCF:** Fixed in commit [3a9e06e](https://github.com/ETHCF/swapboard/commit/3a9e06eb2493b0c501b484c05e3d1033d7e56ba2) using the alternative "stand-alone" pattern.

**Cyfrin:** Verified.


### Don't cache `calldata` array length in `Swapboard::getOrders`

**Description:** It is more [gas-efficient](https://github.com/devdacian/solidity-gas-optimization?tab=readme-ov-file#6-dont-cache-calldata-length-effective-009-cheaper) to not cache `calldata` array length in `Swapboard::getOrders`.

**ETHCF:** Fixed in commit [572f3c5](https://github.com/ETHCF/swapboard/commit/572f3c5d724b78fc3a2f304557a23c018f9fc31d).

**Cyfrin:** Verified.


### Better storage packing in `struct Order` reduces gas cost of all `create, fill, cancel` operations

**Description:** Since `Order::maker, active` are frequently written and read together,  in struct `Order` it is more efficient to pack them into the same slot:
```diff
    struct Order {
        address maker;
+       bool active;
        address tokenA;
        uint256 amountA;
        address tokenB;
        uint256 amountB;
-       bool active;
    }
```

Then in `Swapboard::fillOrder, cancelOrder, fillOrderWithEth, cancelOrderUnwrap, fillOrderUnwrap` use this format to read them both in one SLOAD:
```diff
-       address maker = order.maker;
+       (address maker, bool active) = (order.maker, order.active);
        if (maker == address(0)) revert OrderNotFound(orderId);
-       if (!order.active) revert OrderNotActive(orderId);
+       if (!active) revert OrderNotActive(orderId);
```

This also reduces the gas costs of creating orders since it removes one storage write with no required code changes to those functions.

**ETHCF:** Fixed in commit [82f9b49](https://github.com/ETHCF/swapboard/commit/82f9b4902ae53e439a5b34c08e651abdd9bd5ca8).

**Cyfrin:** Verified.

\clearpage