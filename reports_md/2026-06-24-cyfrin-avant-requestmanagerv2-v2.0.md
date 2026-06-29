**Lead Auditors**

[Dacian](https://x.com/DevDacian)

[JuliusRaynaldi](https://x.com/JuliusRaynaldi) (Formal Verification)

**Assisting Auditors**



---

# Findings
## Low Risk


### Missing input validation in admin setters across `PriceStorage, RequestsManagerV2`

**Description:** Several admin-only setters validate only a trivial degenerate input and accept other values that are syntactically valid but break pricing or settlement. Each is independently low-severity (admin recovers by re-calling the setter), but they share one root cause: the accepted input domain is wider than the safe domain.

1. **`PriceStorage::setLowerBoundPercentage, setUpperBoundPercentage`** accept any value in `(0, 1e18]`, with neither a sane floor nor a sane cap.

   Both setters reject only `0` and values strictly greater than `BOUND_PERCENTAGE_DENOMINATOR` (1e18) (`src/PriceStorage.sol:56-72`). The per-update bounds in `setPrice` are computed as `lastPriceValue +/- lastPriceValue * percentage / 1e18` (`src/PriceStorage.sol:38-44`). At the high end, a bound at or near `1e18` drives the lower bound to `0`, so a single `setPrice` can crash the price to 1 wei and the next `completeMint` mints a vastly inflated amount.

   At the low end, a percentage small enough that the band `lastPriceValue * percentage / 1e18` rounds down to zero (or, at the canonical `1e18` price scale, to a ~1-wei width that rejects every realistic update) collapses the band to `upperBound == lowerBound == lastPriceValue`; every genuine price change then reverts `InvalidPriceRange`.

   Because the per-update band check is computed from `lastPrice` and applies to every key, even a fresh key cannot publish a value outside the band (write-once-per-key at `src/PriceStorage.sol:34` only blocks overwriting an existing key), so the oracle is frozen until the admin widens the bound.

2. **`RequestsManagerV2::setTreasury`** and the constructor accept the self-address `address(this)`.

   Both validate only that the treasury is non-zero (`src/RequestsManagerV2.sol:139-143`, constructor at `src/RequestsManagerV2.sol:113`); neither rejects `address(this)`.

   With `treasuryAddress == address(this)`, the `completeMint` deposit forward becomes a self-transfer no-op that commingles deposits with escrow (`src/RequestsManagerV2.sol:298`), and `completeBurn` requires a self-allowance that is normally absent, so every burn settlement reverts on `safeTransferFrom` (`src/RequestsManagerV2.sol:425`) until the treasury is re-pointed.

**Recommended Mitigation:**
- `PriceStorage::setLowerBoundPercentage, setUpperBoundPercentage`: bound each percentage within a sane closed band rather than `(0, 1e18]` - enforce both a floor large enough that the per-update band cannot round down to a sub-update width at the protocol's price scale, and a cap materially below `1e18` (e.g. `0.5e18`) consistent with the intended 5% / 33% regime. `initialize` routes through these setters, so the fix covers initialization.

- `RequestsManagerV2::setTreasury` and constructor: reject `address(this)` in addition to the existing non-zero check (e.g. revert when `_treasuryAddress == address(this)`).

**Avant:** Acknowledged; `PriceStorage` is pre-exisiting and deployed immutably but we will note this for future deployments. `RequestsManagerV2::setTreasury` we accept as a deployment-time admin responsibility.

\clearpage
## Informational


### `RequestsManagerV2::cancelBurn` reverts during a pause longer than `burnCancelWindow`, breaking the documented pause-cancellation invariant

**Description:** The `pause` NatSpec states that _"cancellation paths stay enabled so pending requests can always be unwound while paused"_ (src/RequestsManagerV2.sol:155-156). This holds for `cancelMint`, which has no window or TTL gate and is always callable while CREATED. It does not hold for `cancelBurn`: that function reverts `BurnCancelWindowClosed` once `block.timestamp > createdAt + burnCancelWindow` (src/RequestsManagerV2.sol:362-369). The cancel window is measured against wall-clock `block.timestamp` and keeps elapsing during a pause - the pause does not freeze time. Because `completeBurn` carries `whenNotPaused`, it is unavailable during the pause as well.

If the contract is paused continuously for longer than a pending burn's remaining cancel window (deployed `burnCancelWindow` is 2 days), the provider can neither complete (the contract is paused) nor cancel (the window has closed). The documented _"always be unwound while paused"_ guarantee is false for the burn path: the provider's only self-service exit is gone precisely while the protocol is paused, which is when a user most wants out. The escrowed issue tokens are recoverable only through the admin-gated `adminCancelBurn`, which has no window or pause gate.

**Recommended Mitigation:** Update the NatSpec above `RequestsManagerV2::pause` to correct the false claim that "pending requests can always be unwound while paused" - this is only true for mints but not burns.

**Avant:** Fixed in commit [f7d9275](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/f7d92759a71701a3a941991d57bfdf29c836c040).

**Cyfrin:** Verified.



### `SimpleToken::idempotentMint, idempotentBurn` write the idempotency flag after the body executes instead of before

**Description:** The keyed `SimpleToken::mint` and `SimpleToken::burn` overloads guard against idempotency-key reuse with the `idempotentMint` and `idempotentBurn` modifiers (src/SimpleToken.sol:20-34). Both modifiers run the function body at `_;` and only afterwards record the key as used:

```solidity
modifier idempotentMint(bytes32 _idempotencyKey) {
    if (mintIds[_idempotencyKey]) {
        revert IdempotencyKeyAlreadyExist(_idempotencyKey);
    }
    _;                                  // body runs first
    mintIds[_idempotencyKey] = true;    // effect applied afterwards
}
```

This inverts the checks-effects-interactions ordering: the effect (recording the key in `mintIds` / `burnIds`) is applied after the interaction in the body (the `_mint` / `_burn` call) rather than before it. The canonical idempotency guard records the key as consumed before executing the body, so that any re-entrant call observes the key as already used and reverts.

With the current code the ordering is harmless. Each keyed overload's body is a single `_mint` / `_burn` call, and in OpenZeppelin Contracts Upgradeable v5.3.0 those route through `ERC20Upgradeable._update` (out of scope, traced for context), which only mutates balances and emits `Transfer`. It makes no external call and invokes no token-transfer or receiver hook - the `_beforeTokenTransfer` / `_afterTokenTransfer` hooks present in OZ v4 were removed in v5. `SimpleToken` does not override `_update`. Control therefore never leaves the contract between the key check and the key write, so a single key cannot be consumed twice within one transaction and no double-mint or double-burn is reachable today.

Here there is no current impact however this is also not good practice; writing the effect before the body removes the hazard unconditionally and costs nothing.

**Recommended Mitigation:** Apply the effect before running the body so the guard holds regardless of what the body later does:

```solidity
modifier idempotentMint(bytes32 _idempotencyKey) {
    if (mintIds[_idempotencyKey]) {
        revert IdempotencyKeyAlreadyExist(_idempotencyKey);
    }
    mintIds[_idempotencyKey] = true;
    _;
}
```

Apply the same reordering to `idempotentBurn`.

**Avant:** Fixed in commit [ff7803c](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/ff7803c1c3ee4c41936a56f4afcd104780563fb5).

**Cyfrin:** Verified.


### `README.md` documentation mismatches: stale and inaccurate references disagree with the code and docs

**Description:** `README.md` contains several statements that disagree with the in-scope contract source and the supplied project docs (`AUDIT_NOTES.md`, `RFP-RequestsManagerV2-external-audit.md`). The inaccuracies mis-state burn pricing, fees, the request-counter offset, the price bounds, and admin powers in ways a reader or integrator would act on.

1. **`README.md:82, 88`** - burn settlement is described as using only the stored request-time price.

   The README states `completeBurn` _"uses this stored price, making the withdrawal amount immune to post-request price changes"_ (`README.md:82`) and that burn prices _"are locked at request time and cannot change"_ (`README.md:88`). The code settles at `min(lockedPrice, currentPrice)` (`src/RequestsManagerV2.sol:406-409`): the stored price is a ceiling only, so a price fall after the request lowers the payout. `AUDIT_NOTES.md:71` and `RFP-RequestsManagerV2-external-audit.md:83` both state the redeemer bears a NAV fall.

   **Recommended:** state that burns settle at `min(lockedPrice, currentPrice)` - the request-time price is a ceiling, not a fixed settlement price, and a price decrease is borne by the redeemer.

2. **`README.md:145`** - the burn formula omits the `min(lockedPrice, currentPrice)`.

   The formula table gives `withdrawalAmount = (burnAmount * price / PRECISION) * (PRECISION - burnFee) / PRECISION` with a generic `price`. The code uses `price = min(lockedPrice, currentPrice)` and the locked `request.fee`, not the live `burnFee` (`src/RequestsManagerV2.sol:409, 412-413`).

   **Recommended:** replace `price` with `min(lockedPrice, currentPrice)` and note the fee is the value locked at request time.

3. **`README.md:125`** - `setBurnFee` is described as retroactive on pending burns.

   The trust model lists _"Change fees retroactively on pending burns (`setBurnFee`)"_. The code locks the burn fee into the `BurnRequest` at request time (`src/RequestsManagerV2.sol:322, 331`) and `completeBurn` consumes `request.fee` (`src/RequestsManagerV2.sol:403`); the `setBurnFee` NatSpec states it applies _"for new requests; pending burns keep the fee locked at request time"_ (`src/RequestsManagerV2.sol:196-197`). The RFP records the retroactive-burn-fee issue as fixed (`RFP-RequestsManagerV2-external-audit.md:273`). The live fee is the mint fee, not the burn fee.

   **Recommended:** remove the retroactive-burn-fee claim; the only live fee is `setMintFee`, applied at completion.

4. **`README.md:118`** - the V2 request-counter start value is wrong.

   The README says counters start at 10,000 and that V1 has _"fewer than 10,000 existing orders"_. The code initializes both counters to `INITIAL_COUNTER = 100_000` (`src/RequestsManagerV2.sol:47, 127-128`); `RFP-RequestsManagerV2-external-audit.md:121` and `AUDIT_NOTES.md:83` both state 100,000.

   **Recommended:** correct the value to 100,000 and update the dependent order-count statement.

5. **`README.md:133, 180`** - the price bounds are presented as fixed guarantees.

   The README implies the bounds are enforced at the +5% upper / -33% lower figures (_"each update is constrained to"_ those values). They are settable parameters: `PriceStorage::setUpperBoundPercentage, setLowerBoundPercentage` accept any value in `(0, 1e18]` (`src/PriceStorage.sol:56-72`), and the RFP notes the figures derive from test configuration with production values TBD (`RFP-RequestsManagerV2-external-audit.md:145`).

   **Recommended:** describe the bounds as configurable parameters rather than presenting the test-config values as enforced guarantees.

6. **`README.md:170`** - the role-permissions table omits two admin setters.

   The table lists `setBurnRequestTTL` but not `setMintRequestTTL` (`src/RequestsManagerV2.sol:174`) or `setBurnCancelWindow` (`src/RequestsManagerV2.sol:183`), both `DEFAULT_ADMIN_ROLE` setters present in the code.

   **Recommended:** add `setMintRequestTTL` and `setBurnCancelWindow` to the `DEFAULT_ADMIN_ROLE` row.

7. **`README.md:92-104`** - the "New features" section omits the mint TTL and the burn cancel window.

   The section documents the burn TTL but not `mintRequestTTL` (enforced in `completeMint`, `src/RequestsManagerV2.sol:278`) or `burnCancelWindow` (enforced in `cancelBurn`, `src/RequestsManagerV2.sol:367`), both new V2 mechanisms.

   **Recommended:** document `mintRequestTTL` and `burnCancelWindow` alongside the existing burn TTL entry.

**Avant:** Fixed in commit [a97fcaf](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/a97fcaf42cb5511690a20864c778e79cc07fa397).

**Cyfrin:** Verified.

\clearpage
## Gas Optimization


### `RequestsManagerV2` cache storage slots to prevent identical storage reads

**Description:** Several functions in `RequestsManagerV2` read the same storage slot more than once within a single call even though the value does not change between reads. With the optimizer enabled but `via_ir` off, it does not dedupe same-slot reads across statement boundaries or around an intervening external call (a `safeTransfer`, `mint`, or `burn` forces a re-read because storage could have changed during the call), so each becomes a separate warm SLOAD (~100 gas). Caching each value into a local once and reusing it removes the redundant read:

1. **`RequestsManagerV2::completeMint`** - reads `mintFee` twice, in the fee calculation at src/RequestsManagerV2.sol:291 and the `MintRequestCompleted` emit at src/RequestsManagerV2.sol:304, with two external calls in between. Cache `uint64 fee = mintFee;`, mirroring `completeBurn` which already caches its per-request `fee`.

2. **`RequestsManagerV2::adminCancelMint`** - reads `request.provider` twice, at the `safeTransfer` (src/RequestsManagerV2.sol:267) and the emit (src/RequestsManagerV2.sol:269); the external transfer between them forces the second SLOAD. Cache `address provider = request.provider;` before the transfer.

3. **`RequestsManagerV2::adminCancelBurn`** - reads `request.provider` twice, at the `safeTransfer` (src/RequestsManagerV2.sol:384) and the emit (src/RequestsManagerV2.sol:386). Cache before the transfer.

4. **`RequestsManagerV2::requestMint`** - reads `mintRequestsCounter` at src/RequestsManagerV2.sol:216 then re-reads it via `mintRequestsCounter++` at src/RequestsManagerV2.sol:226. The pre-increment value is already held in the local `id`.

5. **`RequestsManagerV2::requestBurn`** - reads `burnRequestsCounter` at src/RequestsManagerV2.sol:325 then re-reads it via `burnRequestsCounter++` at src/RequestsManagerV2.sol:337. Same as above.

**Recommended Mitigation:** Cache each repeated read into a local before its first use and reuse the local. For the request counters, assign the incremented value directly instead of re-reading the slot:

```solidity
unchecked {
    mintRequestsCounter = id + 1;
}
```

For the provider re-reads, load the value before the external transfer so the post-call SLOAD is avoided:

```solidity
address provider = request.provider;
request.state = State.CANCELLED;
IERC20(request.token).safeTransfer(provider, request.amount);
emit MintRequestAdminCancelled(_id, provider, msg.sender);
```

**Avant:** Fixed in commit [96e36b5](https://github.com/Avant-Protocol/Avant-Contracts-Max/commit/96e36b548c88ed68594d0cf7f1b99cd4528dffc7).

**Cyfrin:** Verified.

\clearpage