**Lead Auditors**

[Farouk](https://x.com/Ubermensh3dot0)

[qpzm](https://x.com/qpzmly)

**Assisting Auditors**



---

# Findings
## Low Risk


### `factor_roots` masks remainder — silent wrong result on violated precondition


**Description:** In [`polynomial_arithmetic.hpp:56`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.hpp#L56), `factor_roots` performs synthetic division assuming $(X - r) \mid p(X)$. After the division loop, it unconditionally zeroes the final coefficient:

```cpp
polynomial[size - 1] = Fr::zero();  // unconditionally zeroes the leading coefficient slot
```
https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.hpp#L107

The division loop (lines 99-105) computes quotient coefficients $b_0, \ldots, b_{n-2}$ in-place, storing the last value in `temp`. It never touches `polynomial[size-1]`, which still holds the original $a_{n-1}$. For exact division, $a_{n-1} = b_{n-2}$ (i.e., `polynomial[size-1] == temp`). When the precondition is violated, these differ — but line 107 unconditionally zeroes the slot without checking, silently producing a wrong quotient with no indication of error.

**Impact:** Low. Called 7 times in proof-critical path (all prover-side). All callers correctly satisfy the precondition — KZG subtracts the evaluation before quotienting, Shplonk/Gemini evaluations are computed from the polynomial itself, and Merge prover evaluations are derived directly. A failure requires a future trusted-caller bug (not external input), and the result would be verifier rejection, not a soundness break. The assert costs 1 field comparison and would make such a bug fail loudly instead of silently.

**All 7 call sites (prover only):**

1. [`kzg/kzg.hpp:56`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/kzg/kzg.hpp#L56) — KZG Prover
   - Root: `pair.challenge`
   - Precondition: `quotient.at(0) -= pair.evaluation`
2. [`shplonk/shplonk.hpp:77`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/shplonk/shplonk.hpp#L77) — Shplonk Prover
   - Root: `-claim.opening_pair.challenge`
   - Precondition: `tmp.at(0) -= gemini_fold_pos_evaluations[fold_idx]`
3. [`shplonk/shplonk.hpp:86`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/shplonk/shplonk.hpp#L86) — Shplonk Prover
   - Root: `claim.opening_pair.challenge`
   - Precondition: `tmp.at(0) -= claim.opening_pair.evaluation`
4. [`shplonk/shplonk.hpp:102`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/shplonk/shplonk.hpp#L102) — Shplonk Prover (Libra)
   - Root: `claim.opening_pair.challenge`
   - Precondition: `tmp.at(0) -= claim.opening_pair.evaluation`
5. [`shplonk/shplonk.hpp:114`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/shplonk/shplonk.hpp#L114) — Shplonk Prover (Sumcheck)
   - Root: `claim.opening_pair.challenge`
   - Precondition: `tmp.at(0) -= claim.opening_pair.evaluation`
6. [`goblin/merge_prover.cpp:84`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/goblin/merge_prover.cpp#L84) — Merge Prover
   - Root: `kappa`
   - Precondition: `shplonk_batched_quotient.at(0) -= challenge * eval` (in loop)
7. [`goblin/merge_prover.cpp:91`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/goblin/merge_prover.cpp#L91) — Merge Prover
   - Root: `kappa_inv`
   - Precondition: `reversed_batched_left_tables_copy.at(0) -= evals.back()`


**Proof of Concept:** [`AuditPoC_P17_FactorRootsMasksRemainder`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L375) — saves the original $a_{n-1}$ before calling `factor_roots`, then compares it with $b_{n-2}$ (`poly[n-2]` after the call). For exact division these match; for violated preconditions they differ, which is exactly what our proposed assert catches.

```cpp
TYPED_TEST(PolynomialTests, AuditPoC_P17_FactorRootsMasksRemainder)
{
    using FF = TypeParam;

    constexpr size_t n = 3;

    // Case 1: Exact division — p(X) = X^2 - 1 = (X-1)(X+1), root = 1
    {
        std::array<FF, n> poly = { -FF(1), FF(0), FF(1) }; // [-1, 0, 1]
        FF original_leading = poly[n - 1];                  // a_{n-1} = 1

        polynomial_arithmetic::factor_roots(std::span<FF>(poly), FF(1));

        // After division: poly[n-2] = b_{n-2} (last quotient coeff)
        // For exact division: a_{n-1} == b_{n-2}
        FF b_last = poly[n - 2];
        EXPECT_EQ(original_leading, b_last);
    }

    // Case 2: Non-exact division — p(X) = X^2 + 1, root = 1, p(1) = 2 ≠ 0
    {
        std::array<FF, n> poly = { FF(1), FF(0), FF(1) }; // [1, 0, 1]
        FF original_leading = poly[n - 1];                 // a_{n-1} = 1

        FF eval_at_root = polynomial_arithmetic::evaluate(poly.data(), FF(1), n);
        EXPECT_NE(eval_at_root, FF(0));

        polynomial_arithmetic::factor_roots(std::span<FF>(poly), FF(1));

        // After division: a_{n-1} ≠ b_{n-2} — proposed assert catches this
        FF b_last = poly[n - 2];
        EXPECT_NE(original_leading, b_last);
    }
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P17*"
```

```
P-17 Case 1 (exact): a_{n-1}=..01, b_{n-2}=..01       → proposed assert PASSES
P-17 Case 2 (non-exact): a_{n-1}=..01, b_{n-2}=..p-1   → proposed assert CATCHES non-divisibility
```

**Recommended Mitigation:** Replace [`polynomial_arithmetic.hpp:107`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.hpp#L107):

```diff
- polynomial[size - 1] = Fr::zero();
+ BB_ASSERT(polynomial[size - 1] == temp);  // verify a_{n-1} == b_{n-2} (exact divisibility)
+ polynomial[size - 1] = Fr::zero();
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified.


### `compute_efficient_interpolation` silently produces wrong output on duplicate evaluation points


**Description:** In [`polynomial_arithmetic.cpp:249`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L249), `compute_efficient_interpolation` performs Lagrange interpolation from evaluation points and values. When two evaluation points are equal, the Lagrange denominator

$$d_i = \prod_{j \neq i} (x_i - x_j)$$

becomes 0 for the duplicated indices. [`batch_invert`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L305) skips zero entries, leaving $d_i^{-1} = 0$. The contributions from the duplicated points are silently zeroed out, producing an incorrect interpolation with no error or assertion.

```cpp
// Line 296-301: compute denominators
for (size_t j = 0; j < n; ++j) {
    if (j == i) continue;
    roots_and_denominators[n + i] *= (evaluation_points[i] - evaluation_points[j]);
    // If evaluation_points[i] == evaluation_points[j], this multiplies by 0
    // → d_i = 0 → batch_invert skips → contribution silently zeroed
}

// Line 305: batch invert all denominators (zeros are skipped)
Fr::batch_invert(roots_and_denominators.data(), 2 * n);
```

[`batch_invert`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/ecc/fields/field_impl.hpp#L418) skips zeros by design — when an element is zero, it is excluded from the running product and its result slot is left as 0:

```cpp
// field_impl.hpp:430
if (coeffs[i].is_zero()) {
    skipped[i] = true;     // zero excluded from accumulator
}
```

Other callers (e.g., [barycentric evaluation](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/barycentric.hpp#L151)) legitimately rely on this skip-zero behavior. The fix belongs in `compute_efficient_interpolation` — add a distinct-points assertion before calling `batch_invert`.

**Impact:** Low. Duplicate points make Lagrange interpolation mathematically undefined — this is a precondition violation, not a protocol flaw. All production callers use fixed subgroup domains (`{1, g, ..., g^(n-1)}`), which are distinct by construction. There is no current path for an external actor to supply duplicate points. The assert is a defensive check against future misuse.

**Proof of Concept:** Added [`AuditPoC_P07_InterpolationDuplicatePoints`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L420) to `polynomial_arithmetic.test.cpp`:

```cpp
TYPED_TEST(PolynomialTests, AuditPoC_P07_InterpolationDuplicatePoints)
{
    using FF = TypeParam;

    // Create a known polynomial: f(x) = 3x^2 + 2x + 1
    constexpr size_t n = 3;
    std::array<FF, n> poly = { FF(1), FF(2), FF(3) };

    // Case 1: Distinct points — should interpolate correctly
    {
        std::array<FF, n> x = { FF(1), FF(2), FF(3) };
        std::array<FF, n> src;
        for (size_t i = 0; i < n; i++) {
            src[i] = polynomial_arithmetic::evaluate(poly.data(), x[i], n);
        }
        std::array<FF, n> dest;
        std::copy(src.begin(), src.end(), dest.begin());

        polynomial_arithmetic::compute_efficient_interpolation(dest.data(), dest.data(), x.data(), n);

        bool correct = true;
        for (size_t i = 0; i < n; i++) {
            if (dest[i] != poly[i]) {
                correct = false;
                break;
            }
        }
        std::cout << "P-07 Case 1 (distinct points): interpolation correct = " << correct << std::endl;
        EXPECT_TRUE(correct);
    }

    // Case 2: Duplicate points — should fail but silently produces wrong result
    {
        std::array<FF, n> x = { FF(1), FF(2), FF(2) };  // duplicate!
        std::array<FF, n> src;
        for (size_t i = 0; i < n; i++) {
            src[i] = polynomial_arithmetic::evaluate(poly.data(), x[i], n);
        }
        std::array<FF, n> dest;
        std::copy(src.begin(), src.end(), dest.begin());

        // This should ideally throw or assert, but it silently produces wrong output
        polynomial_arithmetic::compute_efficient_interpolation(dest.data(), dest.data(), x.data(), n);

        bool correct = true;
        for (size_t i = 0; i < n; i++) {
            if (dest[i] != poly[i]) {
                correct = false;
                break;
            }
        }
        std::cout << "P-07 Case 2 (duplicate points): interpolation correct = " << correct << std::endl;
        if (!correct) {
            std::cout << "P-07 CONFIRMED: duplicate points produce wrong interpolation with no error" << std::endl;
        }
        // We expect this to be WRONG — the interpolation is ill-defined for duplicate points
        // The test documents the silent failure behavior
    }
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P07*"
```

**Recommended Mitigation:** Add a distinct-points assertion at the start of `compute_efficient_interpolation`.
```cpp
for (size_t i = 0; i < n; ++i)
    for (size_t j = i + 1; j < n; ++j)
        BB_ASSERT(evaluation_points[i] != evaluation_points[j]);
```

O(n²) but not in the hot path — the only production caller is the [`Polynomial` interpolation constructor](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.cpp#L123), called once during polynomial construction

**Aztec:**
Fixed in [12f6f61](https://github.com/AztecProtocol/aztec-packages/commit/12f6f61e4ff50bef70b293febec306ae4725f4a0).

**Cyfrin:** Verified.


### `evaluate_mle` crashes (SIGSEGV) on single-coefficient polynomial

**Description:** In [`polynomial.hpp:399`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.hpp#L399), `_evaluate_mle` unconditionally accesses `evaluation_points[0]` without checking if the span is empty:

```cpp
Fr_ _evaluate_mle(std::span<const Fr_> evaluation_points,
                  const SharedShiftedVirtualZeroesArray<Fr_>& coefficients,
                  bool shift)
{
    if (coefficients.size() == 0) {
        return Fr_(0);
    }
    const size_t n = evaluation_points.size();                        // n = 0
    const size_t dim = numeric::get_msb(coefficients.end_ - 1) + 1;  // dim = get_msb(0) + 1 = 1
    // ...
    size_t n_l = 1 << (dim - 1);                                     // n_l = 1
    // ...
    Fr_ u_l = evaluation_points[0];   // OOB: span is empty!
```

For a `Polynomial(1)` (single coefficient, virtual_size=1), calling `evaluate_mle({})` with an empty evaluation point vector causes:
1. `n = 0` (no evaluation points)
2. `dim = get_msb(0) + 1 = 1` (from `coefficients.end_ = 1`)
3. `n_l = 1 << 0 = 1` (one iteration expected)
4. `evaluation_points[0]` -- out-of-bounds read on empty span, **SIGSEGV**

A single-coefficient polynomial represents a constant (a 0-variable multilinear polynomial). Evaluating it at an empty point set should return the constant value.

**Impact:** Low. `evaluate_mle` is a public API on `Polynomial` that crashes (SIGSEGV) on valid input — a single-coefficient polynomial with an empty evaluation point vector. In practice, sumcheck and other MLE consumers always work with polynomials of size ≥ 2, so `evaluation_points` is never empty. But the function has no guard, and a caller constructing a single-element polynomial would hit undefined behavior with no indication of the cause.

**Proof of Concept:** Integrated test [`AuditPoC_P27_EvaluateMleSingleCoefficientCrash`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L511) in `polynomial_arithmetic.test.cpp`:

```cpp
TYPED_TEST(PolynomialTests, AuditPoC_P27_EvaluateMleSingleCoefficientCrash)
{
    using FF = TypeParam;

    Polynomial<FF> poly(1);
    poly.at(0) = FF(42);

    // 0-variable MLE: empty evaluation points, should return the constant 42
    std::vector<FF> u; // empty
    // This crashes with SIGSEGV — _evaluate_mle accesses evaluation_points[0] on empty span
    FF result = poly.evaluate_mle(u);
    EXPECT_EQ(result, FF(42));
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P27*"
```

```
[  DEATH  ] Exit code 139 (SIGSEGV)
```

Crashes with SIGSEGV — `_evaluate_mle` accesses `evaluation_points[0]` on an empty span.

**Recommended Mitigation:** Add after [`polynomial.hpp:411`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.hpp#L411):

```diff
  const size_t n = evaluation_points.size();
+ if (n == 0) {
+     return coefficients.size() > 0 ? coefficients.get(0) : Fr_(0);
+ }
  const size_t dim = numeric::get_msb(coefficients.end_ - 1) + 1;
```

**Aztec:**
Fixed in [780139e](https://github.com/AztecProtocol/aztec-packages/commit/780139e06d813e38d0f8a92a05c5ec99faeb46cf).

**Cyfrin:** Verified.





### Interpolation constructor does not assert equal sizes of interpolation points and evaluations

**Description:** The interpolation constructor accepts two `std::span` arguments, `interpolation_points` and `evaluations`, and uses the size of `interpolation_points` to determine the polynomial size. It then passes both raw data pointers along with this size to `compute_efficient_interpolation`. There is no assertion or check that `evaluations.size()` is at least as large as `interpolation_points.size()`. If the evaluations span is shorter, the interpolation function reads past the end of the evaluations buffer.

```cpp
// polynomial.cpp, lines 115-125
template <typename Fr>
Polynomial<Fr>::Polynomial(std::span<const Fr> interpolation_points,
                           std::span<const Fr> evaluations,
                           size_t virtual_size)
    : Polynomial(interpolation_points.size(), virtual_size)
{
    BB_ASSERT_GT(coefficients_.size(), static_cast<size_t>(0));

    // evaluations.size() could be < interpolation_points.size() -- no check!
    polynomial_arithmetic::compute_efficient_interpolation(
        evaluations.data(), coefficients_.data(), interpolation_points.data(), coefficients_.size());
}
```

Inside `compute_efficient_interpolation`, the `n` parameter (set to `coefficients_.size()`, which equals `interpolation_points.size()`) is used to index into `src` (the evaluations data pointer) up to index `n-1`:

```cpp
// polynomial_arithmetic.cpp, lines 289-292
for (size_t i = 0; i < n; ++i) {
    roots_and_denominators[i] = -evaluation_points[i];
    temp_src[i] = src[i];     // reads evaluations[i] -- OOB if i >= evaluations.size()
    dest[i] = 0;
```

**Impact:** Out-of-bounds read on the evaluations buffer. The interpolation produces incorrect polynomial coefficients based on whatever data lies beyond the evaluations array.

Current call sites pass matched interpolation/evaluation spans. A mismatched internal call would produce incorrect local proof construction; there is no evidence this would make a verifier accept an invalid proof.

**Proof of Concept:**
```cpp
TEST(LowFindings, ECA_02_InterpolationConstructorMissingSizeCheck)
{
    // Backing buffer of 4 evaluations — but we only intend to pass the first 2.
    std::vector<FF> all_evaluations = { FF(10), FF(20), FF(30), FF(40) };
    std::vector<FF> points = { FF(1), FF(2), FF(3), FF(4) };

    // The "evaluations" span we hand to the constructor is shorter (size 2) than
    // the interpolation points span (size 4).
    std::span<const FF> short_evals(all_evaluations.data(), 2);

    // The constructor uses interpolation_points.size() (=4) as the loop bound
    // inside compute_efficient_interpolation, so it reads evaluations[0..3] from
    // the underlying buffer — past the end of the span we passed.
    auto poly = bb::Polynomial<FF>(points, short_evals, /*virtual_size=*/4);

    // The reconstructed polynomial reproduces ALL FOUR backing values, including
    // the two that lie BEYOND the supplied span. With a proper size assertion
    // those reads should never have happened.
    EXPECT_EQ(poly.evaluate(FF(1)), FF(10));
    EXPECT_EQ(poly.evaluate(FF(2)), FF(20));
    EXPECT_EQ(poly.evaluate(FF(3)), FF(30)); // <-- read PAST evaluations.size()
    EXPECT_EQ(poly.evaluate(FF(4)), FF(40)); // <-- read PAST evaluations.size()
}
```

**Recommended Mitigation:** Add a size assertion at the top of the constructor body:

```cpp
BB_ASSERT_EQ(interpolation_points.size(), evaluations.size());
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified.



### `get_scratch_space` shared buffer unsafe under concurrent FFTs


**Description:** In [`polynomial_arithmetic.cpp:21`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L21), `get_scratch_space` returns a `shared_ptr` to a **single static buffer** reused across sequential calls to avoid repeated allocation. The mutex protects allocation but does **not** prevent two concurrent threads from receiving the same buffer and writing to it simultaneously.

```cpp
template <typename Fr> std::shared_ptr<Fr[]> get_scratch_space(const size_t num_elements)
{
    static std::mutex scratch_mutex;
    std::lock_guard lock(scratch_mutex);          // only protects allocation
    static std::shared_ptr<Fr[]> working_memory = nullptr;
    static size_t current_size = 0;
    if (num_elements > current_size) {
        working_memory = std::make_shared<Fr[]>(num_elements);
        current_size = num_elements;
    }
    return working_memory;                        // returns same pointer to all callers
}
```

The lock serializes the allocation but not the **usage**. Both threads get a `shared_ptr` to the same underlying array and write butterfly results into overlapping indices, corrupting each other's output.

Note: [PR22306](https://github.com/AztecProtocol/aztec-packages/pull/22306) (`20392b77aa`) added this `std::mutex` to `get_scratch_space` to protect the allocation logic. However, this only serializes the check-and-allocate step — the **concurrent usage** issue (two callers receiving the same buffer) remains unfixed.

**Impact:** Low. This is a reproducible data corruption with PoC (50/50 trials corrupted). In barretenberg's current architecture, FFTs are not called concurrently — `parallel_for` parallelizes within a single FFT. The shared scratch buffer is safe under this assumption, but the code does not enforce it and the mutex gives a false sense of thread safety.

**Proof of Concept:** [`AuditPoC_P30_ScratchSpaceConcurrentCorruption`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L528) in `polynomial_arithmetic.test.cpp`:

```cpp
TEST(AuditPoC, P30_ScratchSpaceConcurrentCorruption)
{
    using FF = bb::fr;
    constexpr size_t n = 256;

    std::vector<FF> roots_a(n), roots_b(n);
    for (size_t i = 0; i < n; i++) {
        roots_a[i] = FF(i + 1);
        roots_b[i] = FF(i + 1000);
    }
    std::vector<FF> dest_a(n + 1), dest_b(n + 1);
    std::vector<FF> ref_a(n + 1), ref_b(n + 1);
    polynomial_arithmetic::compute_linear_polynomial_product(roots_a.data(), ref_a.data(), n);
    polynomial_arithmetic::compute_linear_polynomial_product(roots_b.data(), ref_b.data(), n);

    constexpr size_t num_trials = 50;
    size_t corruption_count = 0;
    for (size_t trial = 0; trial < num_trials; trial++) {
        std::atomic<bool> go{ false };
        std::thread thread_a([&]() { while (!go.load()) {} polynomial_arithmetic::compute_linear_polynomial_product(roots_a.data(), dest_a.data(), n); });
        std::thread thread_b([&]() { while (!go.load()) {} polynomial_arithmetic::compute_linear_polynomial_product(roots_b.data(), dest_b.data(), n); });
        go.store(true);
        thread_a.join();
        thread_b.join();
        bool ok = true;
        for (size_t i = 0; i <= n; i++) { if (dest_a[i] != ref_a[i] || dest_b[i] != ref_b[i]) ok = false; }
        if (!ok) corruption_count++;
    }
    // corruption_count == 50/50
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*P30*"
```

```
P-30: 50/50 trials had corrupted results
P-30 CONFIRMED: concurrent scratch space usage causes data corruption
```

**Parallelization Opportunities Currently Blocked**

`get_scratch_space` is reachable only via the call chain:

```
get_scratch_space
  └── compute_linear_polynomial_product       (only caller)
        └── compute_efficient_interpolation   (only caller)
              ├── Polynomial(span, span, vsize) interpolation constructor
              ├── SmallSubgroupIPAProver::compute_eccvm_challenge_polynomial    (small_subgroup_ipa.cpp:226)
              ├── SmallSubgroupIPAProver::compute_monomial_coefficients         (small_subgroup_ipa.cpp:436)
              └── ZKSumcheckData::compute_concatenated_libra_polynomial         (zk_sumcheck_data.hpp:230)
```

All four reachable sites currently run sequentially because the shared scratch buffer makes concurrent invocation unsafe. Once this finding is fixed, the following call sites become legally parallelizable:

| Site | Current | After fix | Estimated savings |
|------|---------|-----------|-------------------|
| [`small_subgroup_ipa.cpp:336-357`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.cpp#L336) — `compute_lagrange_first_and_last` makes two independent `compute_monomial_coefficients` calls (L_1 and L_{\|H\|}) | sequential | trivially parallel | ~50% of this function (~30 μs at n=87) |
| `SmallSubgroupIPAProver::prove()` over multiple proofs (Chonk / folding pipelines, batched circuits) | one prover at a time | concurrent provers | scales linearly with #circuits |
| Future Lagrange-batched routines (e.g., constructing several `Polynomial(points, evals_i, vsize)` inside a `parallel_for`) | unsafe — silently corrupts | safe | depends on caller |

Sites NOT blocked (for completeness):
- Gemini's `compute_fold_polynomials` (`gemini_impl.hpp:124-157`) — has a hard data dependency across folds (A_{l+1} depends on A_l). Already uses `parallel_for_heuristic` *within* each fold, which is the only parallelism that algorithm admits.
- Shplonk's per-claim quotient batching (`shplonk.hpp:75-117`) — uses `factor_roots`, not `compute_efficient_interpolation`. Independent per claim and could be parallelized as a separate optimization, but isn't blocked by this finding.

The largest practical payoff is the second row above: enabling Chonk/folding pipelines to safely invoke independent `SmallSubgroupIPAProver` instances concurrently. The mutex inside `get_scratch_space` even gives reviewers a *false signal* of thread safety, so the fix also removes a long-term tripwire — the natural "wrap a `compute_efficient_interpolation` loop in `parallel_for`" refactor would silently corrupt proofs today.

**Recommended Mitigation:** Give each thread its own buffer with `thread_local`:

```cpp
template <typename Fr> std::shared_ptr<Fr[]> get_scratch_space(const size_t num_elements)
{
    thread_local std::shared_ptr<Fr[]> working_memory = nullptr;
    thread_local size_t current_size = 0;
    if (num_elements > current_size) {
        working_memory = std::make_shared<Fr[]>(num_elements);
        current_size = num_elements;
    }
    return working_memory;
}
```

Note: a deeper fix that removes `get_scratch_space` entirely — by rewriting `compute_linear_polynomial_product` in place — is tracked separately as [issue-21](https://github.com/AztecProtocol/aztec-packages/issues/21). That rewrite would also close the concurrency concern here as a side effect.

**Aztec:**
Fixed in [044b745](https://github.com/AztecProtocol/aztec-packages/commit/044b745f678d854b1d446f1bfb53c58b8942b815).

**Cyfrin:** Verified.



### `parse_size_string` does not check for overflow in `value * multiplier`

**Description:** `parse_size_string()` in `backing_memory.cpp` parses a human-readable size string (e.g., `"500m"`, `"2g"`) into a byte count. After extracting the numeric value via `std::stoull` and selecting the appropriate multiplier based on the suffix, it returns the product `value * multiplier` without checking whether that multiplication overflows `size_t`. On a 64-bit system, `size_t` is 8 bytes, and `value * multiplier` silently wraps modulo 2^64.

```cpp
// backing_memory.cpp, lines 33-73
size_t parse_size_string(const std::string& size_str)
{
    if (size_str.empty()) {
        return std::numeric_limits<size_t>::max();
    }

    try {
        std::string str = size_str;
        char suffix = static_cast<char>(std::tolower(static_cast<unsigned char>(str.back())));
        size_t multiplier = 1;

        if (suffix == 'k') {
            multiplier = 1024ULL;
            str.pop_back();
        } else if (suffix == 'm') {
            multiplier = 1024ULL * 1024ULL;
            str.pop_back();
        } else if (suffix == 'g') {
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            str.pop_back();
        } else if (std::isdigit(static_cast<unsigned char>(suffix)) == 0) {
            throw_or_abort("Invalid storage size format: ...");
        }

        if (str.empty()) {
            throw_or_abort("Invalid storage size format: ...");
        }

        size_t value = std::stoull(str);
        return value * multiplier;   // <--- unchecked overflow
    } catch (...) { ... }
}
```

For example, `"18014398509481984k"` parses as `value = 2^54` and `multiplier = 1024 = 2^10`. The product is `2^64`, which wraps to `0`. The storage budget is then set to `0`, causing all subsequent file-backed allocations to fail the budget check and silently fall back to RAM.

**Impact:** An operator specifying a large `BB_STORAGE_BUDGET` env var value gets a silently tiny budget. All file-backed allocations fail, falling back to RAM. There is no memory safety issue; the consequence is unexpected performance behavior (RAM instead of mmap), not corruption. The env var is set by trusted operators, not attacker-controlled.

This is operator-controlled configuration. It is suitable as a Low severity reliability issue, not an externally exploitable security issue.

**Proof of Concept:** At the shell level:

```bash
# Operator intends to set a very large budget:
BB_SLOW_LOW_MEMORY=1 BB_STORAGE_BUDGET="18014398509481984k" ./bb prove ...
# Internally: 18014398509481984 * 1024 = 2^64, wraps to 0. storage_budget = 0
# In low-memory mode, any required_bytes > 0 causes the file-backed admission
# check to fail, silently falling back to aligned heap memory.
```

```cpp
TEST(LowFindings, ECA_04_ParseSizeStringOverflow)
{
    // Sanity: well-formed inputs parse correctly.
    EXPECT_EQ(parse_size_string("1k"), 1024u);
    EXPECT_EQ(parse_size_string("2g"), 2ULL * 1024 * 1024 * 1024);

    // 2^54 * 1024 == 2^64 → wraps to 0 silently. An operator who set
    // BB_SLOW_LOW_MEMORY=1 BB_STORAGE_BUDGET=18014398509481984k would actually
    // get a budget of 0 bytes, disabling all file-backed allocation.
    EXPECT_EQ(parse_size_string("18014398509481984k"), 0u);
}
```

**Recommended Mitigation:** Add an overflow guard before the multiplication:

```cpp
size_t value = std::stoull(str);
if (value > std::numeric_limits<size_t>::max() / multiplier) {
    throw_or_abort("Storage size overflows: '" + size_str + "'");
}
return value * multiplier;
```

**Aztec:**
Fixed in [87513f8](https://github.com/AztecProtocol/aztec-packages/commit/87513f8bffb880276c560bea2d8c540a8fa94945).

**Cyfrin:** Verified.


### `EvaluationDomain` copy constructor off-by-one for size=2 domains

**Description:** In [`evaluation_domain.cpp:112`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L112), the copy constructor allocates `round_roots` using the formula `log2_size - 1`:

```cpp
round_roots.resize(log2_size - 1);               // for log2_size=1: resize(0)
inverse_round_roots.resize(log2_size - 1);
round_roots[0] = &roots[0];                      // OOB write when resize(0)!
inverse_round_roots[0] = &roots.get()[size];
for (size_t i = 1; i < log2_size - 1; ++i) {
    round_roots[i] = round_roots[i - 1] + (1UL << i);
    inverse_round_roots[i] = inverse_round_roots[i - 1] + (1UL << i);
}
```

For a size-2 domain ($\log_2(2) = 1$), this resizes to 0 elements, then writes to `round_roots[0]` — an out-of-bounds write on an empty vector (undefined behavior).

The original [`compute_lookup_table_single`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L43) correctly uses `emplace_back` which always adds at least 1 entry unconditionally, then grows dynamically. But the [copy constructor](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L90) pre-allocates with the formula `log2_size - 1`, which underestimates by 1 when `log2_size = 1`:

- `log2_size = 1`: original creates 1 entry, copy constructor creates 0 entries (bug)
- `log2_size = 2`: both create 1 entry
- `log2_size = 3`: both create 2 entries

**Impact:** Low. Copying an `EvaluationDomain<Fr>` of size 2 after `compute_lookup_table()` has been called causes undefined behavior. In practice, FFT domains are typically larger (2^10+), but size-2 domains are valid and could appear.

**Proof of Concept:** Integrated test [`AuditPoC_P22_EvalDomainCopyCtorOffByOne`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L599) in `polynomial_arithmetic.test.cpp`:

```cpp
TYPED_TEST(PolynomialTests, AuditPoC_P22_EvalDomainCopyCtorOffByOne)
{
    using FF = TypeParam;

    auto domain = EvaluationDomain<FF>(2);
    domain.compute_lookup_table();

    // Copy the domain — triggers the off-by-one bug:
    // round_roots.resize(log2_size - 1) = resize(0), then writes round_roots[0]
    // This is UB (out-of-bounds write on empty vector)
    auto copied = EvaluationDomain<FF>(domain);
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P22*"
```

```
[==========] Running 2 tests from 2 test suites.
[ RUN      ] PolynomialTests/0.AuditPoC_P22_EvalDomainCopyCtorOffByOne
[1]    48511 segmentation fault  ./bin/polynomials_tests --gtest_filter="*AuditPoC_P22*"
```

The test crashes with a segfault, confirming the OOB write on the empty `round_roots` vector.

The formula `log2_size - 1` should be `log2_size` (or `std::max(1UL, log2_size - 1)`) to handle the size=2 case correctly.

**Recommended Mitigation:** In [`evaluation_domain.cpp:112-113`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L112):

```diff
-        round_roots.resize(log2_size - 1);
-        inverse_round_roots.resize(log2_size - 1);
+        round_roots.resize(std::max(size_t(1), log2_size - 1));
+        inverse_round_roots.resize(std::max(size_t(1), log2_size - 1));
```

**Aztec:**
Fixed in [6cd21a0](https://github.com/AztecProtocol/aztec-packages/commit/6cd21a083ab5620d0ed9800a72f973417f5042b1).

**Cyfrin:** Verified.


### `UnivariateCoefficientBasis` `operator==` compares unused `coefficients[2]` for `domain_end=2`

**Description:** In [`univariate_coefficient_basis.hpp:87`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L87), `operator==` is defaulted:

```cpp
bool operator==(const UnivariateCoefficientBasis& other) const = default;
```

The compiler-generated `= default` compares **all** members, including all 3 elements of `std::array<Fr, 3> coefficients` — even `coefficients[2]`.

For `(domain_end=2, has_a0_plus_a1=false)` objects, `coefficients[2]` is semantically unused (neither an x² coefficient nor a valid Karatsuba precomputation). However, it may contain different values depending on the construction path, causing `operator==` to return `false` for two objects that represent the same polynomial.

Construction paths that leave `coefficients[2]` with different values:

1. [Cross-`has_a0_plus_a1` constructor (line 59)](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L59): Copies `[0]` and `[1]` from a `(2, true)` source, does NOT set `[2]` — it is left uninitialized:

```cpp
UnivariateCoefficientBasis(const UnivariateCoefficientBasis<Fr, domain_end, true>& other)
    requires(!has_a0_plus_a1)
{
    coefficients[0] = other.coefficients[0];
    coefficients[1] = other.coefficients[1];
    // coefficients[2] NOT set for domain_end=2 → uninitialized
    if constexpr (domain_end == 3) {
        coefficients[2] = other.coefficients[2];
    }
}
```

2. [Default constructor (line 57)](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L57) (`= default`): Leaves the entire array uninitialized for trivial types.

3. Arithmetic operators ([`operator+`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L153), [`operator-`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L169), etc.): Copy `*this` into `res` (copying whatever `[2]` held), then modify only `[0]` and `[1]`.

During sumcheck, `UnivariateCoefficientBasis<Fr, 2, true>` objects are naturally constructed from Lagrange-basis polynomials with `[2] = a0 + a1` precomputed for Karatsuba. After arithmetic, results become `(2, false)`. Two objects representing the same polynomial can end up with different `[2]` values depending on the construction path:

- **Path A** — [cross-constructor](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L59) `(2, true)` → `(2, false)`: copies `[0]` and `[1]`, leaves `[2]` uninitialized
- **Path B** — cross-constructor then [`operator+`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L156): `res(*this)` copies all 3 elements including `[2]`, then only updates `[0]` and `[1]`

Both produce the same polynomial, but `[2]` differs → `operator==` returns false.

**Impact:** Low. `operator==` produces false negatives — two objects representing the same polynomial compare as not equal. The `operator==` is currently not called in production code, but `UnivariateCoefficientBasis` is core sumcheck machinery, and equality comparison is a natural operation to add.

The `(2, true)` case is not affected (`coefficients[2] = a₀ + a₁` is deterministic). The `(3, false)` case is also fine (`[2]` is the actual x² coefficient).

**Proof of Concept:** [`AuditPoC_P35_EqualityComparesUnusedCoefficient`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.test.cpp#L56) — builds two `(2, false)` objects with identical `[0]` and `[1]` but different `[2]`, then shows `operator==` returns false:

```cpp
TYPED_TEST(UnivariateCoefficientBasisTest, AuditPoC_P35_EqualityComparesUnusedCoefficient)
{
    // Start from a (2, true) object — as naturally constructed from Univariate (Lagrange basis)
    // P(X) = 5 + 3X, so a0=5, a1=3, a0+a1=8
    UnivariateCoefficientBasis<fr, 2, true> src;
    src.coefficients[0] = fr(5);
    src.coefficients[1] = fr(3);
    src.coefficients[2] = fr(8); // a0 + a1 (Karatsuba precomputation)

    // Path A: cross-constructor (2, true) → (2, false)
    // copies [0] and [1], but does NOT set [2] → uninitialized
    UnivariateCoefficientBasis<fr, 2, false> a(src);

    // Path B: cross-constructor then arithmetic (operator+ copies [2] from *this)
    UnivariateCoefficientBasis<fr, 2, false> b(src);
    UnivariateCoefficientBasis<fr, 2, false> zero;
    zero.coefficients[0] = fr(0);
    zero.coefficients[1] = fr(0);
    b = b + zero; // operator+ copies b's [2] into result via res(*this)

    // Both represent P(X) = 5 + 3X, but [2] may differ
    // BUG: operator== (= default) compares unused [2]
    EXPECT_NE(a, b);
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*P35*"
```

**Recommended Mitigation:** In [`univariate_coefficient_basis.hpp:87`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L87), replace `= default` with a custom `operator==` that only compares semantically meaningful coefficients:

```diff
-    bool operator==(const UnivariateCoefficientBasis& other) const = default;
+    bool operator==(const UnivariateCoefficientBasis& other) const
+    {
+        bool eq = (coefficients[0] == other.coefficients[0]) &&
+                  (coefficients[1] == other.coefficients[1]);
+        if constexpr (domain_end == 3 || has_a0_plus_a1) {
+            eq = eq && (coefficients[2] == other.coefficients[2]);
+        }
+        return eq;
+    }
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified


### Signed integer overflow in `_evaluate_mle` bit-shift expressions

**Description:** The `_evaluate_mle` function in `polynomial.hpp` uses the integer literal `1` (type `int`, 32-bit signed) as the left operand of the left-shift operator `<<` in three places:

```cpp
// polynomial.hpp:415
BB_ASSERT_EQ(coefficients.virtual_size(), static_cast<size_t>(1 << n));

// polynomial.hpp:421
size_t n_l = 1 << (dim - 1);

// polynomial.hpp:448
n_l = 1 << (dim - l - 1);
```

Per the C++ standard ([expr.shift]/1), shifting a signed integer by an amount greater than or equal to its bit-width, or shifting into the sign bit, is undefined behavior. When `n >= 31`, the expression `1 << n` overflows a 32-bit signed `int`. Concretely:

- `1 << 31` produces `INT_MIN` (-2147483648) in two's complement.
- `static_cast<size_t>(INT_MIN)` then sign-extends to `0xFFFFFFFF80000000` on a 64-bit system, which is NOT `2^31`.
- The assertion on line 415 spuriously fails, or worse, a conforming compiler is entitled to optimize away the entire check because the expression involves UB.

The same issue affects the buffer size computation on line 421 and the loop variable on line 448. If `dim >= 32`, these produce garbage values that control loop bounds and allocation sizes.

The codebase already uses the correct `1UL << d` pattern elsewhere, for instance in `eq_polynomial.hpp`:

```cpp
// eq_polynomial.hpp:145 — correct pattern
const size_t N = 1UL << d;
```

The three occurrences in `_evaluate_mle` are inconsistent with this established convention.

**Impact:** For circuits with 2^31 or more rows, MLE evaluation silently produces incorrect results or crashes. The current maximum circuit size is `CONST_SIZE_PROOF_LOG_N = 28`, so this is not reachable today. However, the trend in proving systems is toward larger circuits, and this is actual C++ undefined behavior — the compiler is not required to produce any particular result, and optimizations based on UB assumptions can silently break seemingly unrelated code.

**Recommended Mitigation:** Replace the signed `1` literal with `size_t(1)` in all three locations:

```cpp
// Line 415
BB_ASSERT_EQ(coefficients.virtual_size(), size_t(1) << n);

// Line 421
size_t n_l = size_t(1) << (dim - 1);

// Line 448
n_l = size_t(1) << (dim - l - 1);
```

**Aztec:**
Fixed in [87513f8](https://github.com/AztecProtocol/aztec-packages/commit/87513f8bffb880276c560bea2d8c540a8fa94945).

**Cyfrin:** Verified.


### `EvaluationDomain` move-assignment self-assignment permanently destroys lookup tables

**Description:** The `EvaluationDomain<Fr>::operator=(EvaluationDomain&&)` move-assignment operator in `evaluation_domain.cpp` lacks a self-assignment guard. When `domain = std::move(domain)` is executed, the function first destroys its own state and then attempts to read from `other` — which is the same object:

```cpp
// evaluation_domain.cpp:147-172
template <typename Fr> EvaluationDomain<Fr>& EvaluationDomain<Fr>::operator=(EvaluationDomain&& other)
{
    size = other.size;
    generator_size = other.generator_size;
    // ... scalar copies work fine since this == &other ...

    roots = nullptr;                     // (1) destroys this->roots, which IS other.roots
    round_roots.clear();                 // (2) destroys this->round_roots, which IS other.round_roots
    inverse_round_roots.clear();         // (3) destroys this->inverse_round_roots

    if (other.roots != nullptr) {        // (4) always FALSE — we just set it to nullptr at (1)
        roots = other.roots;             //     never reached
        round_roots = std::move(other.round_roots);
        inverse_round_roots = std::move(other.inverse_round_roots);
    }
    other.roots = nullptr;               // (5) redundant — already nullptr
    return *this;
}
```

The sequence is:
1. Line 162: `roots = nullptr` — since `this == &other`, this also nullifies `other.roots`. If this was the last `shared_ptr` reference, the root-of-unity array is deallocated.
2. Lines 163-164: `round_roots.clear(); inverse_round_roots.clear()` — destroys the pointer vectors for both `this` and `other`.
3. Line 165: `if (other.roots != nullptr)` — evaluates to `false` because step 1 already nullified it.
4. All precomputed FFT lookup table data is permanently lost. Any subsequent FFT/IFFT call will crash or produce garbage.

Both `Polynomial::operator=(const Polynomial&)` and `BackingMemory::operator=(BackingMemory&&)` in the same codebase correctly check for self-assignment:

```cpp
// polynomial.cpp:137-144 — correct pattern
template <typename Fr> Polynomial<Fr>& Polynomial<Fr>::operator=(const Polynomial<Fr>& other)
{
    if (this == &other) {
        return *this;
    }
    coefficients_ = _clone(other.coefficients_);
    return *this;
}

// backing_memory.hpp:78-89 — correct pattern
BackingMemory& operator=(BackingMemory&& other) noexcept
{
    if (this != &other) {
        raw_data = other.raw_data;
        // ...
    }
    return *this;
}
```

`EvaluationDomain` is the only move-assignment operator in the module that omits this guard.

**Impact:** Self-move-assignment can occur through generic algorithms (e.g., `container[i] = std::move(container[j])` where `i == j` at runtime), `std::swap` idioms with moved-from temporaries, or standard library operations on containers of `EvaluationDomain` objects. The result is permanent, irrecoverable loss of all precomputed FFT root tables, causing null pointer dereference or incorrect FFT results on subsequent use. Not currently reachable in normal proving flows, but the inconsistency with sibling operators suggests an oversight.

**Recommended Mitigation:** Add the same self-assignment guard used by `Polynomial` and `BackingMemory`:

```cpp
template <typename Fr>
EvaluationDomain<Fr>& EvaluationDomain<Fr>::operator=(EvaluationDomain&& other)
{
    if (this == &other) {
        return *this;
    }
    // ... rest unchanged
}
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified.


### `Polynomial::random(size, start_index)` underflows when `start_index > size`

**Description:** The two-argument `Polynomial::random` overload computes the allocation size as `size - start_index`. Both parameters are `size_t` (unsigned), so when `start_index > size`, the subtraction wraps to a near-`SIZE_MAX` value:

```cpp
// polynomial.hpp:274-289
static Polynomial random(size_t size, size_t start_index = 0)
{
    BB_BENCH_NAME("generate random polynomial");
    return random(size - start_index, size, start_index);
    //             ^^^^^^^^^^^^^^^^^^  wraps if start_index > size
}

static Polynomial random(size_t size, size_t virtual_size, size_t start_index)
{
    Polynomial p(size, virtual_size, start_index, DontZeroMemory::FLAG);
    parallel_for_heuristic(
        size,
        [&](size_t i) { p.coefficients_.data()[i] = Fr::random_element(); },
        thread_heuristics::ALWAYS_MULTITHREAD);
    return p;
}
```

The three-argument overload then calls `allocate_backing_memory`, which has its own assertion:

```cpp
BB_ASSERT_LTE(start_index + size, virtual_size);
```

But this assertion is also defeated by unsigned wraparound. For example, `random(4, 10)` computes `size - start_index = 4 - 10 = SIZE_MAX - 5`. Inside `allocate_backing_memory`, the check becomes `10 + (SIZE_MAX - 5) = SIZE_MAX + 5`, which wraps to `4`, and `4 <= 4` passes. The subsequent `BackingMemory::allocate(SIZE_MAX - 5)` attempts a roughly 2^64 byte allocation that fails with `std::bad_alloc`.

The naming is also misleading: in the two-argument form, the `size` parameter actually represents `virtual_size`, not the allocation size. A caller might reasonably write `Polynomial::random(4, /*start_index=*/1)` expecting 4 random elements starting at index 1, but actually gets 3 random elements with `virtual_size=4`.

**Impact:** OOM crash (not silent corruption). The function is used internally with correct arguments. The underflow is caught by the memory allocator throwing `std::bad_alloc`, so no exploitable memory corruption occurs. The issue is a fragile helper API that turns invalid arguments into an attempted huge allocation instead of rejecting them with a clear assertion at the boundary.

**Proof of Concept:**
```cpp
TEST(LowFindings, ECA_08_RandomTwoArgUnderflow)
{
    // random(size=4, start_index=10) computes random(4 - 10, 4, 10).
    //   - 4 - 10 underflows in size_t to SIZE_MAX - 5, requested as the alloc size.
    //   - allocate_backing_memory's internal BB_ASSERT_LTE(start + size, virtual)
    //     also wraps (10 + (SIZE_MAX-5) = SIZE_MAX+5 == 4 in size_t), so the
    //     check passes and does NOT catch the bug.
    //   - The allocator then tries to allocate ~2^64 bytes and throws std::bad_alloc.
    EXPECT_THROW(bb::Polynomial<FF>::random(/*size=*/4, /*start_index=*/10), std::bad_alloc);
}
```

**Recommended Mitigation:** Add a precondition check before the subtraction:

```cpp
static Polynomial random(size_t size, size_t start_index = 0)
{
    BB_ASSERT_GTE(size, start_index);
    return random(size - start_index, size, start_index);
}
```

**Aztec:**
Fixed in [6cd21a0](https://github.com/AztecProtocol/aztec-packages/commit/6cd21a083ab5620d0ed9800a72f973417f5042b1).

**Cyfrin:** Verified.


### `ProverEqPolynomial::construct` returns `[0]` instead of `[1]` for empty challenges

**Description:** When `ProverEqPolynomial::construct()` is called with an empty challenges vector (`d=0`), the mathematically expected result is the constant polynomial `[1]` (the empty product equals 1). The function first computes the scaling factor:

```cpp
// eq_polynomial.hpp:56-70
static Polynomial<FF> construct(std::span<const FF> challenges, size_t log_num_monomials)
{
    FF scaling_factor = compute_scaling_factor(challenges);
    // For empty challenges: scaling_factor = 1 (empty product), non-zero

    if (scaling_factor.is_zero()) {
        return construct_eq_with_edge_cases(challenges, log_num_monomials);
        // This fallback handles d=0 correctly: loop doesn't execute, returns [1]
    }

    // Optimal path — delegates to GateSeparatorPolynomial (out of scope)
    return GateSeparatorPolynomial<FF>::compute_beta_products(
        transform_challenge(challenges), log_num_monomials, scaling_factor);
};
```

For empty challenges:
1. `compute_scaling_factor({})` returns `1` (the empty product of `(1 - r_i)` terms).
2. Since `1 != 0`, the optimal path is taken, calling `GateSeparatorPolynomial::compute_beta_products({}, 0, 1)`.
3. This out-of-scope function hits its `betas.empty()` early return, which creates a size-1 polynomial initialized to `0` and ignores the `scaling_factor = 1` argument.

The `compute_scaling_factor` and `transform_challenge` for empty input:

```cpp
// eq_polynomial.hpp:80-88
static FF compute_scaling_factor(std::span<const FF> challenge)
{
    FF out(1);
    const FF one(1);
    for (auto u_i : challenge) {   // empty loop — no iterations
        out *= (one - u_i);
    }
    return out;   // returns 1
}

// eq_polynomial.hpp:101-116
static std::vector<FF> transform_challenge(std::span<const FF> challenges)
{
    std::vector<FF> result;         // empty
    std::vector<FF> denominators;   // empty
    for (const auto& challenge : challenges) { ... }   // empty loop
    FF::batch_invert(denominators);  // no-op on empty vector
    // ...
    return result;   // empty vector
}
```

The fallback path (`construct_eq_with_edge_cases`) would handle `d=0` correctly — its loop doesn't execute and it returns `[1]`. But the optimal path is chosen because `scaling_factor = 1` is non-zero, and the downstream function discards the scaling factor.

**Impact:** Only affects `d=0`, which is a degenerate case. Sumcheck requires at least `d=1`, so this is not reachable in normal protocol execution. The bug is technically in `GateSeparatorPolynomial::compute_beta_products` (out of scope), but manifests through the `ProverEqPolynomial` public interface. It is an incorrect public helper result for the mathematically valid empty-product case.

**Proof of Concept:**
```cpp
TEST(LowFindings, ECA_10_ProverEqPolynomialEmptyChallengesReturnsZero)
{
    std::vector<FF> empty_challenges;
    auto result = bb::ProverEqPolynomial<FF>::construct(empty_challenges, /*log_num_monomials=*/0);

    ASSERT_EQ(result.size(), 1u);

    // Mathematically eq(X, r) with d=0 is the empty product, which equals 1.
    // BUG: GateSeparatorPolynomial::compute_beta_products({}, 0, scaling_factor=1)
    // hits its betas.empty() early return and produces Polynomial(1)=[0],
    // ignoring the scaling_factor. So the public helper returns [0] instead of [1].
    EXPECT_EQ(result.get(0), FF(0));
    // Expected after fix:
    //   EXPECT_EQ(result.get(0), FF(1));
}
```

**Recommended Mitigation:** Add a guard at the top of `construct`:

```cpp
static Polynomial<FF> construct(std::span<const FF> challenges, size_t log_num_monomials)
{
    if (challenges.empty()) {
        Polynomial<FF> result(1, 1);
        result.at(0) = FF(1);
        return result;
    }
    // ... rest unchanged
}
```

Alternatively, fix `GateSeparatorPolynomial::compute_beta_products` to respect the `scaling_factor` argument when `betas` is empty.

**Aztec:**
Fixed in [87513f8](https://github.com/AztecProtocol/aztec-packages/commit/87513f8bffb880276c560bea2d8c540a8fa94945).

**Cyfrin:** Verified.


### `EvaluationDomain` move constructor leaves inconsistent state

**Description:** The [move constructor](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L125-L145) nullifies `other.roots` and moves the `round_roots` / `inverse_round_roots` vectors, but leaves `other.size`, `other.root`, `other.domain`, and the other scalar fields at their original nonzero values.

After move, the moved-from domain has `size > 0` (appears valid) but `roots == nullptr` and `round_roots` empty. Any subsequent FFT operation on the moved-from object dereferences null or accesses empty vectors.

Same issue in the [move assignment operator](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/evaluation_domain.cpp#L147-L172).

**Impact:** Low. In C++ move semantics, using a moved-from object is generally discouraged. But the partial invalidation (`size` still > 0) makes accidental reuse more dangerous than a fully-zeroed state — the object looks valid but crashes on use.

**Proof of Concept:** Integrated test [`AuditPoC_P18_EvalDomainMoveInconsistent`](https://github.com/AztecProtocol/aztec-packages/blob/7b19ca3983/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L662) in `polynomials/polynomial_arithmetic.test.cpp`:

```cpp
TEST(polynomials, AuditPoC_P18_EvalDomainMoveInconsistent)
{
    using FF = bb::fr;

    constexpr size_t n = 16;
    auto domain = EvaluationDomain<FF>(n);
    domain.compute_lookup_table();

    // Save original values
    FF original_root = domain.root;

    // Move-construct a new domain
    auto moved = EvaluationDomain<FF>(std::move(domain));

    // moved should have the data
    EXPECT_EQ(moved.size, n);
    EXPECT_EQ(moved.root, original_root);
    EXPECT_NE(moved.get_round_roots().size(), 0UL);

    // Source domain: roots were moved out (nullptr), but size and root are NOT zeroed
    // This is inconsistent — size > 0 suggests a valid domain, but roots == nullptr
    std::cout << "P-18: After move, source domain.size = " << domain.size << std::endl;
    std::cout << "P-18: After move, source domain.root = " << domain.root << std::endl;
    std::cout << "P-18: After move, source domain round_roots count = "
              << domain.get_round_roots().size() << std::endl;

    bool inconsistent = (domain.size > 0) && (domain.get_round_roots().empty());
    if (inconsistent) {
        std::cout << "P-18 CONFIRMED: moved-from domain has size=" << domain.size
                  << " but empty round_roots" << std::endl;
    }
    EXPECT_TRUE(inconsistent);
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P18*"
```

```
P-18: After move, source domain.size = 16
P-18: After move, source domain.root = ...
P-18: After move, source domain round_roots count = 0
P-18 CONFIRMED: moved-from domain has size=16 but empty round_roots
```

**Recommended Mitigation:** Make the moved-from object match the **default-constructed empty state** — i.e., restore the invariant `size > 0 → roots != nullptr`. Use `std::exchange` to both steal the field's value and zero the source in one expression:

```diff
 EvaluationDomain<Fr>::EvaluationDomain(EvaluationDomain&& other)
-    : size(other.size)
-    , num_threads(compute_num_threads(other.size))
-    , thread_size(other.size / num_threads)
-    , log2_size(static_cast<size_t>(numeric::get_msb(size)))
-    , log2_thread_size(static_cast<size_t>(numeric::get_msb(thread_size)))
-    , log2_num_threads(static_cast<size_t>(numeric::get_msb(num_threads)))
-    , generator_size(other.generator_size)
+    : size(std::exchange(other.size, 0))
+    , num_threads(std::exchange(other.num_threads, 0))
+    , thread_size(std::exchange(other.thread_size, 0))
+    , log2_size(std::exchange(other.log2_size, 0))
+    , log2_thread_size(std::exchange(other.log2_thread_size, 0))
+    , log2_num_threads(std::exchange(other.log2_num_threads, 0))
+    , generator_size(std::exchange(other.generator_size, 0))
     , root(other.root)
     , root_inverse(other.root_inverse)
-    , domain(Fr{ size, 0, 0, 0 }.to_montgomery_form())
-    , domain_inverse(domain.invert())
+    , domain(other.domain)
+    , domain_inverse(other.domain_inverse)
     , generator(other.generator)
     , generator_inverse(other.generator_inverse)
+    , roots(std::move(other.roots))            // shared_ptr move → other.roots = nullptr
+    , round_roots(std::move(other.round_roots))
+    , inverse_round_roots(std::move(other.inverse_round_roots))
 {
-    roots = other.roots;
-    round_roots = std::move(other.round_roots);
-    inverse_round_roots = std::move(other.inverse_round_roots);
-    // @audit move must not destruct the source
-    other.roots = nullptr;
 }
```

Apply the same pattern to the move assignment operator.

Reference pattern: [`BackingMemory::operator=(BackingMemory&&)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.hpp#L78) already does this correctly — it nulls `other.raw_data` after stealing its target to preserve the invariant that `raw_data` mirrors the owning pointer. `EvaluationDomain` should mirror this discipline.

Why `std::exchange` is applied to these specific fields — two tiers:

- Must zero (`size`) — this is the only invariant-gating field. All validity checks on an `EvaluationDomain` gate on `size > 0`; zeroing it on move makes the source visibly empty and prevents any downstream code from treating the moved-from object as usable.
- Should zero for internal consistency (`num_threads`, `thread_size`, `log2_size`, `log2_thread_size`, `log2_num_threads`, `generator_size`) — these are derived from `size`. Setting `size = 0` but leaving `log2_size = 4` would be internally incoherent even though no code reads them without first checking `size`. Cheap to fix, keeps the moved-from state coherent.

The field elements (`root`, `domain`, `generator`, etc.) are not invariant-gating, so plain `other.root` is fine — zeroing them is defensive but adds noise. The `shared_ptr` and `vector` members use `std::move`, not `std::exchange`, because moving a `shared_ptr` already nulls the source and moving a `vector` already empties it.

**Aztec:**
Fixed in [cf988ed](https://github.com/AztecProtocol/aztec-packages/commit/cf988ed6f4801af41adab1e98d7d0ff771adb227).

**Cyfrin:** Verified.


### `Polynomial` defaulted move leaves inconsistent state

**Description:** [`Polynomial`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.hpp#L96) uses both a defaulted move constructor and move assignment:

```cpp
Polynomial(Polynomial&& other) noexcept = default;                    // line 96
Polynomial& operator=(Polynomial&& other) noexcept = default;         // line 134
```

Both share the same issue.

`Polynomial` has one member, `coefficients_` of type `SharedShiftedVirtualZeroesArray<Fr>`. That struct also has no custom move, so the compiler-generated move performs:

- **`start_`, `end_`, `virtual_size_`** (`size_t` scalars) — trivially copied, **source unchanged**
- **`backing_memory_`** (contains `shared_ptr<Fr[]>`, `raw_data`, optional `file_backed`) — moved via `BackingMemory`'s move, which correctly nulls source's pointer fields

The result: after move, the source polynomial has `size() > 0` (scalars unchanged), but `data() == nullptr` (backing memory moved out).

A moved-from `Polynomial` looks valid to most accessors:
- `size()` returns the old non-zero value
- `virtual_size()` returns the old value
- `start_index()` / `end_index()` return old values
- `is_empty()` returns `false`

But any attempt to access backed memory (`at()`, `data()[i]`, `operator+=`, etc.) **dereferences nullptr** → segfault or UB.

**Impact:** Low. C++ move semantics say moved-from objects should not be used without reassignment. Careful callers avoid this entirely. The danger is that:

1. A caller accidentally uses a moved-from polynomial (common bug class in C++)
2. The polynomial looks valid via scalar queries (size, virtual_size)
3. The crash happens only on data access, with a misleading null-pointer error

**Proof of Concept:** Integrated death test [`AuditPoC_P50_MovedFromPolynomialCausesSegfault`](https://github.com/AztecProtocol/aztec-packages/blob/d630e5bd77/barretenberg/cpp/src/barretenberg/polynomials/polynomial.test.cpp#L262) in `polynomials/polynomial.test.cpp`. A caller trusts the scalar fields (`size() > 0`) and writes via `src.at(start_index)`, which dereferences the null `data()` pointer and segfaults — demonstrating that the inconsistent moved-from state (`size() > 0` but `data() == nullptr`) is a real crash path, not just a latent state violation.

```cpp
TEST(PolynomialDeathTest, AuditPoC_P50_MovedFromPolynomialCausesSegfault)
{
    using FF = bb::fr;
    using Polynomial = bb::Polynomial<FF>;

    auto use_moved_from = [] {
        auto src = Polynomial::random(10, 16, 2);
        Polynomial moved{ std::move(src) };

        // After move: src.size() == 10 (looks valid), but src.data() == nullptr.
        src.at(2) = FF(5); // dereferences nullptr
    };

    EXPECT_DEATH(use_moved_from(), ".*");
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P50*"
```

Observed output:
```
[ RUN      ] PolynomialDeathTest.AuditPoC_P50_MovedFromPolynomialCausesSegfault
[       OK ] PolynomialDeathTest.AuditPoC_P50_MovedFromPolynomialCausesSegfault (9 ms)
```

`EXPECT_DEATH` forks a subprocess, runs the write, and confirms the subprocess terminates abnormally (SIGSEGV).

**Recommended Mitigation:** Fix at the [`SharedShiftedVirtualZeroesArray`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/shared_shifted_virtual_zeroes_array.hpp#L29) layer — replace the implicit defaulted move with an explicit one that zeros the scalar fields. This addresses the root cause and propagates up to every wrapper (not just `Polynomial`):

```cpp
SharedShiftedVirtualZeroesArray(SharedShiftedVirtualZeroesArray&& other) noexcept
    : start_(std::exchange(other.start_, 0))
    , end_(std::exchange(other.end_, 0))
    , virtual_size_(std::exchange(other.virtual_size_, 0))
    , backing_memory_(std::move(other.backing_memory_))
{}

SharedShiftedVirtualZeroesArray& operator=(SharedShiftedVirtualZeroesArray&& other) noexcept {
    if (this != &other) {
        start_         = std::exchange(other.start_, 0);
        end_           = std::exchange(other.end_, 0);
        virtual_size_  = std::exchange(other.virtual_size_, 0);
        backing_memory_ = std::move(other.backing_memory_);
    }
    return *this;
}
```

With this fix, the moved-from `Polynomial` has `size() == 0` and `is_empty() == true` — matching the default-constructed empty state. The invariant `size > 0 → data() != nullptr` is restored.

**Aztec:**
Fixed in [6043f43](https://github.com/AztecProtocol/aztec-packages/commit/cf988ed6f4801af41adab1e98d7d0ff771adb227).

**Cyfrin:** Verified.


### `ProverEqPolynomial::construct` fast path does not enforce `challenges.size() == log_num_monomials`

**Description:** `ProverEqPolynomial::construct()` in `eq_polynomial.hpp` decides between an optimized path (via `GateSeparatorPolynomial::compute_beta_products`) and a fallback (`construct_eq_with_edge_cases`) based on a scaling factor. Only the fallback path asserts the fundamental dimensional precondition `challenges.size() == log_num_monomials` — the fast path has no such check:

```cpp
// eq_polynomial.hpp:56-70
static Polynomial<FF> construct(std::span<const FF> challenges, size_t log_num_monomials)
{
    FF scaling_factor = compute_scaling_factor(challenges);

    if (scaling_factor.is_zero()) {
        return construct_eq_with_edge_cases(challenges, log_num_monomials);
        // construct_eq_with_edge_cases does:
        //   BB_ASSERT_EQ(d, log_num_monomials, "expect log_num_monomials == r.size()");
    }

    // Fast path — no dimension assertion:
    return GateSeparatorPolynomial<FF>::compute_beta_products(
        transform_challenge(challenges), log_num_monomials, scaling_factor);
};
```

Two concrete symptoms follow:

1. **`log_num_monomials < challenges.size()`** — extra challenges are silently discarded. The returned eq-table is not `eq(X, r)` over the full challenge vector; it corresponds to a smaller-dimensional polynomial. For a weighting object over the Boolean hypercube, dropping a dimension changes the polynomial entirely.
2. **`log_num_monomials > challenges.size()` and no `r_i == 1`** — the fast path continues into `compute_beta_products`, where the inner loop walks `betas[current_element_idx]` past the end of the transformed-challenge vector. This is an out-of-bounds read in the consuming helper, reachable only via this public entry point.

The existing issue 16 (`ProverEqPolynomial::construct returns [0] instead of [1] for empty challenges`) is adjacent but strictly narrower — it addresses only the empty-challenge degenerate case, not the general-dimension mismatch on non-empty input.

**Impact:** Current production callers pass matched dimensions. A mismatched internal caller either silently computes the wrong eq-polynomial (soundness-relevant if the output feeds into a sumcheck-style relation) or reads out of bounds in the downstream `compute_beta_products`. The fallback path has the right assertion; the fast path should too.

**Recommended Mitigation:** Hoist the dimension check out of `construct_eq_with_edge_cases` and apply it on both paths:

```cpp
static Polynomial<FF> construct(std::span<const FF> challenges, size_t log_num_monomials)
{
    BB_ASSERT_EQ(challenges.size(), log_num_monomials,
                 "ProverEqPolynomial::construct: challenges.size() must equal log_num_monomials");
    FF scaling_factor = compute_scaling_factor(challenges);
    // ... rest unchanged
}
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4) and [19c03f4](https://github.com/AztecProtocol/aztec-packages/commit/19c03f4739bac844350e91357b662b36725dc160).

**Cyfrin:** Verified.

\clearpage
## Informational


### `SharedShiftedVirtualZeroesArray` invariant enforcement gap


**Description:** In [`shared_shifted_virtual_zeroes_array.hpp`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/shared_shifted_virtual_zeroes_array.hpp), the struct requires the invariant `start_ <= end_ <= virtual_size_`, but this is never validated:

1. No constructor checks the invariant — aggregate initialization allows any values
2. `Polynomial::shrink_end_index` checks the upper bound but not the lower:

```cpp
// polynomial.cpp:236
void Polynomial<Fr>::shrink_end_index(const size_t new_end_index)
{
    BB_ASSERT_LTE(new_end_index, end_index());   // checks: new <= current end
    coefficients_.end_ = new_end_index;            // NO check: new >= start_
}
```

If `new_end_index < start_`, then `size()` (= `end_ - start_`) underflows to `SIZE_MAX` because both are `size_t` (unsigned). This corrupts all size-dependent operations.

**Impact:** Informational. All current callers use `shrink_end_index` correctly. If misused, the `SIZE_MAX` underflow would crash immediately (not silently produce wrong results). The assert is a code hygiene suggestion.

**Proof of Concept:** [`AuditPoC_P15_ShrinkEndIndexUnderflow`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L485) — creates a polynomial with `start_index=2`, then calls `shrink_end_index(1)`. The current check passes (`1 <= 10`) but `end_ < start_` causes `size()` to underflow. With our fix, the assert would catch it.

```cpp
TEST(AuditPoC, P15_ShrinkEndIndexUnderflow)
{
    using FF = bb::fr;

    // Create a polynomial with start_index=2: coefficients at indices [2..9], virtual_size=16
    auto poly = Polynomial<FF>(8, 16, /*start_index=*/2);
    EXPECT_EQ(poly.start_index(), 2UL);
    EXPECT_EQ(poly.end_index(), 10UL);
    EXPECT_EQ(poly.size(), 8UL);

    // shrink_end_index(1): passes current check (1 <= 10) but violates start_ <= end_
    poly.shrink_end_index(1);

    // end_ = 1, start_ = 2 → size() = 1 - 2 = SIZE_MAX (unsigned underflow)
    EXPECT_EQ(poly.end_index(), 1UL);
    EXPECT_EQ(poly.size(), SIZE_MAX);

    // With fix: BB_ASSERT_GTE(new_end_index, start_index()) would catch 1 < 2
}
```

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*P15*"
```

```
P-15: start=2 end=1 size=18446744073709551615
P-15 CONFIRMED: size() underflows to SIZE_MAX
```

**Recommended Mitigation:** Add lower bound check at [`polynomial.cpp:238`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.cpp#L238):

```diff
  BB_ASSERT_LTE(new_end_index, end_index());
+ BB_ASSERT_GTE(new_end_index, start_index());
  coefficients_.end_ = new_end_index;
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified.


### `set()`, `at()`, and `operator[]` (mutable) use debug-only bounds checks allowing silent heap corruption in release


**Description:** `SharedShiftedVirtualZeroesArray` provides two classes of accessors. The read-only `get()` method has an explicit runtime bounds check in all builds, while the mutable `set()` and `operator[]` methods guard bounds with `BB_ASSERT_DEBUG`, a macro that compiles to a no-op in release builds (when `NDEBUG` is defined). `Polynomial::at()` delegates directly to `operator[]`, inheriting the same behavior.

The safe read path (`get()`):

```cpp
// shared_shifted_virtual_zeroes_array.hpp, lines 56-64
const T& get(size_t index, size_t virtual_padding = 0) const
{
    static const T zero{};
    BB_ASSERT_DEBUG(index < virtual_size_ + virtual_padding);  // debug-only hint
    if (index >= start_ && index < end_) {                     // ALWAYS runs -- safe
        return data()[index - start_];
    }
    return zero;  // out-of-range returns zero, no memory access
}
```

The unsafe write paths (`set()` and `operator[]`):

```cpp
// shared_shifted_virtual_zeroes_array.hpp, lines 38-43
void set(size_t index, const T& value)
{
    BB_ASSERT_DEBUG(index >= start_);   // compiled out in release
    BB_ASSERT_DEBUG(index < end_);      // compiled out in release
    data()[index - start_] = value;     // executes unconditionally in release
}

// shared_shifted_virtual_zeroes_array.hpp, lines 86-91
T& operator[](size_t index)
{
    BB_ASSERT_DEBUG(index >= start_);   // compiled out in release
    BB_ASSERT_DEBUG(index < end_);      // compiled out in release
    return data()[index - start_];      // executes unconditionally in release
}
```

`Polynomial::at()` delegates to `operator[]`:

```cpp
// polynomial.hpp, line 268
Fr& at(size_t index) { return coefficients_[index]; }
```

When `index < start_`, the expression `index - start_` wraps around because both are `size_t` (unsigned), producing a huge offset. `data()` returns a pointer to the beginning of the allocated buffer, so `data()[huge_offset]` dereferences an address far beyond the allocation, resulting in a wild pointer write. When `index >= end_` but the backing memory is smaller than `end_ - start_` elements, the access is a classic heap buffer overflow.

**Impact:** Silent heap corruption in release builds if any caller passes an out-of-range index to a mutable accessor. The `SharedShiftedVirtualZeroesArray` is only accessed through `Polynomial`, which is expected to maintain correct invariants.

This requires a caller bug or a corrupted polynomial range invariant. No current production call site was identified that intentionally writes out of range, but the release-build failure mode is memory corruption rather than a clean abort.

**Recommended Mitigation:** Promote the mutable-access bounds checks that protect memory safety to always-on `BB_ASSERT`, at least for `set()` and `operator[]`. If profiling shows this is too expensive for hot paths, document the invariant requirement directly on the mutable accessors and add narrow wrapper APIs for checked mutation at call sites where indices are not trivially derived from validated ranges.

**Aztec:**
Acknowledged.


### `backing_memory.cpp` preprocessor guard inconsistent with header

**Description:** In [`backing_memory.cpp:20`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.cpp#L20) and [`backing_memory.hpp:36`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.hpp#L36), the preprocessor guards for file-backed storage features differ:

| File | Guard |
|------|-------|
| `backing_memory.hpp:36` | `#if !defined(__wasm__) && !defined(_WIN32)` |
| `backing_memory.cpp:20` | `#if !defined(__wasm__) \|\| defined(ENABLE_WASM_BENCH)` |

Two inconsistencies:

1. **Missing `_WIN32` exclusion in `.cpp`** — The header excludes Windows, but the `.cpp` doesn't. On Windows the `.cpp` defines symbols (`storage_budget`, `current_storage_usage`, `parse_size_string`) that nothing can reference because the header never declares them.

2. **`ENABLE_WASM_BENCH` not recognized by header** — The `.cpp` allows WASM builds when `ENABLE_WASM_BENCH` is defined, but the header has no such exception. When building with both `__wasm__` and `ENABLE_WASM_BENCH`, the `.cpp` provides definitions that are invisible to any translation unit including the header.

In UltraHonk production (Linux/macOS), file-backed storage is only activated when `BB_SLOW_LOW_MEMORY=1` is set. Windows and WASM are not supported production targets.

**Impact:** Informational. No impact on production prover or verifier.

**Recommended Mitigation:** Make [`backing_memory.cpp:20`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.cpp#L20) match [`backing_memory.hpp:36`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.hpp#L36):

```diff
-#if !defined(__wasm__) || defined(ENABLE_WASM_BENCH)
+#if !defined(__wasm__) && !defined(_WIN32)
```

**Aztec:**
Acknowledged.


### `fft_inner_parallel` unsafe when `coeffs == target`

**Description:** In [`polynomial_arithmetic.cpp:86-93`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L86), phase 1 of `fft_inner_parallel` reads from `coeffs[swap_index]` (bit-reversed) and writes to `target[i]` (sequential):

```cpp
Fr::__copy(coeffs[swap_index_1], temp_1);   // read from bit-reversed index
Fr::__copy(coeffs[swap_index_2], temp_2);
target[i + 1] = temp_1 - temp_2;            // write to sequential index
target[i] = temp_1 + temp_2;
```

If `coeffs == target` (same pointer), the bit-reversed read at `swap_index` could access an element that was already overwritten by a previous iteration's sequential write. For example with `n=8`:

```
i=0: writes target[0], target[1]
i=2: reads coeffs[reverse(2)] = coeffs[2] ← OK (not yet written)
     reads coeffs[reverse(3)] = coeffs[6] ← OK
     writes target[2], target[3]
i=4: reads coeffs[reverse(4)] = coeffs[1] ← ALREADY OVERWRITTEN at i=0!
```

The function signature accepts separate `Fr* coeffs` and `Fr* target` pointers but does not assert they are different.

**Impact:** Informational. In UltraHonk, `ifft` is only called in ZK sumcheck Libra ([`zk_sumcheck_data.hpp:233`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/sumcheck/zk_sumcheck_data.hpp#L233)) and small subgroup IPA ([`small_subgroup_ipa.cpp:439`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.cpp#L439)), both on `SUBGROUP_SIZE = 256` with separate input/output buffers. The function signature permits aliasing, and a future caller passing the same buffer would get silently wrong results.

**Proof of Concept:** [`AuditPoC_P32_FftInPlaceAliasing`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L620) in `polynomial_arithmetic.test.cpp`:

```cpp
TEST(AuditPoC, P32_FftInPlaceAliasing)
{
    using FF = bb::fr;
    constexpr size_t n = 16;

    auto domain = bb::EvaluationDomain<FF>(n);
    domain.compute_lookup_table();

    std::array<FF, n> coeffs;
    for (size_t i = 0; i < n; i++) {
        coeffs[i] = FF::random_element();
    }

    // Correct: separate input/output buffers
    std::array<FF, n> correct_output;
    std::array<FF, n> coeffs_copy;
    std::copy(coeffs.begin(), coeffs.end(), coeffs_copy.begin());
    polynomial_arithmetic::fft_inner_parallel(
        coeffs_copy.data(), correct_output.data(), domain, domain.root, domain.get_round_roots());

    // Buggy: in-place (coeffs == target)
    std::array<FF, n> aliased;
    std::copy(coeffs.begin(), coeffs.end(), aliased.begin());
    polynomial_arithmetic::fft_inner_parallel(
        aliased.data(), aliased.data(), domain, domain.root, domain.get_round_roots());

    // In-place produces different (wrong) results
    bool mismatch = false;
    for (size_t i = 0; i < n; i++) {
        if (correct_output[i] != aliased[i]) {
            mismatch = true;
            break;
        }
    }
    EXPECT_TRUE(mismatch);
}
```

**Recommended Mitigation:** In [`polynomial_arithmetic.cpp:74`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L74):

```diff
 void fft_inner_parallel(
     Fr* coeffs, Fr* target, const EvaluationDomain<Fr>& domain, const Fr&, const std::vector<Fr*>& root_table)
 {
+    BB_ASSERT(coeffs != target, "fft_inner_parallel does not support in-place operation");
```

**Aztec:**
Fixed in [80131f6](https://github.com/AztecProtocol/aztec-packages/commit/80131f6906d0c5e0ac9f55f2d40a00757899c7c4).

**Cyfrin:** Verified.


### `compute_linear_polynomial_product` is O(n^3) instead of O(n^2)

**Description:** In [`polynomial_arithmetic.cpp:213`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L213), `compute_linear_polynomial_product` builds the polynomial `(X − r_0)(X − r_1)···(X − r_{n−1})` using a doubly-nested loop with a `compute_sum` call inside, giving total complexity **O(n^3)**:

```cpp
for (size_t i = 0; i < n - 1; ++i) {
    temp = 0;
    for (size_t j = 0; j < n - 1 - i; ++j) {
        scratch_space[j] = roots[j] * compute_sum(&scratch_space[j + 1], n - 1 - i - j);
        //                              compute_sum is O(n - 1 - i - j) → cubic total
        temp += scratch_space[j];
    }
    dest[n - 2 - i] = temp * constant;
    constant *= Fr::neg_one();
}
```

The same coefficients can be obtained in **O(n^2)** by the standard "multiply by `(X − r_i)` one root at a time" recurrence:

```cpp
dest[0] = -roots[0];
dest[1] = 1;
for (size_t i = 1; i < n; ++i) {
    const Fr r = roots[i];
    dest[i + 1] = dest[i];
    for (size_t k = i; k >= 1; --k) {
        dest[k] = dest[k - 1] - r * dest[k];
    }
    dest[0] = -r * dest[0];
}
```

Short trace with `n = 3`, `roots = [1, 2, 3]`, expected `(X−1)(X−2)(X−3) = X^3 − 6X^2 + 11X − 6` -> `dest = [−6, 11, −6, 1]`:

- Init (represents `X − 1`): `dest = [−1, 1, ?, ?]`.
- Iteration `i = 1` (multiply in `X − 2`, `r = 2`):
  - shift `dest[2] = dest[1] = 1`;
  - inner `k=1`: `dest[1] = dest[0] − r·dest[1] = −1 − 2 = −3`;
  - then `dest[0] = −r·dest[0] = 2`.
  - Result: `[2, −3, 1, ?]` = `(X−1)(X−2)`.
- Iteration `i = 2` (multiply in `X − 3`, `r = 3`):
  - shift `dest[3] = dest[2] = 1`;
  - inner `k=2`: `dest[2] = dest[1] − r·dest[2] = −3 − 3·1 = −6`;
  - inner `k=1`: `dest[1] = dest[0] − r·dest[1] = 2 − 3·(−3) = 11`;
  - then `dest[0] = −r·dest[0] = −3·2 = −6`.
  - Result: `[−6, 11, −6, 1]` = `(X−1)(X−2)(X−3)`.

The inner loop runs high → low so `dest[k−1]` still holds its previous-iteration value when read — the shift-then-combine trick that keeps the update in place without a scratch buffer. The current algorithm needs a scratch buffer because `dest[k]` stores the final coefficient `(-1)^(n-k) · e_{n-k}` while its inner loop aggregates partial sums of a different shape; the optimized version keeps the partial polynomial `(X − r_0)···(X − r_i)` directly in `dest[0..i+1]`, so `dest[]` already has the right layout.

As a side benefit, `compute_linear_polynomial_product` is the only caller of `get_scratch_space<Fr>` ([`polynomial_arithmetic.cpp:21`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.cpp#L21)) — the static thread-shared buffer at the root of [issue-8](https://github.com/AztecProtocol/aztec-packages/issues/8). After this fix, `get_scratch_space` can be deleted outright, so one change delivers O(n^3) → O(n^2) cost, zero per-call allocation, and concurrency safety.

**Impact:** Informational (performance). Production callers via `compute_efficient_interpolation`:

| Caller | n |
|--------|---|
| `zk_sumcheck_data.hpp:230` (Libra interpolation, non-BN254 path) | Grumpkin SUBGROUP_SIZE = **87** |
| `small_subgroup_ipa.cpp:226` (ECCVM challenge polynomial, Grumpkin) | 87 |
| `small_subgroup_ipa.cpp:436` (monomial coefficients, Grumpkin) | 87 |
| Generic interpolation constructor (any future caller) | up to BN254 SUBGROUP_SIZE = **256** |

(BN254 ZK-Sumcheck takes the IFFT path, not this one.)

**Proof of Concept:** Integrated benchmark [`AuditPoC.P36_LinearPolyProductCubicVsQuadratic`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial_arithmetic.test.cpp#L775) in `polynomials/polynomial_arithmetic.test.cpp`. The test generates random roots, runs both implementations, verifies coefficient-by-coefficient equality and that `evaluate(dest, z) == \prod(z − r_i)`, then times 50 runs of each and reports the speedup.

Measured on an M-series Mac, release build:

```
P-36 n=87  (Grumpkin):   current = 307 μs    optimized = 35 μs    speedup = 8.7×
P-36 n=256 (BN254 subgroup): current = 7.1 ms   optimized = 0.30 ms  speedup = 23.4×
```

The speedup grows linearly with `n` as expected from O(n³) → O(n²).

Removing the scratch buffer also makes `compute_efficient_interpolation` reentrant, so today-sequential call sites become independently parallelizable:

| Site | Currently | After fix | Wall-time savings |
|------|-----------|-----------|-------------------|
| [`small_subgroup_ipa.cpp:336-357`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.cpp#L336) — `compute_lagrange_first_and_last` does 2 independent `compute_monomial_coefficients` calls (L_1 and L_{\|H\|}) | sequential | trivially parallel | ~50% of this function (~30 μs at n=87) |
| Batched proof generation (e.g., Chonk / folding pipelines) — multiple `SmallSubgroupIPAProver::prove()` instances across circuits | must run sequentially or risk corruption | each prover thread-safe | scales linearly with #circuits |

The mutex inside `get_scratch_space` also gives reviewers a false signal of thread safety, so the fix removes a long-term tripwire.

**Recommended Mitigation:** Replace the implementation with the incremental "multiply by `(X − r_i)`" loop (shown above). Same output, ~9× faster on production-sized inputs. Then delete `get_scratch_space<Fr>` from `polynomial_arithmetic.cpp` — it has no other callers.

**Aztec:**
Fixed in [044b745](https://github.com/AztecProtocol/aztec-packages/commit/044b745f678d854b1d446f1bfb53c58b8942b815).

**Cyfrin:** Verified.


### `UnivariateCoefficientBasis` loses Karatsuba precomputation after arithmetic


**Description:** In [`univariate_coefficient_basis.hpp`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp), all arithmetic operators ([`operator+`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L153), [`operator-`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L169), [`operator+=`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L90), [`operator-=`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L105), scalar operations) return `UnivariateCoefficientBasis<Fr, domain_end, false>` — unconditionally resetting `has_a0_plus_a1` to `false`. This discards the precomputed `a0 + a1` value stored in `coefficients[2]`, even when the result could preserve it cheaply.

```cpp
// operator+ always returns has_a0_plus_a1 = false
template <size_t other_domain_end, bool other_has_a0_plus_a1>
UnivariateCoefficientBasis<Fr, domain_end, false> operator+(
    const UnivariateCoefficientBasis<Fr, other_domain_end, other_has_a0_plus_a1>& other) const
{
    UnivariateCoefficientBasis<Fr, domain_end, false> res(*this);
    res.coefficients[0] += other.coefficients[0];
    res.coefficients[1] += other.coefficients[1];
    // coefficients[2] NOT updated for domain_end=2
    // → precomputed (a0+a1) is lost even though (a0'+a1') = (a0+a1) + (b0+b1)
    return res;
}
```

The in-place operators have the same issue — they skip `coefficients[2]` when `domain_end=2`:

```cpp
// operator+= also returns has_a0_plus_a1 = false
UnivariateCoefficientBasis<Fr, domain_end, false>& operator+=(...)
{
    coefficients[0] += other.coefficients[0];
    coefficients[1] += other.coefficients[1];
    if constexpr (other_domain_end == 3 && domain_end == 3) {
        coefficients[2] += other.coefficients[2];
    }
    // coefficients[2] NOT updated for domain_end=2
    return *this;
}
```

When both operands are `(domain_end=2, has_a0_plus_a1=true)`, the precomputation is preservable for all four operators:

```
operator+/+=:
  this:  a0, a1, (a0+a1)
  other: b0, b1, (b0+b1)
  result: (a0+b0), (a1+b1), (a0+a1)+(b0+b1) = (a0+b0)+(a1+b1) ← correct!

operator-/-=:
  result: (a0-b0), (a1-b1), (a0+a1)-(b0+b1) = (a0-b0)+(a1-b1) ← correct!
```

But the return type is hardcoded to `false`, so downstream `operator*` cannot use the (T,T) Karatsuba branch and must recompute `a0+a1` from scratch.

**Impact:** Informational (performance). In Sumcheck's inner loop, `UnivariateCoefficientBasis` operations are executed per-gate, per-relation, per-round. The Karatsuba optimization saves 1 field addition per degree-1 multiplication by using the precomputed `a0+a1`.

For relation patterns like `(wire_a + wire_b) * wire_c`:

```
1. wire_a, wire_b, wire_c: converted from Lagrange → (2, true), a0+a1 free
2. wire_a + wire_b → (2, false), Karatsuba precomputation LOST
3. result * wire_c → hits (F,T) branch, recomputes a0+a1 (+1 addition)
```

If step 2 preserved `has_a0_plus_a1=true`, step 3 would use the cheaper (T,T) branch.

**Proof of Concept:** Measured benchmark:

Integrated benchmark [`AuditPoC.P33_AddThenMultiplyKaratsubaPath`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.test.cpp#L142) in `polynomials/univariate_coefficient_basis.test.cpp`. The test simulates the realistic Sumcheck pattern `(wire_a + wire_b) * wire_c` for 200k iterations:

- Current: `a + b` returns `(2, false)` (precomputation discarded), so `(a+b) * c` takes the (F,T) Karatsuba branch.
- Optimized: manually preserve `a0+a1` in the sum (what the recommended fix would do automatically), so `(a+b) * c` takes the (T,T) branch.

```cpp
TEST(AuditPoC, P33_AddThenMultiplyKaratsubaPath)
{
    constexpr size_t N = 200000;
    std::vector<UnivariateCoefficientBasis<fr, 2, true>> A(N), B(N), C(N);
    // ... fill each with random (a0, a1) and coefficients[2] = a0 + a1

    // Current: (A + B) returns (2, false), so * falls into the (F, T) branch.
    auto t0 = high_resolution_clock::now();
    for (size_t i = 0; i < N; ++i) {
        auto sum = A[i] + B[i];           // has_a0_plus_a1 = false
        auto out = sum * C[i];            // (F, T) Karatsuba branch
    }
    auto t1 = high_resolution_clock::now();

    // Optimized: reconstruct the sum as (2, true) with coefficients[2] preserved → (T, T).
    for (size_t i = 0; i < N; ++i) {
        UnivariateCoefficientBasis<fr, 2, true> sum;
        sum.coefficients[0] = A[i].coefficients[0] + B[i].coefficients[0];
        sum.coefficients[1] = A[i].coefficients[1] + B[i].coefficients[1];
        sum.coefficients[2] = A[i].coefficients[2] + B[i].coefficients[2];  // a0'+a1'
        auto out = sum * C[i];            // (T, T) Karatsuba branch
    }
    auto t2 = high_resolution_clock::now();
}
```

```
P-33 N=200000:  current ((F,T) chain) = 33.3 ns/op   optimized ((T,T) chain) = 30.2 ns/op   saved = 9.5%
```

Per-`(add + mul)` pattern saved: ~3 ns. The 9.5% is the realistic per-pattern speedup, not the upper bound — it includes the `+` operation cost as well.

**Recommended Mitigation:** Template the return type to preserve `has_a0_plus_a1=true` when both inputs are `(2, true)`:

```cpp
template <size_t other_domain_end, bool other_has_a0_plus_a1>
auto operator+(const UnivariateCoefficientBasis<Fr, other_domain_end, other_has_a0_plus_a1>& other) const
{
    constexpr bool preserve = (domain_end == 2 && other_domain_end == 2
                               && has_a0_plus_a1 && other_has_a0_plus_a1);
    UnivariateCoefficientBasis<Fr, domain_end, preserve> res;
    res.coefficients[0] = coefficients[0] + other.coefficients[0];
    res.coefficients[1] = coefficients[1] + other.coefficients[1];
    if constexpr (other_domain_end == 3 && domain_end == 3) {
        res.coefficients[2] = coefficients[2] + other.coefficients[2];
    } else if constexpr (preserve) {
        res.coefficients[2] = coefficients[2] + other.coefficients[2];
    }
    return res;
}
```

Similar changes needed for `operator-`, `operator+=`, `operator-=`. Profiling recommended before applying.

**Aztec:**
Acknowledged.



### `Polynomial::full()` performs unnecessary double-clone


**Description:** [`Polynomial::full()`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.cpp#L242-L247) clones the polynomial's backing memory **twice**. The first clone is immediately discarded by the second:

```cpp
// polynomial.cpp:298
template <typename Fr> Polynomial<Fr> Polynomial<Fr>::full() const
{
    Polynomial result = *this;                                         // ← Clone 1 (wasted)
    result.coefficients_ = _clone(coefficients_, virtual_size() - end_index(), start_index());
                                                                       // ← Clone 2 (the kept one)
    return result;
}
```

`Polynomial` has only one data member: `coefficients_`. So:

1. Line 244 (`Polynomial result = *this;`) invokes the copy constructor, which delegates to [`Polynomial(const Polynomial& other, size_t target_size)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/polynomial.cpp#L108-L113). That constructor calls `_clone(other.coefficients_, 0)` — a full deep copy of all `other.size()` backed elements (allocation + memcpy).

2. Line 246 (`result.coefficients_ = _clone(...)`) calls `_clone` again on the original `this->coefficients_` and assigns the result. This drops the `shared_ptr` to the line 244 allocation (refcount → 0 → `delete[]`) and installs a new allocation.

The line 244 clone's data is never used. Both the allocation and the memcpy that filled it are wasted.

**Impact:** Informational, but the IPA-prover impact is non-trivial.

`full()` is called only once per IPA prove ([`ipa.hpp:182`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/commitment_schemes/ipa/ipa.hpp#L182)) — but on a polynomial sized to the **circuit size**:

| Circuit size `N` | Wasted alloc + memcpy per IPA prove |
|------------------|-------------------------------------|
| 2^{16} (test bench)  | ~2 MB |
| 2^{20} (typical app circuit) | **~32 MB** |
| 2^{28} (`CONST_SIZE_PROOF_LOG_N` upper bound) | **~8 GB** |

For typical UltraHonk circuits, this is **~32 MB of extra alloc + memcpy + free on every IPA prove** — real memory-bandwidth and allocator pressure on a hot prover path. The fix is a one-line change with zero correctness risk.

The author of `full()` routed through `Polynomial result = *this` (itself going through `_clone` via the copy constructor) and then called `_clone` again directly. Each step looks correct in isolation; the duplication is only visible when both calls are traced together.

**Proof of Concept:** Integrated test [`AuditPoC_P48_FullDoubleClone`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/polynomial.test.cpp#L293) in `polynomials/polynomial.test.cpp`. It compares the time taken by `full()` against a baseline single-clone operation (the copy constructor) on the same-size polynomial:

```cpp
TEST(Polynomial, AuditPoC_P48_FullDoubleClone)
{
    using FF = bb::fr;
    using Polynomial = bb::Polynomial<FF>;

    const size_t SIZE = 1 << 16;  // 65536 elements (~2 MB of Fr data)
    auto poly = Polynomial::random(SIZE, SIZE, 0);

    const int ITERATIONS = 100;

    // Time full() — expected to do TWO clones
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        auto result = poly.full();
        (void)result;
    }
    auto t1 = std::chrono::steady_clock::now();
    auto full_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    // Time single-copy via copy constructor — does ONE clone
    auto t2 = std::chrono::steady_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        Polynomial result = poly;
        (void)result;
    }
    auto t3 = std::chrono::steady_clock::now();
    auto single_us = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();

    const double ratio = static_cast<double>(full_us) / static_cast<double>(single_us);
    EXPECT_GT(ratio, 1.3) << "full() should be noticeably slower due to the extra _clone call";
}
```

Observed output on a release build (M-series Mac):

```
P-48: full()         took 7263 us over 100 iterations
P-48: single-copy    took 3001 us over 100 iterations
P-48: ratio = 2.42x (expected ~2x if double-copy is real)
P-48 CONFIRMED: full() does more work than a single copy — consistent with double-clone
```

A ratio of ~2x is empirical proof that `full()` performs two clones. The slight overshoot above 2.0 is consistent with the extra `new`/`delete` pair from the discarded allocation (allocator overhead beyond the pure memcpy cost).

```bash
cd barretenberg/cpp/build && ninja polynomials_tests
./bin/polynomials_tests --gtest_filter="*AuditPoC_P48*"
```

**Recommended Mitigation:** Skip the first clone by constructing `result` empty, then assigning the one clone we actually need:

```cpp
template <typename Fr> Polynomial<Fr> Polynomial<Fr>::full() const
{
    Polynomial result;   // default-constructed, empty (no allocation)
    result.coefficients_ = _clone(coefficients_, virtual_size() - end_index(), start_index());
    return result;
}
```

`Polynomial` has a default constructor (`= default`) that leaves `coefficients_` in a harmless empty `SharedShiftedVirtualZeroesArray` state (default-initialized members, no allocations). The assignment then installs the only clone we actually want.

This eliminates one `new Fr[size]` + one `memcpy(size * sizeof(Fr))` + one `delete[]` per `full()` call. For size-$2^{20}$ polynomials, that's ~32 MB of saved work.

**Aztec:**
Fixed in [27400b6](https://github.com/AztecProtocol/aztec-packages/commit/27400b680b30b6e3333ac34395b279b8c53bfce6).

**Cyfrin:** Verified.


### scalar `operator*=` unnecessarily restricted by `requires(!has_a0_plus_a1)`


**Description:** In [`univariate_coefficient_basis.hpp:232`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L232), `operator*=(const Fr& scalar)` has a `requires(!has_a0_plus_a1)` constraint that prevents it from being called on `(domain_end=2, has_a0_plus_a1=true)` objects:

```cpp
UnivariateCoefficientBasis<Fr, domain_end, false>& operator*=(const Fr& scalar)
    requires(!has_a0_plus_a1)   // ← unnecessarily restrictive
{
    coefficients[0] *= scalar;
    coefficients[1] *= scalar;
    if constexpr (domain_end == 3) {
        coefficients[2] *= scalar;
    }
    return *this;
}
```

Unlike `operator+=` and `operator-=` with scalars — where the constraint IS necessary because adding/subtracting a scalar changes `a₀` without changing `a₁`, invalidating the precomputed `a₀ + a₁` — scalar multiplication scales all coefficients uniformly:

```
Before: a₀, a₁, (a₀ + a₁)
After:  s·a₀, s·a₁, s·(a₀ + a₁) = s·a₀ + s·a₁  ← still valid!
```

Comparison of scalar operators:

| Operator | `requires(!has_a0_plus_a1)` justified? | Reason |
|----------|----------------------------------------|--------|
| [`operator+=(scalar)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L219) | **Yes** | `a₀` changes, `a₁` doesn't → `a₀+a₁` invalidated |
| [`operator-=(scalar)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L226) | **Yes** | Same as above |
| [`operator*=(scalar)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L232) | **No** | All terms scale by `s` → `s·(a₀+a₁)` still valid |

The same issue applies to the non-in-place [`operator*(const Fr& scalar)`](https://github.com/AztecProtocol/aztec-packages/blob/main/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.hpp#L257) which returns `has_a0_plus_a1=false` and does not scale `coefficients[2]`.

**Impact:** Informational. This is a conservative design choice that simplifies the type system. The performance impact is the same as [issue-22](https://github.com/AztecProtocol/aztec-packages/issues/22): downstream `operator*` falls into a more expensive Karatsuba branch when the precomputation has been discarded.

**Proof of Concept:** Measured benchmark:

Integrated benchmark [`AuditPoC.P34_KaratsubaTTvsFFBranch`](https://github.com/AztecProtocol/aztec-packages/blob/audit/qpzm/barretenberg/cpp/src/barretenberg/polynomials/univariate_coefficient_basis.test.cpp#L65) in `polynomials/univariate_coefficient_basis.test.cpp`. The test directly compares the cost of the (T,T) Karatsuba branch (which P-34 unlocks downstream) against the (F,F) branch (which the current code is forced into after a scalar `*=` strips the precomputation):

```cpp
TEST(AuditPoC, P34_KaratsubaTTvsFFBranch)
{
    constexpr size_t N = 200000;
    std::vector<UnivariateCoefficientBasis<fr, 2, true>>  lhs_T(N), rhs_T(N);
    std::vector<UnivariateCoefficientBasis<fr, 2, false>> lhs_F(N), rhs_F(N);
    // ... fill both representations with the same random (a0, a1) / (b0, b1)
    //     — the (2, true) copies additionally set coefficients[2] = a0 + a1.

    // (T, T) — the cheap branch P-34 would unlock by removing the `requires` gate.
    auto t0 = high_resolution_clock::now();
    for (size_t i = 0; i < N; ++i) {
        auto r = lhs_T[i] * rhs_T[i];     // (T, T) Karatsuba branch
    }
    auto t1 = high_resolution_clock::now();

    // (F, F) — what the current code is forced into once a scalar `*=` strips the flag.
    for (size_t i = 0; i < N; ++i) {
        auto r = lhs_F[i] * rhs_F[i];     // (F, F) Karatsuba branch
    }
    auto t2 = high_resolution_clock::now();
}
```

```
P-34 N=200000:  (T,T) Karatsuba = 25.6 ns/op   (F,F) Karatsuba = 29.7 ns/op   (F,F) overhead = 13.7%
```

Per-multiplication cost difference: ~4 ns (one extra field addition). The 13.7% overhead is the upper bound on what the P-34 fix would save for any multiplication chain that currently goes through (F,F) because of an intervening scalar `*=`.

**Recommended Mitigation:** Remove the `requires` constraint and preserve `has_a0_plus_a1`:

```diff
- UnivariateCoefficientBasis<Fr, domain_end, false>& operator*=(const Fr& scalar)
-     requires(!has_a0_plus_a1)
+ UnivariateCoefficientBasis& operator*=(const Fr& scalar)
  {
      coefficients[0] *= scalar;
      coefficients[1] *= scalar;
      if constexpr (domain_end == 3) {
          coefficients[2] *= scalar;
+     } else if constexpr (has_a0_plus_a1) {
+         coefficients[2] *= scalar;  // preserve a₀+a₁ precomputation
      }
      return *this;
  }
```

**Aztec:**
Acknowledged.

\clearpage