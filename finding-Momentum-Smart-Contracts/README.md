# Momentum Smart Contracts — Uninitialized Pool Phantom Liquidity Drain

## Target
https://github.com/hackenproof-public/mmt-v3-core

**Type:** Smart Contract

## Vulnerability Details

- **Severity:** Critical
- **Component:** mmt_v3::pool, mmt_v3::liquidity, mmt_v3::liquidity_math
- **Affected Functions:** pool::initialize, liquidity::add_liquidity, pool::add_liquidity, liquidity_math::get_liquidity_for_amounts
- **Attack Type:** Phantom liquidity / direct fund theft from LP reserves

### Description

mmt_v3::pool::initialize is the only function that enforces pool.sqrt_price == 0 as a one-shot guard. No other public entrypoint asserts that the pool has been initialized before mutating its state. In particular, liquidity::add_liquidity and the underlying pool::add_liquidity accept calls while sqrt_price == 0.

When current_sqrt_price = 0, liquidity_math::get_liquidity_for_amounts (liquidity_math.move:172-175) takes the current <= sqrt_lower branch:

```move
if (sqrt_price_current <= sqrt_price_lower) {
    get_liquidity_for_amount_x(sqrt_price_lower, sqrt_price_upper, amount_x)
}
```

This branch prices the deposit as out-of-range below — only amount_x is consumed, amount_y is silently ignored. The depositor mints liquidity L while paying zero of token Y.

A malicious creator can then call pool::initialize with a sqrt_price chosen to fall inside the position's tick range. The position becomes retroactively in-range under the new sqrt_price, and the attacker now holds an LP position whose position.liquidity = L > 0 while the pool's reserve_y is still zero.

Once the pool is shared, any honest LP who subsequently provides liquidity at a normal in-range position deposits both X and Y proportional to the (forged) sqrt_price. The attacker then calls liquidity::remove_liquidity. pool::update_data_for_delta_l computes the withdrawal as (amount_x, amount_y) priced at the new in-range sqrt_price, and take_from_reserves ships both tokens out of the reserves. The amount_y paid out is sourced entirely from the victim LP's deposit, because no other source of Y exists in the pool.

This is direct, reproducible fund theft. In an asymmetric token-pair scenario where the attacker controls a worthless token X (e.g., a self-issued junk token) paired with a valuable token Y (e.g., USDC), the attacker walks out with the victim's USDC while only "losing" tokens that have zero real-world value to them.

The empty-observations abort that protects in-range deposits at uninitialized pools is sidestepped trivially by choosing the malicious position's tick range to be entirely above (or below) the default tick_index = 0. This skips the oracle::write call in pool::update_data_for_delta_l's active-branch.

The bug additionally leaves the pool in an inconsistent state where pool.liquidity becomes lower than the legitimate LP's position.liquidity after the attacker's extraction, which subsequently reverts that LP's full-redemption remove_liquidity call and locks a portion of their deposit indefinitely.

### Impact

This vulnerability falls squarely within the program's primary in-scope category ('Stealing or loss of funds' and 'Attacks on logic'). The PoC is fully runnable via a single sui move test command against unmodified main source, with deterministic conservation assertions that mathematically prove a 1:1 token transfer from victim to attacker. Impact scales linearly with deposit size; the demonstrated $983,120 extraction at 98.3% capture rate applies identically to any LP — including automated vaults and aggregator integrations — that interacts with a maliciously-prepared shared pool.

Direct theft of LP-provided tokens. An attacker creates and weaponizes a pool with a worthless token X, then drains valuable token Y (e.g., USDC, USDT, SUI) from any honest LP that adds liquidity to that pool.

Empirically verified PoC numbers (asymmetric scenario, single $1,000,000 victim deposit):

| Account | Token | Paid (raw) | Received (raw) | Net (raw) | USD Value |
|---|---|---|---|---|---|
| Attacker | Junk X | 1,000,000,000,000 | 22,173,370,812 | -977,826,629,188 | $0 (worthless) |
| Attacker | USDC | 0 | 983,120,909,968 | +983,120,909,968 | +$983,120 |
| Victim (Bob) | Junk X | 247,599,220,871 | (locked) | (locked) | $0 |
| Victim (Bob) | USDC | 1,000,000,000,000 | 16,879,090,032 | -983,120,909,968 | -$983,120 |

**Conservation:** the attacker's USDC gain equals the victim's USDC loss to within 1 wei — a clean 1-to-1 token transfer. Asserted in the PoC (diff <= 1)

**Profit ratio:** the attacker keeps 98.3% of the victim's USDC deposit, with the remainder landing in pool reserves as stranded Y unredeemable by anyone.

**Scaling:** profit scales linearly with victim deposit size and is bounded only by max_liquidity_per_tick ≈ 7.7 × 10³² (orders of magnitude beyond any realistic pool). For a $100M victim deposit, the same attack produces ≈ $98.3M stolen USDC. For a 1B USDC TVL pool, ≈ $983M

**Secondary impact:** even when the victim attempts to recover their position, pool::update_data_for_delta_l reverts on add_delta(pool.liquidity, -L_victim) because pool.liquidity has been reduced by the attacker's phantom L. The victim can only redeem partially (≈ 1.6% of their original deposit in the demonstrated PoC), with the remainder stranded as pool-locked liquidity that no LP can claim.

**Privilege required:** none. Anyone can call create_pool::new, pool::initialize, liquidity::open_position, liquidity::add_liquidity, pool::transfer. The full attack runs in a single PTB by the attacker followed by ordinary LP behavior from the victim.

### Mitigation

The bug has a single-line fix. Add an initialization check at the top of liquidity::add_liquidity in clmm/sources/actions/liquidity.move:

```rust
public fun add_liquidity<X, Y>(
    pool: &mut Pool<X, Y>,
    position: &mut Position,
    coin_x: Coin<X>,
    coin_y: Coin<Y>,
    min_amount_x: u64,
    min_amount_y: u64,
    clock: &Clock,
    version: &Version,
    ctx: &mut TxContext,
): (Coin<X>, Coin<Y>) {
    version::assert_supported_version(version);
    pool::assert_not_pause(pool);
+   assert!(pool::sqrt_price(pool) != 0, error::pool_not_initialised());
    mmt_v3::tick::check_tick_range(...);
    ...
}
```

The error::pool_not_initialised() code (= 31) already exists at clmm/sources/error.move:65; only mmt_v3::trade::validate_sqrt_price_limit (trade.move:847) currently uses it. Extending the same guard to the liquidity provisioning path closes the entire phantom-liquidity attack class.

### Defense-in-depth Recommendations

1. Apply the same guard in liquidity::open_position. Position creation against an uninitialized pool has no legitimate purpose and is a useful denial-by-design.

2. Atomicize creation + initialization + share in create_pool. Modify create_pool::new to require an initial sqrt_price argument and call pool::initialize before returning the pool. This makes it impossible for any caller (malicious or buggy) to ever expose an uninitialized pool to other PTBs in the first place. Concretely:

```move
public fun new_and_initialize<X, Y>(
    global_config: &mut GlobalConfig,
    fee_rate: u64,
    initial_sqrt_price: u128,
    clock: &Clock,
    version: &Version,
    ctx: &mut TxContext,
): Pool<X, Y> {
    let mut pool = create_pool_internal<X, Y>(global_config, fee_rate, version, ctx);
    pool::initialize(&mut pool, initial_sqrt_price, clock);
    pool
}
```

3. Add an invariant test: after every liquidity-mutating function, assert that pool.liquidity is consistent with the sum of in-range position.liquidity. This would have caught the bug at unit-test time.

### Why the Simple Fix Is Sufficient

The attack relies on calling add_liquidity while pool.sqrt_price == 0. Adding assert!(pool::sqrt_price(pool) != 0) to add_liquidity means:

- The malicious flow create_pool → add_liquidity (X-only) reverts at step 2
- An attacker cannot mint phantom L without first initializing the pool.
- After legitimate initialization, get_liquidity_for_amounts correctly prices any deposit, and the standard V3 floor-L/ceil-amount asymmetry favors the pool — eliminating the entire attack surface.

The pool::initialize function itself does not need to change; its sqrt_price == 0 precondition remains the correct one-shot guard for initialization itself.

## Validation Steps

### Steps to Reproduce

Attacker constructs a single PTB:

a. create_pool::new<X, Y>(global_config, fee_rate, version, ctx) — returns an uninitialized pool with sqrt_price = 0, tick_index = 0.

b. liquidity::open_position(pool, lower=10, upper=100, version, ctx) — opens a position whose tick range is strictly above the default tick_index = 0. This is essential: it makes the position out-of-range at the time of deposit so the active-branch in update_data_for_delta_l (and its dependent oracle::write call on empty observations) is skipped.

c. liquidity::add_liquidity(pool, position, coin_x = N units of junk X, coin_y = zero, ...). With current_sqrt_price = 0, get_liquidity_for_amounts takes the X-only branch and credits position.liquidity = L while consuming zero Y.

d. pool::initialize(pool, sqrt_price_at_tick_98, clock) — chosen to fall inside [10, 100]. The assert!(pool.sqrt_price == 0) passes; the pool is now initialized. The attacker's position is retroactively in-range. Tick 98 is chosen to maximize the eventual amount_y extraction (formula: amount_y_remove = L * (sqrt_98 - sqrt_10) / Q).

e. pool::transfer(pool) — share the now-malformed pool.

Victim Bob, in a separate transaction, sees a normal-looking shared pool with sqrt_price > 0, opens a position at [90, 100], and calls liquidity::add_liquidity with $1,000,000 USDC plus matching junk X.

Attacker, in another transaction, calls liquidity::remove_liquidity(pool, attacker_position, attacker_l, 0, 0, ...). update_data_for_delta_l computes amount_y based on L and the in-range sqrt_price. take_from_reserves ships the USDC out of reserve_y to the attacker. Attacker walks away with $983,120 USDC.

### Proof of Concept

The poc : I will leave the complete poc with the attachments with results.

Two passing tests:

- uninit_pool_phantom_liquidity_drain — same-decimals-pair drain (confirms mechanic; demonstrates 44.6 B raw Y stolen plus 22.28 T units of victim liquidity locked).
- asymmetric_pair_junk_x_vs_usdc_drain — junk-X vs USDC scenario yielding $983,120 net attacker profit at zero real cost.

### Expected Results

(I'll leave a screenshot showing the output)

Run commande:

```bash
cd clmm && sui move test --silence-warnings asymmetric_pair_junk_x_vs_usdc_drain
```

The conservation check (bob_y_loss == attacker_received_y within 1 wei) is asserted by the test and passes. The attacker's $983,120 profit equals the victim's $983,120 loss exactly. There is no ambiguity, rounding, or simulation artifact.
