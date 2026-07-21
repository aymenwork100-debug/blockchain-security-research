## Remote Deterministic Process Termination in ECDSA-2PC Signing Due to Missing Paillier Ciphertext Validation (Release Build)



📌Program

Coinbase Bug Bounty – cb-mpc Open Source Repository: https://github.com/coinbase/cb-mpc
Commit tested: cb60753220d07cb2bd9aa2e3c4fdd467d5b6024f

================================================================================

### Summary

A malformed Paillier ciphertext sent by a malicious MPC participant can deterministically reach paillier_t::decrypt() in the ECDSA-2PC signing path without prior validation via verify_cipher().

In Release builds (-O3 -DNDEBUG), this triggers a fatal cb_assert() leading to:

- std::terminate()
- SIGABRT
- Exit code 134
- Immediate termination of the signing process

This occurs in production Release configuration and is reachable via protocol-controlled input.

This results in a reliable remote denial-of-service of the ECDSA-2PC signing worker.

### Threat Model

The attacker is a malicious or compromised MPC participant within the ECDSA-2PC protocol.

In standard MPC security models, one or more participating parties may behave adversarially. Protocol implementations are therefore expected to safely reject malformed, unexpected, or malicious protocol messages received over the network.

In this case, a remote participant can send a malformed Paillier ciphertext that is forwarded into paillier_t::decrypt() without prior validation via verify_cipher().

Because decrypt() performs fatal cb_assert() checks that remain active in Release builds, attacker-controlled input deterministically triggers process termination (SIGABRT).

This does not require:

- Local system access

- Memory corruption

- Undefined behavior

- Exploitation of undefined C++ semantics

The vulnerability exists entirely within the defined adversarial model of MPC, where malicious protocol participants must be anticipated and handled safely.

Instead of rejecting invalid ciphertext with a structured error, the implementation aborts the signing process, resulting in remote denial-of-service.

================================================================================

### Root Cause

In ecdsa_2p.cpp:

bn_t s = key.paillier.decrypt(c[i]);

The helper function:

error_t verify_cipher(const bn_t& cipher);

exists but is not invoked before decryption.

Inside paillier_t::decrypt():

cb_assert(src > 0 && src < NN);
cb_assert(mod_t::coprime(src, N));

Malformed ciphertext triggers fatal assertion → abort.

Instead of returning structured error, the process terminates.

================================================================================

### Reachability

Public entry: ecdsa_2p.h → sign_batch(...)

Attacker-controlled input: ecdsa_2p.cpp: job.p2_to_p1(c)

Network receive path: mpc_job.h → send_receive_message()

Sink: ecdsa_2p.cpp → key.paillier.decrypt(c[i])

This is reachable via protocol message from a remote MPC participant.

================================================================================

### Release Build Confirmation

CMAKE_CXX_FLAGS_RELEASE = -O3 -DNDEBUG

- cb_assert is not compiled out under NDEBUG
- Crash reproduced in Release

Observed output:

[ASSERTION FAILED] src > 0 && src < NN
terminate called after throwing 'coinbase::assertion_failed_t'
SIGABRT
Exit code: 134

Repeated runs confirm deterministic behavior.

================================================================================

### Reproduction Steps

git checkout cb60753220d07cb2bd9aa2e3c4fdd467d5b6024f
rm -rf build/Release
mkdir -p build/Release
cd build/Release
cmake -DCMAKE_BUILD_TYPE=Release ../..
cmake --build . --target test_paillier_abort -j
cd ../..

./build/Release/bin/Release/test_paillier_abort
echo $?

Expected: Exit code 134 SIGABRT

================================================================================

### Why This Is Security-Relevant

Cryptographic signing services protecting digital assets must:

- Safely reject malformed adversarial inputs
- Never terminate due to attacker-controlled protocol messages

The presence of verify_cipher() indicates malformed ciphertext handling is expected in the threat model.

Failure to invoke it in the signing path allows attacker-triggered termination.

================================================================================

### Recommended Fix

Validate before decrypt:

if (auto rv = key.paillier.verify_cipher(c[i])) {
  return coinbase::error(rv, "invalid Paillier ciphertext");
  }
  bn_t s = key.paillier.decrypt(c[i]);

  Additionally:

  - Avoid fatal assertions in adversarial input paths
  - Replace abort behavior with structured error handling

  ================================================================================

  #### Final Severity Assessment

  Severity Justification
  This aligns with High-severity issues under the cb-mpc classification because:

  - Remote trigger
  - Deterministic
  - Affects high-level ECDSA-2PC signing protocol
  - Reproducible in Release builds
  - No mitigating validation in current code path
  - Direct impact on signing service availability

  ================================================================================

  ## Impact

  Availability Impact (Primary Severity Basis)

  - Triggered by protocol-controlled input from a malicious participant.
  - Requires no memory corruption or undefined behavior.
  - Works in Release builds.
  - Deterministic and repeatable.
  - Affects high-level cryptographic signing logic (ecdsa_2p).
  - A single malformed ciphertext is sufficient to terminate the signer process.

  In typical worker-based deployments, this would:

  - Kill the signing worker process
  - Fail in-flight signing requests
  - Allow repeated crash-triggering for sustained disruption

  This affects a high-level signing protocol and represents a deterministic, attacker-triggerable availability failure in Release builds.

  Threat Model Clarification

  - In MPC systems, malicious participants are explicitly within the adversary model.
  - Protocol implementations must reject adversarial messages gracefully.
  - Attacker-controlled protocol input must never trigger process termination in key-handling cryptographic code.
  - This is a robustness failure in a high-level signing protocol.

  This is a remote, attacker-triggerable denial-of-service condition affecting a high-level cryptographic signing primitive.
  
