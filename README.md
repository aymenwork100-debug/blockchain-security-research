# Blockchain Security Research

A curated collection of blockchain and smart contract security research, including technical vulnerability reports, exploit analysis, and reproducible Proof of Concept (PoC) demonstrations.

The repository focuses primarily on high-impact security failures involving authorization boundaries, cross-chain verification, asset safety, cryptographic protocols, and protocol-level invariants.

---

## Security Findings

| # | Finding | Target | Security Area | Evidence |
|---|---|---|---|---|
| 01 | [LayerZero Grace-Period Verification State Overwrite](finding/01-LayerZero-Grace-Overwrite/) | LayerZero V2 | Cross-chain Verification | Mainnet-fork PoC |
| 02 | [WalletCore Privilege Escalation](finding/02-OKX-WalletCore-Privilege-Escalation/) | OKX Wallet Core | Authorization / Privilege Escalation | Foundry PoC |
| 03 | [TSS Signature Replay](finding/03-ZetaChain-TSS-Signature-Replay/) | ZetaChain | TSS / Signature Security | Go & Rust PoCs |
| 04 | [Post-Expiry ERC20 Fund Drain](finding/04-OKX-Post-Expiry-ERC20-Fund-Drain/) | OKX Wallet Core | Authorization / Asset Safety | Foundry PoCs |
| 05 | [Paillier Ciphertext Validation DoS](finding/05-Coinbase-cbmpc-Paillier-DoS/) | Coinbase cb-mpc | MPC / Cryptographic Protocol Security | Release-build C++ PoC |
| 06 | [Uninitialized Pool Phantom Liquidity Drain](finding/06-Momentum-Smart-Contracts/) | Momentum | Move Smart Contract Security | Move PoC |

---

## Repository Structure

```text
blockchain-security-research/
│
├── finding/
│   │
│   ├── 01-LayerZero-Grace-Overwrite/
│   │   ├── README.md
│   │   ├── report.md
│   │   └── poc/
│   │       ├── Fork_Production_GraceOverwrite.t.sol
│   │       └── PRIMARY_TESTS.md
│   │
│   ├── 02-OKX-WalletCore-Privilege-Escalation/
│   │   ├── README.md
│   │   ├── PoC.t.sol
│   │   └── assets/
│   │       └── poc-test-output.png
│   │
│   ├── 03-ZetaChain-TSS-Signature-Replay/
│   │   ├── README.md
│   │   └── poc/
│   │       ├── .test-ouput1.png
│   │       ├── gateway_message_ambiguity_test.go
│   │       ├── gateway_message_cross_type_test.go
│   │       ├── test-output2.png
│   │       └── validate_message_hash_collision.rs
│   │
│   ├── 04-OKX-Post-Expiry-ERC20-Fund-Drain/
│   │   ├── README.md
│   │   └── poc/
│   │       ├── ExecutorLogic.sol
│   │       ├── SessionApproveMax_PostExpiryDrain.t.sol
│   │       ├── SessionApproveMax_PostExpiryDrain_Revocation.t.sol
│   │       ├── test-output-post-expiry-drain.png
│   │       └── test-output-revocation.png
│   │
│   ├── 05-Coinbase-cbmpc-Paillier-DoS/
│   │   ├── README.md
│   │   ├── test_paillier_abort.cpp
│   │   └── poc output.png
│   │
│   └── 06-Momentum-Smart-Contracts/
│       ├── README.md
│       └── poc/
│           ├── poc_uninit_pool_test.move
│           └── poc-test-output.png
│
└── README.md
```

---

## Selected Research Highlights

### 01 — LayerZero V2: Grace-Period Verification State Overwrite

Research into LayerZero V2 messaging verification behavior during receive-library migration and grace-period handling.

The investigation includes production-oriented Foundry mainnet-fork testing and focused exploit-path validation around verification state replacement.

**Evidence:** 13 passing fork-production tests, including 3 focused production-path tests.

**[View full research →](finding/01-LayerZero-Grace-Overwrite/)**

**[View technical report →](finding/01-LayerZero-Grace-Overwrite/report.md)**

**[View primary PoC tests →](finding/01-LayerZero-Grace-Overwrite/poc/PRIMARY_TESTS.md)**

---

### 02 — OKX Wallet Core: Privilege Escalation

Analysis of an authorization-boundary failure involving session-based execution and privileged wallet operations.

The finding includes a technical report and reproducible Foundry Proof of Concept demonstrating the vulnerable execution path.

**[View finding →](finding/02-OKX-WalletCore-Privilege-Escalation/)**

**[View PoC →](finding/02-OKX-WalletCore-Privilege-Escalation/PoC.t.sol)**

---

### 03 — ZetaChain: TSS Signature Replay

Security research covering signature replay behavior and hash-preimage ambiguity in the Solana Gateway message-validation flow.

The finding includes Go and Rust Proof of Concept implementations covering the relevant message-hashing behavior.

**[View finding →](finding/03-ZetaChain-TSS-Signature-Replay/)**

**[View PoCs →](finding/03-ZetaChain-TSS-Signature-Replay/poc/)**

---

### 04 — OKX Wallet Core: Post-Expiry ERC20 Fund Drain

Analysis of persistent ERC20 approval behavior across session expiry and revocation boundaries.

The research includes focused Foundry tests covering post-expiry and post-revocation execution scenarios.

**[View finding →](finding/04-OKX-Post-Expiry-ERC20-Fund-Drain/)**

**[View PoCs →](finding/04-OKX-Post-Expiry-ERC20-Fund-Drain/poc/)**

---

### 05 — Coinbase cb-mpc: Paillier Ciphertext Validation DoS

A malformed Paillier ciphertext can reach a fatal assertion in the cryptographic decryption path when processed without prior ciphertext validation.

The included standalone Release-build PoC deterministically demonstrates:

```text
Malformed ciphertext
        ↓
paillier_t::decrypt()
        ↓
cb_assert failure
        ↓
std::terminate()
        ↓
SIGABRT
        ↓
Exit code 134
```

The report separately documents the protocol-level reachability analysis through the ECDSA-2PC signing path.

**[View finding →](finding/05-Coinbase-cbmpc-Paillier-DoS/)**

**[View C++ PoC →](finding/05-Coinbase-cbmpc-Paillier-DoS/test_paillier_abort.cpp)**

---

### 06 — Momentum Smart Contracts: Uninitialized Pool Phantom Liquidity Drain

Security research into uninitialized pool state and phantom liquidity behavior in Momentum smart contracts.

The finding includes a Move-based Proof of Concept and execution evidence.

**[View finding →](finding/06-Momentum-Smart-Contracts/)**

**[View PoC directory →](finding/06-Momentum-Smart-Contracts/poc/)**

---

## Research Methodology

My security research follows an invariant-driven and exploitability-focused process:

1. Reconstruct the protocol architecture and trust boundaries.
2. Identify security-critical state transitions and economic invariants.
3. Trace attacker-controlled input to sensitive execution paths.
4. Attempt to falsify each hypothesis before treating it as a finding.
5. Build deterministic PoCs whenever practical.
6. Validate realistic exploit paths against production-like environments when possible.
7. Document both exploitability and important limiting conditions.

The primary research focus is on vulnerabilities that can lead to:

- Unauthorized asset movement
- Privilege escalation
- Cross-chain verification failures
- Signature or message replay
- Creation of unbacked value
- Double redemption
- Protocol insolvency
- Permanent loss of funds
- Security-critical cryptographic protocol failures

---
