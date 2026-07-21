# Blockchain Security Research

A curated collection of blockchain and smart contract security research, including technical vulnerability reports, exploit analysis, and reproducible Proof of Concept (PoC) demonstrations.

The repository focuses primarily on high-impact security failures involving authorization boundaries, cross-chain verification, asset safety, cryptographic protocols, and protocol-level invariants.

---

## Security Findings

| # | Finding | Target | Security Area | Evidence |
|---|---|---|---|---|
| 01 | [LayerZero Grace-Period Verification State Overwrite](finding/01-LayerZero-Grace-Overwrite/) | LayerZero V2 | Cross-chain verification / Messaging | Mainnet-fork PoCs |
| 02 | [WalletCore Privilege Escalation](finding/02-OKX-WalletCore-Privilege-Escalation/) | OKX Wallet Core | Authorization / Privilege Escalation | Reproducible PoC |
| 03 | [TSS Signature Replay](finding/03-ZetaChain-TSS-Signature-Replay/) | ZetaChain | TSS / Signature Security | Technical analysis |
| 04 | [Post-Expiry ERC20 Fund Drain](finding/04-OKX-Post-Expiry-ERC20-Fund-Drain/) | OKX | Authorization / Asset Safety | Technical report |
| 05 | [Paillier Ciphertext Validation DoS](finding/05-Coinbase-cbmpc-Paillier-DoS/) | Coinbase cb-mpc | MPC / Cryptographic Protocol Security | Release-build C++ PoC |
| 06 | [Momentum Smart Contracts Security Finding](finding/06-Momentum-Smart-Contracts/) | Momentum | Smart Contract Security | Technical report |

---

## Repository Structure

```text
blockchain-security-research/
│
├── finding/
│   ├── 01-LayerZero-Grace-Overwrite/
│   ├── 02-OKX-WalletCore-Privilege-Escalation/
│   ├── 03-ZetaChain-TSS-Signature-Replay/
│   ├── 04-OKX-Post-Expiry-ERC20-Fund-Drain/
│   ├── 05-Coinbase-cbmpc-Paillier-DoS/
│   └── 06-Momentum-Smart-Contracts/
│
├── methodology/
├── case-studies/
├── poc-templates/
└── README.md

Each finding directory contains the available supporting material for that investigation, which may include:

Full technical vulnerability report
Root-cause analysis
Attack or exploit flow
Proof of Concept source code
Reproduction instructions
Execution output or supporting evidence
Remediation recommendations
Selected Research Highlights
LayerZero V2 — Grace-Period Verification State Overwrite

Research into LayerZero V2 messaging verification behavior during receive-library migration and grace-period handling.

The investigation includes production-oriented Foundry mainnet-fork testing and focused exploit-path validation around verification state replacement.

Evidence: 13 passing fork-production tests, including 3 focused production-path tests.

View research →

OKX Wallet Core — Privilege Escalation

Analysis of an authorization-boundary failure involving session-based execution and privileged wallet operations.

The finding includes a technical report and reproducible Proof of Concept demonstrating the vulnerable execution path.

View finding →

ZetaChain — TSS Signature Replay

Security research covering replay behavior and signature-validation assumptions in a threshold-signature environment.

View finding →

OKX — Post-Expiry ERC20 Fund Drain

Analysis of a post-expiry authorization condition affecting ERC20 asset safety.

View finding →

Coinbase cb-mpc — Paillier Ciphertext Validation DoS

A malformed Paillier ciphertext can reach a fatal assertion in the cryptographic decryption path when processed without prior ciphertext validation.

The included standalone Release-build PoC deterministically demonstrates process termination through:

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

The report separately documents the protocol-level reachability analysis through the ECDSA-2PC signing path.

View finding →

Momentum Smart Contracts

Technical smart contract security research covering the identified vulnerability and its underlying protocol behavior.

View finding →

Research Methodology

My security research follows an invariant-driven and exploitability-focused process:

Reconstruct the protocol architecture and trust boundaries.
Identify security-critical state transitions and economic invariants.
Trace attacker-controlled input to sensitive execution paths.
Attempt to falsify each hypothesis before treating it as a finding.
Build deterministic PoCs whenever practical.
Validate realistic exploit paths against production-like environments when possible.
Document both exploitability and important limiting conditions.

The primary research focus is on vulnerabilities that can lead to:

Unauthorized asset movement
Privilege escalation
Cross-chain verification failures
Signature or message replay
Creation of unbacked value
Double redemption
Protocol insolvency
Permanent loss of funds
Security-critical cryptographic protocol failures
Disclaimer

This repository is maintained for defensive security research, technical education, and professional portfolio purposes.

The presence of a report in this repository does not imply that a vendor accepted the reported severity or classification unless explicitly stated in the corresponding finding.

No private keys, confidential vendor information, or non-public production credentials are included.

