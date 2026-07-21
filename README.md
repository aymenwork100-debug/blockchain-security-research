# Smart Contract Vulnerability Research

A curated collection of smart contract vulnerability disclosures, including full technical reports and Proof of Concept (PoC) exploits. Each finding was independently discovered, analyzed, and validated.

---

## Vulnerability Index

| # | Title | Target | Category | Severity |
|---|-------|--------|----------|----------|
| 1 | [Critical Privilege Escalation via Session-Based Execution](./01-OKX-WalletCore-Privilege-Escalation/README.md) | OKX Wallet Core | Privilege Escalation / Authorization Boundary Violation | 🔴 Critical |

---

## Repository Structure

```
smart-contract-vulnerabilities/
└── 01-OKX-WalletCore-Privilege-Escalation/
    ├── README.md        # Full vulnerability report
    └── PoC.t.sol        # Foundry test — Proof of Concept
```

---

## Methodology

Each entry in this repository follows a consistent structure:

- **Report** — Full technical write-up including root cause, impact analysis, exploit flow, and remediation recommendations.
- **PoC** — A self-contained, deterministic, and reproducible test demonstrating the vulnerability.

---

## Additional Case Studies

- [LayerZero EndpointV2 Grace-Period Verification State Replacement](findings/layerzero-grace-overwrite)
  - Area: Cross-chain protocol security
  - Evidence: Foundry mainnet-fork PoC
  - Result: 13 passing fork-production tests
  - Primary evidence: 3 focused tests
