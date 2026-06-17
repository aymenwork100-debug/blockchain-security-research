# Critical Privilege Escalation via Session-Based Execution

**Target:** OKX Wallet Core (Web3 Smart Account Authorization Layer)
**Category:** Privilege Escalation / Authorization Boundary Violation
**Severity:** 🔴 Critical

---

## Affected Component / Deployment Context

WalletCore represents the authorization and execution layer used by OKX Web3 smart account wallets. The issue exists at the contract logic level and affects any deployed instance where session-based execution is enabled, independent of UI or user configuration.

---

## Summary

A temporary session authorization can be abused to permanently add a validator to the wallet, enabling post-expiry fund theft without any active session or further user consent.

This breaks a fundamental security invariant of session-based authorization:

> ⚠️ **Temporary authority must never result in permanent control.**

The issue allows an attacker to escalate privileges during a valid session window and retain full wallet control indefinitely after the session expires.

---

## Impact

An attacker can:
- Gain permanent validator access using a time-limited session
- Retain wallet control after session expiry
- Drain wallet funds without using the session
- Maintain a persistent backdoor (validator persistence)

**Security consequences:**
- Post-expiry theft of user funds
- Persistent wallet compromise
- Collapse of session security guarantees
- Loss of user trust in session-based authorization

**Important notes:**
- ✅ No private keys are leaked
- ✅ No cryptographic primitives are broken
- ✅ The exploit uses valid signatures in an unintended authorization context

This is a **post-expiry theft scenario with permanent impact**.

---

## Realistic Attack Scenario

A user authorizes a short-lived session for a dApp or automation bot.

During the session, the dApp adds itself as a validator and retains full wallet control even after the session expires, enabling **silent post-expiry fund theft**.

### Business Impact

This issue represents a systemic failure of the wallet's trust and authorization model, rather than a one-off execution flaw.

**User & Platform Consequences**

Because the compromise persists beyond the lifetime of any authorized session, users lose the ability to reliably reason about the security state of their wallet. A session that is expected to expire and revoke access instead leaves behind a latent, irreversible compromise. As a result:
- Wallet compromise may occur long after the original session interaction, increasing stealth and reducing detectability
- Users may continue using the wallet under the false assumption that all temporary access has been revoked
- Asset loss may appear unexplained, delayed, or disconnected from any recent user action

**Impact on Security Guarantees**

Session-based authorization is intended to provide temporary, scoped, and revocable access. Allowing such access to permanently modify trust roots undermines this guarantee at a foundational level. This breaks the core safety property that session expiry is sufficient to restore security, and invalidates the threat model assumed by both users and integrators relying on session isolation.

**Operational & Reputational Risk**

From a platform perspective, this class of issue introduces:
- Increased support and incident-response burden due to delayed and non-obvious compromise
- Difficulty in attributing asset loss to a specific user action or consent event
- Elevated reputational and compliance risk resulting from silent, persistent wallet compromise

---

## Root Cause

The wallet allows `executeFromExecutor()` (session-based execution) to perform arbitrary internal calls via `_batchCall()`, **including governance functions such as `addValidator()`**.

As a result:
- Privileged functions protected by `onlySelf` can be invoked during a session
- Session execution is time-bounded
- Validator state mutation is permanent and unbounded

The session signature:
- ✅ Is time-limited (`validUntil`)
- ❌ Is **not** restricted from mutating permanent authorization state
- ❌ Does **not** distinguish between temporary execution and permanent privilege changes

This allows a temporary executor to permanently modify wallet trust state.

---

## Design-Level Contradiction

In the OKX Wallet authorization model, **validators** represent root, long-lived trust anchors, while **sessions** are explicitly implemented as temporary, time-bounded execution permissions.

Allowing a session executor to permanently mutate validator state collapses this distinction.

If a time-bounded session is allowed to grant permanent validator authority, then:
- Session expiry no longer revokes the effective privileges granted
- Sessions become equivalent to permanent private keys
- The security guarantees of session-based access control are nullified by design

This is not a matter of user intent or signature scope, but a **violation of the wallet's internal authorization separation** between temporary execution and permanent trust roots.

---

## Exploit Flow (Verified)

1. User signs a temporary session authorization
2. Attacker uses the session to call `addValidator()`
3. Session expires
4. Session execution is correctly rejected after expiry
5. The added validator persists permanently
6. Attacker drains wallet funds after expiry **without using the session**

---

## Proof of Concept

**Test file:** `PoC.t.sol`

**Result:** `[PASS] test_PostExpiryTheft_HardenedEvidence()`

**Key Runtime Evidence:**
- Session expires at: `3601`
- Current block time: `3602`
- Session execution correctly reverts after expiry
- Validator persists after expiry
- Funds drained after expiry without session usage

![PoC Test Output](./assets/poc-test-output.png)

This demonstrates:
- ✅ Session expiry is enforced
- ✅ Privilege escalation persists beyond expiry
- ✅ Theft occurs without an active session

The PoC is deterministic, self-contained, and reproducible. See [`PoC.t.sol`](./PoC.t.sol) for the full test.

---

## Reproduction Steps (High-Level)

1. Create a temporary session signed by the wallet owner
2. Execute a session-authorized call to `addValidator()`
3. Wait until the session expires
4. Observe that session execution is rejected
5. Execute a transaction via the persisted validator
6. Observe wallet funds transferred to the attacker

> Details are demonstrated in the attached video and test script.

---

## Threat Model

This vulnerability affects the wallet-core authorization model, not a specific UI or deployment choice.

**The issue does not rely on EIP-7702.**

It exists in any environment where:
- The wallet is implemented as a smart contract account, **and**
- Session-based execution (`executeFromExecutor`) is enabled

The core issue is that a temporary authorization (session executor) can permanently mutate wallet authority by adding a validator.

EIP-7702 only increases reachability by allowing EOAs to temporarily behave as smart accounts using the same execution semantics. Without EIP-7702, the issue already affects deployed smart-contract wallets.

The use of `vm.etch` in the PoC is purely to emulate a deployed wallet runtime environment. The exploit does not depend on test-only behavior, code replacement, or EIP-7702-specific mechanics.

---

## Authorization Model Violation

This issue is not about what the user technically signed, but about what a session is **expected to represent** in a secure wallet system.

Sessions are implicitly designed and communicated as temporary, scoped, and revocable authorizations.

If session execution is allowed to mutate permanent authorization state, then **sessions are functionally equivalent to permanent private keys**.

This contradicts the expected and documented purpose of sessions as time-bounded access mechanisms.

---

## Broken Security Invariant

> **A temporary authorization mechanism must never be able to grant permanent authority.**

Violating this invariant collapses authorization boundaries and invalidates the security assumptions of time-based access control.

---

## Why This Is Not "User Consent"

The user consented to:
- ✅ Temporary execution
- ✅ Time-bounded access
- ✅ Executor-scoped authority

The user did **NOT** consent to:
- ❌ Permanent governance mutation
- ❌ Persistent validator addition
- ❌ Post-expiry wallet control

User consent cannot justify a design where temporary and permanent trust boundaries are indistinguishable.

---

## Severity Justification

This issue meets **Critical** criteria under Web3 security policy:
- Complete authorization boundary violation
- Persistent compromise via validator backdoor
- Post-expiry fund theft
- Affects core wallet trust model

The impact is systemic and not limited to a single user action or UI surface.

---

## Recommendations

One or more of the following should be enforced:

1. Disallow `executeFromExecutor()` from invoking governance or authorization functions
2. Prevent session-based execution from mutating permanent privilege state
3. Require explicit, non-session authorization for validator changes
4. Introduce allowlists for session-executable calls
5. Enforce separation between temporary execution and permanent trust mutation

---

## Conclusion

This is a **real privilege escalation vulnerability**, not a design preference.

It enables:
- Persistent wallet compromise
- Post-expiry fund theft
- Collapse of session security guarantees

Allowing sessions to permanently mutate wallet authorization state **renders sessions unsafe by design**.

---

## Reporter Note

A video demonstration is available showing:
- Session expiry enforcement
- Validator persistence after expiry
- Post-expiry fund theft without session usage

*AI tools were used to assist with language clarity and report structuring. All technical analysis, vulnerability discovery, and proof-of-concept development were performed and validated manually by the reporter.*
