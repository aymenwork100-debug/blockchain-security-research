# Critical — Session Delegation Enables Post-Expiry & Post-Revocation ERC20 Drain via Persistent MAX Allowance (Intent Not Bound)

- **Target:** OKX WalletCore — Session-based delegated execution (executeFromExecutor)
- **Category:** Authorization Logic / Delegation Scope Violation
- **Severity:** Critical (Web3 – Theft of Funds)
- **Mainnet Deployment:** 0x80296FF8D1ED46f8e3C7992664D13B833504c2Bb

## Executive Summary

A structural authorization boundary violation exists in the session-based execution model of WalletCore.

A time-bounded session allows an executor to create persistent, unlimited ERC20 spending authority that survives:

- Session expiry (validUntil)
- Explicit session revocation (revokeSession)
- Blocking of executeFromExecutor

An executor can call:
→ token.approve(attacker, type(uint256).max)

during a valid session.

Although session expiry and revocation correctly prevent further session execution, the ERC20 allowance created during the session remains permanently active.

The attacker can later drain the wallet via:
→ token.transferFrom(wallet, attacker, balance)

without:

- Reusing the session
- Any additional wallet signature
- Validator escalation
- Governance mutation

This converts temporary execution delegation into permanent asset authority.

## Impact

This enables:

- Full ERC20 fund theft
- Post-expiry drain
- Post-revocation drain
- Deterministic exploitation
- Single-signature compromise
- No replay required
- No cryptographic bypass

→ Theft of funds resulting from authorization boundary failure.

### Business Impact

**A) User Risk**
- delayed theft
- false sense of safety after expiry
- non-obvious compromise

**B) Platform Risk**
- incident response complexity
- forensic ambiguity (loss disconnected from session event)
- increased support burden

**C) Trust Model Impact**
- session expiry no longer reliable security boundary

## Threat Model

- User signs time-limited session
- Executor may be:
  - dApp
  - automation bot
  - relayer
  - delegated service
- Wallet relies on expiry/revocation as safety boundary

Attack does NOT require:

- replay
- governance mutation
- root access
- no on-chain reorg / MEV / timing dependency
- special timing

### Executor Compromise Is a First-Class Risk

Sessions are explicitly designed for third-party executors (bots/relayers/dApps). A malicious or compromised executor is a first-class threat in this model; otherwise sessions provide no meaningful security boundary compared to permanent validators.

## Affected Component & Scope

- WalletCore session execution layer
- executeFromExecutor authorization path
- Any deployed wallet instance enabling session-based execution
- Independent of UI restrictions

### UI Restrictions Are Irrelevant

UI safeguards cannot be relied upon because the exploit occurs entirely at the contract authorization layer: executeFromExecutor forwards arbitrary external calls without selector/target constraints, so any off-chain UI restriction is bypassable by a malicious executor submitting the transaction directly.

## Root Cause

### 1. Session Typed Data Does NOT Bind Execution Intent

The session EIP-712 schema includes:

- wallet
- id
- executor
- validator
- validUntil
- validAfter
- hooks

It does NOT include:

- Call[]
- target addresses
- function selectors
- calldata
- token address
- spender
- allowance amount

The owner signs: → who may execute and when

The owner does not sign: → what may be executed

Execution authority is signed. Intent is not.

### 2. Arbitrary Execution Is Permitted

executeFromExecutor forwards arbitrary calls via batch execution.

There are:

- No selector restrictions
- No target restrictions
- No approval caps
- No persistent side-effect guards

Therefore approve(MAX) is fully permitted during session validity.

### 3. Expiry & Revocation Only Block Execution — Not Financial Side-Effects

revokeSession(id) and time expiry:

- Correctly block future executeFromExecutor calls
- Do NOT revoke ERC20 allowances
- Do NOT track or revert financial side-effects
- Do NOT restore pre-session asset state

Revocation and expiry are execution controls — not asset authority controls.

## Deterministic Proof of Concept

**Test Files:**

- SessionApproveMax_PostExpiryDrain.t.sol
- SessionApproveMax_PostExpiryDrain_Revocation.t.sol

**Verified Results:**

- [PASS] test_SessionApproveMax_AllowsPostExpiryFullDrain()
- [PASS] test_Revocation_DoesNotRestoreFinancialSafety()

### Exploit Flow

**Step 1 — User Signs Time-Bounded Session**
→ User signs session believing delegation is temporary.

**Step 2 — During Valid Session**
Executor calls: → approve(attacker, type(uint256).max)

Result: → token.allowance(wallet, attacker) = MAX

**Step 3 — Session Expires or Is Revoked**
→ executeFromExecutor correctly reverts
→ Session becomes invalid

**Step 4 — Drain After Expiry / Revocation (No Session Used)**
Attacker calls: → token.transferFrom(wallet, attacker, full_balance);

Result:

- Wallet balance → 0
- Attacker receives full token balance
- Allowance remains MAX

No session. No replay. No governance mutation.

## Deterministic Reproduction (Foundry)

**Environment:** Foundry (Forge)

### Core Exploit Test

**File:** test/SessionApproveMax_PostExpiryDrain.t.sol

**Run:**

```bash
forge test --match-test test_SessionApproveMax_AllowsPostExpiryFullDrain -vvv
```

Observe:

- During valid session (executeFromExecutor): → approve(attacker, MAX) succeeds → token.allowance(wallet, attacker) == type(uint256).max
- After expiry: → executeFromExecutor reverts (InvalidSession)
- Post-expiry drain (NO session / direct ERC20 call): → transferFrom succeeds → wallet balance == 0 → attacker balance == INITIAL_BALANCE → allowance remains MAX

### Revocation Test

**File:** test/SessionApproveMax_PostExpiryDrain_Revocation.t.sol

**Run:**

```bash
forge test --match-test test_Revocation_DoesNotRestoreFinancialSafety -vvv
```

Observe:

- Revocation blocks executeFromExecutor (session invalid/revoked)
- Allowance persists at MAX
- transferFrom still drains wallet after revocation

## Why This Is a Wallet Authorization Failure (Not Expected ERC20 Behavior)

In a normal EOA flow: → The owner explicitly signs an ERC20 approval transaction.

Here:

- The owner does not sign an approval transaction.
- The owner signs a generic time-bounded session object.

The session signature is not bound to execution intent.

This creates a structural mismatch:

| Authorization | Effect |
|---|---|
| Time-bounded | Persistent |
| Revocable | Irreversible financial delegation |
| Scoped | Unlimited allowance |
| Expires | Allowance survives |

If a session can create financial authority that survives expiry and revocation:

→ Expiry does not restore safety.
→ Revocation does not restore safety.

This defeats the primary security control of sessions.

### Not a "User Accepted Overbroad Approval"

The user never authorizes an ERC20 approval transaction (spender/token/amount). The only signed artifact is a generic session object that does not commit to the executed calldata. Therefore this is not "the user accepted an overbroad approval"; it is blind delegated execution where approval can be injected without explicit consent.

This is not ERC20 semantics — it is a delegation scope failure in WalletCore's authorization layer.

## Architectural Separation Collapse

WalletCore defines two primitives:

| Primitive | Intended Purpose |
|---|---|
| Validators | Permanent trust root |
| Sessions | Temporary delegated execution |

The existence of:

- validUntil
- validAfter
- revokeSession
- hooks

demonstrates clear architectural intent for constrained delegation.

The current implementation collapses this separation:

Temporary execution authority → Permanent financial authority

This violates least-privilege principles.

> "Even if arbitrary calls are permitted during the session window, a time-bounded delegation primitive must not be able to create irreversible asset authority that outlives both expiry and revocation, otherwise the time bound becomes a non-security control."

## Production Relevance

Mainnet WalletCore deployment: 0x80296FF8D1ED46f8e3C7992664D13B833504c2Bb

This confirms the same session schema and entrypoint is present on mainnet deployment; therefore the vulnerability class is production-relevant. The execution path allows arbitrary external calls during session validity. Since approve() is a standard ERC20 function callable via external calls, the vulnerability class applies wherever session execution is enabled.

## Realistic Attack Scenario

1. User signs "one-time" automation session for a dApp
2. dApp calls approve(MAX) via session
3. Session expires naturally
4. Weeks later, attacker drains tokens via transferFrom
5. User cannot revoke — session already expired

Attack requires only one session signature.

## Recommended Mitigations

One or more:

1. **Bind Intent to Session Signature (Recommended)** → Include keccak256(Call[]) in session typed hash.
2. **Add Explicit Session Scopes** — Allow: target restrictions, selector allowlists, amount caps
3. **Restrict Persistent Financial Operations** — Block or cap: approve, setApprovalForAll, similar persistent delegation functions

## Broken Security Invariant

Session expiry must restore the wallet to a secure post-session state.

Current behavior violates this invariant because asset authority persists beyond session lifetime.

### Design Intent Clarification

If sessions were intended to grant unrestricted wallet authority equivalent to validators:

There would be no need for:

- validUntil
- revokeSession
- hooks
- separate validator primitive

The existence of separate validator and session primitives demonstrates clear intent separation: Validators → Permanent authority, Sessions → Constrained, temporary delegation

Allowing sessions to create irreversible financial authority contradicts this architectural separation.

## Statement of Compliance

- Testing performed on local environments and forked state
- No production user data accessed
- No DoS or disruptive behavior performed
- Report submitted within 24 hours of discovery
- Human-verified analysis and deterministic PoC

## Final Conclusion

A temporary session delegation can create permanent ERC20 spending authority that survives expiry and revocation, enabling complete post-expiry wallet drain without additional signatures.

This is a structural authorization boundary violation in WalletCore.

## Reporter Note

A video demonstration is available showing:

- Session creation and valid signature
- Execution of approve(attacker, MAX) during session validity
- Proper session expiry enforcement (executeFromExecutor reverts)
- Persistent ERC20 allowance after expiry
- Post-expiry wallet drain via transferFrom without session reuse

The demonstration confirms that session expiry and revocation function correctly, yet the financial authority created during the session persists.

AI tools were used to assist with language clarity and report structuring. The technical procedures have been manually verified by me.

## Impact Summary

An attacker can create unlimited ERC20 spending authority during a time-bounded session and later drain the wallet after the session has expired or been revoked.

This results in full post-expiry fund theft without additional signatures, without session reuse, and without modifying wallet authorization state.
