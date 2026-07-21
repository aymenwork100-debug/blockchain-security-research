# LayerZero EndpointV2 Grace-Period Verification State Replacement

## Summary

This report documents an independent security research case study on LayerZero V2's `EndpointV2` receive-library upgrade behavior.

The research focuses on a verification-state integrity issue that can appear during default receive-library upgrades with a non-zero grace period. During this grace period, the deprecated receive library remains valid. The tested behavior shows that the deprecated library can replace an inbound payload hash already committed by the new receive library before message execution.

In practical terms, the security invariant under review is:

```text
For a given receiver, source endpoint, sender, and nonce, once a payload hash is verified by the active receive library, a deprecated grace-valid library should not be able to replace that payload hash before execution.
```

The provided Foundry fork tests demonstrate that this invariant can be broken under the tested upgrade scenario.

## Research Scope

- Protocol: LayerZero V2
- Component: `EndpointV2`
- Area: Receive-library upgrades and inbound message verification
- Chain used for testing: Ethereum mainnet fork
- Fork block: `24,562,286`
- Test framework: Foundry
- Main PoC file: `poc/Fork_Production_GraceOverwrite.t.sol`

This writeup is intended as a public security research artifact. It does not include RPC keys, private bounty correspondence, secrets, or sensitive non-public information.

## Background

LayerZero V2 uses message libraries to verify cross-chain messages. On the destination chain, a receive library verifies an incoming message and commits its payload hash into `EndpointV2` state.

The key state variable for this research is conceptually:

```solidity
inboundPayloadHash[receiver][srcEid][sender][nonce]
```

This state determines which payload hash is considered verified for a given inbound message path and nonce. When `lzReceive()` is later called, the endpoint checks this verification state before delivering the message to the receiving OApp.

LayerZero also supports receive-library upgrades. When a default receive library is upgraded, the old library may remain valid for a grace period. This feature is useful because some messages may already be in flight when the upgrade happens.

The expected purpose of the grace period is to preserve compatibility for already in-flight messages. The risk tested here is whether the deprecated library can do more than that: specifically, whether it can commit fresh verification state or replace state already committed by the new library.

## High-Level Issue

The issue is a composition of three behaviors:

1. A deprecated receive library can remain valid during the configured grace period.
2. `EndpointV2` allows re-verification of an unexecuted inbound nonce.
3. The inbound payload hash write does not bind the slot to the receive library that first committed it.

Together, these behaviors allow the following sequence in the tested scenario:

1. The default receive library is upgraded from `libOld` to `libNew`.
2. `libOld` remains valid during the grace period.
3. `libNew` verifies and commits a payload hash for a fresh inbound nonce.
4. A DVN that is not trusted by `libNew`, but is still part of `libOld`'s configuration, cannot finalize through `libNew`.
5. The same deprecated path can still satisfy `libOld`'s quorum and commit a different payload hash.
6. The endpoint's stored payload hash is replaced before execution.
7. Execution follows the replaced payload hash.

This creates a verification-state replacement problem across receive-library generations.

## Technical Root Cause

### 1. Deprecated library validity is broad during the grace period

The receive-library validity check allows a deprecated library to remain valid while its timeout is active.

Simplified pattern:

```solidity
if (timeout.lib == _actualReceiveLib && timeout.expiry > block.number) {
    return true;
}
```

This confirms that the deprecated library is still accepted during the grace period. The relevant issue is that this validity is not restricted to a specific set of pre-upgrade or already in-flight nonces.

### 2. Re-verification is allowed for unexecuted slots

`EndpointV2` allows verification when a nonce is beyond the lazy inbound nonce or when a payload hash already exists for the slot.

Simplified pattern:

```solidity
return _origin.nonce > _lazyInboundNonce
    || inboundPayloadHash[_receiver][_origin.srcEid][_origin.sender][_origin.nonce] != EMPTY_PAYLOAD_HASH;
```

This permits re-verification before execution. The tested issue is that the system does not track which receive library wrote the existing verification state.

### 3. Inbound payload hash is overwritten without library binding

The inbound payload hash write is effectively unconditional once the payload hash is accepted.

Simplified pattern:

```solidity
inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
```

There is no per-nonce binding between the first committing library and future writes to the same verification slot.

## Security Invariant

The relevant invariant is:

```text
A receive library that is only valid because of an upgrade grace period should not be able to replace verification state already committed by the new active receive library for the same receiver, source endpoint, sender, and nonce.
```

A second related invariant is:

```text
The grace period should preserve execution of already in-flight messages, not grant unrestricted post-upgrade mutation authority over fresh or already-committed verification slots.
```

The PoC demonstrates that these invariants are not enforced in the tested scenario.

## Proof of Concept

The PoC is implemented as a Foundry fork test file:

```text
poc/Fork_Production_GraceOverwrite.t.sol
```

The full fork-production suite contains 13 passing tests. Three focused tests are used as the primary evidence for this report.

### Primary Tests

```text
test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain
test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState
test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive
```

### Focused Run Command

Run from the relevant LayerZero Foundry project directory:

```bash
ETH_RPC_URL="<YOUR_ARCHIVE_RPC_URL>" forge test \
  --match-path test/Fork_Production_GraceOverwrite.t.sol \
  --match-test "test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain|test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState|test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive" \
  -vvvv --via-ir
```

### Observed Result

The focused test run completed successfully:

```text
3 tests passed
0 failed
0 skipped
```

## Test 1: OFTAdapter-Style Escrow Drain Demonstration

### Test Name

```text
test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain
```

### Purpose

This is the strongest application-level impact demonstration.

The test uses a faithful reproduction of LayerZero's OFTAdapter receive path, including:

- Endpoint-only receive authorization
- Trusted peer verification
- OFT message decoding
- Token credit through an escrowed token transfer pattern

The purpose is to show that if an OApp releases escrowed assets based on the verified LayerZero payload, then replacing the endpoint's canonical payload hash can change the execution outcome.

### Tested Sequence

1. The adapter is funded with `2,000,000e18` tokens.
2. `libNew` becomes the current default receive library after the simulated upgrade.
3. `libOld` remains valid during the grace period.
4. The current trusted DVN under `libNew` commits a legitimate payload hash.
5. A DVN from `libOld`'s real on-chain configuration is shown not to be able to finalize through `libNew`.
6. The same deprecated path satisfies the real `libOld` quorum and commits a forged payload hash.
7. The endpoint's stored payload hash is replaced.
8. `lzReceive()` executes the replaced payload.

### Important Evidence

The run shows:

```text
libOld confirmations (REAL): 20
libOld requiredDVNCount (REAL): 2
current-path commit established canonical state
revoked-from-current identity cannot finalize via current path
revoked grace-valid path still mutated canonical state
execution followed overwritten state, not current-path commit
```

The resulting token balances were:

```text
adapter escrow before: 2000000000000000000000000
adapter escrow after:  0
alice balance after:   0
attacker balance after: 2000000000000000000000000
```

### Interpretation

The test demonstrates that the execution outcome is determined by the payload hash committed through the deprecated grace-valid library, not by the payload hash first committed by the active receive library.

This is presented as an application-level impact demonstration using a controlled fork test and a faithful OFTAdapter-style receiver.

## Test 2: Production Default-Path Verification State Replacement

### Test Name

```text
test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState
```

### Purpose

This test demonstrates that the replacement behavior is not limited to a toy receiver. It checks a live production receiver path on the Ethereum mainnet fork.

### Receiver

```text
Stargate TokenMessaging on Ethereum:
0x6d6620eFa72948C5f68A3C8646d58C00d3f4A980
```

### Tested Conditions

At fork block `24,562,286`, the test verifies that:

```text
The receiver uses the protocol default receive-library path.
The receiver does not rely on an app-specific receive-library timeout.
The deprecated library remains grace-valid.
The receiver has live inbound traffic.
The next nonce slot is empty before verification.
```

The test logs include:

```text
live inbound nonce:      106303
live lazy inbound nonce: 106303
```

The test then uses the next nonce and demonstrates that the current receive library can commit a payload hash, after which the deprecated grace-valid library can replace it with another payload hash before execution.

### Interpretation

This test provides production-path evidence for the verification-state replacement behavior. It does not claim that a full Stargate message execution was completed in the test. Instead, it demonstrates that the endpoint verification state on a live default-path receiver can be replaced under the tested grace-period conditions.

## Test 3: Stargate Default-Path Preconditions

### Test Name

```text
test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive
```

### Purpose

This supporting test verifies the live preconditions used by Test 2.

It confirms that the Stargate TokenMessaging receiver:

```text
uses the default receive-library path
has the deprecated library grace-valid
has an active public source peer
has live inbound and lazy inbound nonces
has an empty next nonce slot
```

This test helps show that the production-path setup is not a test-rig artifact.

## Impact Analysis

### Confirmed by the PoC

The PoC confirms the following:

```text
A deprecated grace-valid receive library can remain valid after a default receive-library upgrade.
The active receive library can commit a payload hash for a nonce.
A DVN excluded from the active library configuration can fail to finalize through the active library.
The deprecated library path can still satisfy its own quorum.
The deprecated path can replace the endpoint's stored payload hash before execution.
Execution can follow the replaced payload hash.
```

### Potential Impact

The impact depends on the receiving OApp.

For OApps where the inbound message payload controls asset release, token credit, vault withdrawal, or escrow movement, verification-state replacement can lead to unauthorized asset movement in the tested model.

The strongest demonstrated impact is the OFTAdapter-style escrow receiver test, where the replaced payload causes the full escrowed token balance to be transferred to the attacker address in the controlled fork environment.

### Severity Assessment

A conservative severity assessment is:

```text
Potential High to Critical, depending on application reachability, active upgrade state, receive-library configuration, and reachable asset flow.
```

This assessment is intentionally conservative.

The PoC demonstrates a serious verification-state integrity break and an application-level drain model. However, live exploitability depends on whether a relevant grace-period window is active and whether the receiving OApp's asset flow is reachable through the replaced payload.

## Latent vs. Currently Exploitable

This research should distinguish between two concepts.

### Architectural Behavior

The architectural behavior is the code-level composition that allows cross-library verification state replacement during a grace-period upgrade scenario.

This behavior is important because it can recur whenever similar upgrade conditions occur.

### Runtime Exploitability

Runtime exploitability depends on live chain state.

The tested scenario uses a mainnet fork at a specific historical block and simulates a default receive-library upgrade with a grace period. Therefore, this report should not be read as a claim that the issue is currently exploitable at the time of publication.

A correct interpretation is:

```text
The PoC demonstrates that the verification-state replacement behavior is reachable under the tested upgrade conditions.
Whether it is exploitable at a given live moment depends on current protocol configuration, active grace-period windows, receiver configuration, and asset-flow reachability.
```

This distinction is important for keeping the report technically accurate and professionally conservative.

## Limitations

This research has the following limitations:

- The PoC uses a controlled Ethereum mainnet fork environment.
- The strongest drain demonstration uses a faithful OFTAdapter-style receiver deployed inside the test.
- The Stargate production-path test demonstrates verification-state replacement, not full Stargate payload execution.
- The tested exploitability depends on a grace-period upgrade window.
- The report does not claim that any live deployment was exploited.
- The report does not claim that the behavior was unknown to LayerZero.
- The report does not include private bounty correspondence or any statement about bounty eligibility.

## Suggested Mitigations

### Option 1: Pin the committing library per verification slot

Track which receive library first committed verification state for each `(receiver, srcEid, sender, nonce)` slot.

Conceptual example:

```solidity
mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => address))))
    public committingLibrary;

function _inbound(...) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();

    address pinned = committingLibrary[_receiver][_srcEid][_sender][_nonce];

    if (pinned == address(0)) {
        committingLibrary[_receiver][_srcEid][_sender][_nonce] = msg.sender;
    } else if (pinned != msg.sender) {
        revert Errors.LZ_LibraryMismatch();
    }

    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

This preserves same-library re-verification while preventing cross-library replacement.

### Option 2: Restrict deprecated libraries to pre-upgrade nonces

At upgrade time, record a nonce watermark per `(receiver, srcEid, sender)` path. The deprecated library should only be allowed to commit verification for nonces that were already in flight before the upgrade.

### Option 3: Disallow cross-library overwrite

If a verification slot already contains a non-empty payload hash, reject writes from a different receive library unless an explicit invalidation mechanism is used.

## Defensive Lessons

This case study highlights several defensive lessons for cross-chain protocol design:

```text
Grace-period compatibility should be scoped to the minimum authority needed.
Verification state should be bound to the security domain that produced it.
Library upgrades should preserve in-flight messages without allowing unrestricted post-upgrade mutation.
Default configuration paths need the same security guarantees as explicit per-application configuration.
Fork tests are valuable for validating protocol behavior against real deployed state.
```

## Research Skills Demonstrated

This case study demonstrates:

- Foundry mainnet-fork testing
- Fixed-block reproduction
- Cross-chain message verification analysis
- LayerZero EndpointV2 state reasoning
- Receive-library upgrade analysis
- DVN configuration analysis
- Faithful OFTAdapter-style receiver modeling
- Production-path precondition validation
- Conservative impact and severity calibration

## Publication Note

This writeup is published as an independent technical research artifact for portfolio purposes.

No mainnet or testnet state was modified. All testing was performed against local forks or controlled test contracts inside the fork environment.

This report does not include RPC keys, API keys, private bounty correspondence, exploit attempts against live deployments, or sensitive non-public information.
