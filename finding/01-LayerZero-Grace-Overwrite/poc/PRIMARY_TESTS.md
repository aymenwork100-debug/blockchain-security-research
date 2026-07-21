# Primary PoC Tests

The full fork-production suite contains 13 passing tests. The following three tests are the primary focused tests for this case study.

## Test File

```text
Fork_Production_GraceOverwrite.t.sol
```

## Primary Tests

```text
test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain
test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState
test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive
```

## Run Command

Run from the relevant LayerZero Foundry project directory.

```bash
ETH_RPC_URL="<YOUR_ARCHIVE_RPC_URL>" forge test \
  --match-path test/Fork_Production_GraceOverwrite.t.sol \
  -vvvv --via-ir
```

## Focused Run Command

```bash
ETH_RPC_URL="<YOUR_ARCHIVE_RPC_URL>" forge test \
  --match-path test/Fork_Production_GraceOverwrite.t.sol \
  --match-test "test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain|test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState|test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive" \
  -vvvv --via-ir
```

## Why These Tests Matter

These three tests are treated as the primary evidence because they focus on:

- Application-level impact through an OFTAdapter-style receiver
- Canonical verification state replacement on a production default receive-library path
- Live precondition verification for the Stargate TokenMessaging path

The remaining tests in the fork-production suite are exploratory, diagnostic, or supporting tests.
