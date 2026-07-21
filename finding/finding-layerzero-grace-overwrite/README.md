# LayerZero EndpointV2 Grace-Period Verification State Replacement

## Summary

This case study analyzes a LayerZero EndpointV2 receive-library grace-period behavior where canonical inbound verification state may be replaced before message execution.

The research focuses on the security invariant that, for a given receiver, source endpoint, sender, and nonce, a verified inbound payload hash should not be replaceable by a different receive library before execution.

## Research Area

- Protocol: LayerZero EndpointV2
- Category: Cross-chain protocol security
- Focus: Receive-library upgrades, grace periods, and inbound payload hash integrity
- Testing: Foundry mainnet-fork tests
- Primary PoC file: `poc/Fork_Production_GraceOverwrite.t.sol`

## Primary Evidence

The full fork-production suite contains 13 passing tests. The primary evidence is represented by three focused tests documented in:

```text
poc/PRIMARY_TESTS.md
```

## Report

The final cleaned technical report will be added in:

```text
report.md
```

## Publication Note

This case study is organized as a technical portfolio artifact. It does not include RPC keys, private bounty correspondence, secrets, or sensitive non-public information.
