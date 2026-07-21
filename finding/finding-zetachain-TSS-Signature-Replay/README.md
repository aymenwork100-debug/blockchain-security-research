# ZetaChain TSS Signature Replay via Hash-Preimage Ambiguity in Solana Gateway

**Target:** https://github.com/zeta-chain/node
**Protocol:** ZetaChain

## Vulnerability Details

**Target:** zeta-chain/node

**Affected files:**
- `pkg/contracts/solana/gateway_message.go` — `MsgExecute.Hash()` and `MsgExecuteSPL.Hash()`
- (cross-validated against) `protocol-contracts-solana/programs/gateway/src/utils/validate_message_hash.rs`

**Pinned commits:**
- zeta-chain/node @ `9a516a34db15ccf991eb1cf93ba90d5c1eee87fe`
- zeta-chain/protocol-contracts-solana @ `0852ac80202fc10ed35ba5d7e342c887c8c9a110`

## 1. Summary

The L1 node builds the TSS-signed message for outbound Execute/ExecuteSPL calls to Solana by concatenating two variable-length fields — data and remainingAccounts — back-to-back with no length prefix and no count prefix between them. Because every remainingAccounts entry is exactly 32 bytes, an attacker can shift any multiple of 32 bytes from the tail of data into remainingAccounts (or vice-versa), producing a byte-identical Keccak preimage and therefore an identical TSS-signed digest.

The on-chain Solana validator (validate_message_hash) reconstructs the same flat layout and accepts a TSS signature produced for one split against a different split. A single TSS signature is valid for many distinct account lists.

This is not a flaw in the TSS itself; it is a flaw in the digest construction. No malicious observer/signer is required.

## 2. The Bug — Code Locations

### 2.1 Signing side (Go, in-scope) — pkg/contracts/solana/gateway_message.go

`MsgExecute.Hash()` (L352–388):

```go
// ... fixed-length prefix: "ZETACHAIN" || instruction_id(1B) || chainID(8B) ||
//     nonce(8B) || amount(8B) || to(32B) || sender(20B or 32B) ...
message = append(message, msg.data...)                  // L381 — variable, no length prefix
for _, r := range msg.remainingAccounts {
    message = append(message, r.PublicKey.Bytes()...)   // L383-385 — variable count, no count prefix
}
return crypto.Keccak256Hash(message)
```

Lines 381–385 are the bug. The trailing `data || pubkey₁ || pubkey₂ || …` has no boundary marker. Any 32-byte-aligned shift of the boundary produces identical bytes.
The identical pattern exists in `MsgExecuteSPL.Hash()` (L690–728, specifically L722 and L724–726).

### 2.2 Verifying side (Rust) — programs/gateway/src/utils/validate_message_hash.rs:30-38

```rust
for data in additional_data {
    concatenated_buffer.extend_from_slice(data);     // raw, back-to-back
}
if let Some(accounts) = remaining_accounts {
    for account in accounts {
        concatenated_buffer.extend_from_slice(&account.key().to_bytes());  // raw
    }
}
```

The on-chain validator reproduces the same delimiter-free layout.

## 3. Attacker Model

### 3.1 Who can exploit this

Any user who can submit a transaction to the deployed Solana gateway. No privileged role required.

The flaw is reachable because:
- `data` is passed as an instruction argument to `gateway.execute(...)` (caller-controlled — see lib.rs:79-90)
- `remainingAccounts` is passed as the Solana transaction's account list (caller-controlled)
- Both are independent inputs to `validate_message_hash`, but the digest does not distinguish them

### 3.2 Exploit sequence

1. zetaclient signer computes `MsgExecute.Hash()` for a CCTX, obtains TSS signature S
2. Signer broadcasts the legitimate Solana tx with split A: `data = X`, `remainingAccounts = Y` (signer.go:382-386)
3. Signature S is now public in Solana mempool
4. Attacker, watching mempool, builds an alternate tx with split B: `data = X'`, `remainingAccounts = Y'` such that the preimage bytes are identical, reusing signature S
5. Attacker submits via Jito bundles to front-run the legitimate broadcast
6. Whichever tx lands first consumes nonce; the other fails with NonceMismatch

### 3.3 Why the race is winnable in practice

`verify_and_update_nonce` (utils/verify_and_update_nonce.rs:7-13) consumes the nonce atomically. This gives the attacker:

Attacker needs to win ONCE per CCTX. A single successful front-run demonstrates the exploit.

Failed attempts are cheap. ~5,000 lamports (~$0.001) per failed race. No slashing, no on-chain penalty.

Each new Execute CCTX is an independent attempt. Over N CCTXs with per-attempt success probability p (Jito reports ~88–95% stake share for top-of-block placement, but inclusion is auction-priced and not deterministic), expected successes ≈ N × p.

This is the standard threat model for MEV-class exploits on public chains — patient adversary, probabilistic success, negligible failure cost.

### 3.4 Verification ordering offers no graceful recovery

`validate_message` (utils/validate_message.rs:20-30) consumes the nonce before verifying the hash:

```rust
verify_and_update_nonce(pda, nonce)?;       // nonce consumed FIRST
validate_message_hash(...)?;                 // hash checked SECOND
recover_and_verify_eth_address(...)?;        // signature checked THIRD
```

This ordering is irrelevant to the attack (the malicious tx is byte-equivalent at the digest level — hash check passes). But it means: if the attacker's tx lands first, the nonce is permanently consumed and the legitimate outbound is invalidated. The CCTX must be re-signed with a new nonce, and the attacker has already captured the routed funds.

This also enables a pure DoS primitive: an attacker who only wishes to disrupt the bridge can front-run with any malformed split, consuming the nonce and forcing operational re-signing. Repeated DoS against every Execute outbound degrades bridge operations indefinitely at negligible cost.

## 4. Impact

### 4.1 What the PoC directly demonstrates

Three test files (provided in Validation Steps section) prove at the code level:
- `Hash()` collides under (data, remainingAccounts) repartitioning — Go tests against production constructors
- The on-chain `validate_message_hash` accepts colliding splits — Rust integration test calling the unmodified production validator
- No Call/Revert cross-collision — negative test, scoping the bug precisely

Together: a single TSS signature is cryptographically valid for multiple distinct (data, remainingAccounts) pairs at the validator level. This is the irreducible cryptographic flaw.

### 4.2 What follows by code-path analysis

After `validate_message_hash` returns `Ok`, Execute performs `invoke(&ix, ctx.remaining_accounts)` (SOL: execute.rs:85, SPL: execute.rs:234). Same slice that satisfied the validator forwards to CPI — no second filtering.

`data` and `remaining_accounts` are caller-controlled at Solana RPC boundary, no zetaclient involvement.

An end-to-end Solana devnet PoC demonstrating the full chain (CCTX → signature reuse → CPI → lamport transfer to attacker) can be delivered within 5 business days on request. This disclosure stage prioritizes the program's 24-hour reporting rule over PoC scope.

### 4.3 Exploit primitive — what the attacker gains

**Account-list injection at destination program CPI.** Attacker controls which pubkeys reach `ctx.remaining_accounts`, independent of TSS authorization. Cannot make injected accounts signers (prepare_account_metas.rs:8-31 forces `is_signer = false`), but can substitute, prepend, append, or remove at 32-byte-aligned offsets.

**Theft from reference-pattern connected programs.** ZetaChain's reference connected programs (programs/examples/connected/src/lib.rs:52-62 and connectedSPL/src/lib.rs:38-55) are the canonical integration template that ZetaChain documentation provides for downstream developers. Both distribute amount/2 linearly across `remaining_accounts`:

```rust
let share = half / rem_accounts_len;
for acc in ctx.remaining_accounts.iter() {
    acc.add_lamports(share)?;
}
```

Attacker submits CCTX with data ending in their pubkey, front-runs with pubkey moved to remainingAccounts. Reference `on_call` distributes amount/2 to attacker.

**Permanent DoS of any Execute outbound, with negligible cost.** Because nonce is consumed before hash verification (validate_message.rs:20-30), any front-run with any byte-equivalent malformed split invalidates the legitimate outbound. Attacker pays ~5,000 lamports per attempt with no slashing or on-chain penalty.

### 4.4 Why gateway PDA drain is NOT a mitigating factor

The exploit primitive does not directly drain gateway PDA balances — every gateway-internal transfer is bound to a fixed-length destination element hashed BEFORE the ambiguous tail (withdraw.rs:29,71, execute.rs:62,185, plus verify_ata_match checks).

The attack surface is the destination program's CPI and the bridge's value flow, not the gateway's instantaneous balance. Cross-chain bridges route value continuously; value-at-risk is the flow.

### 4.5 Cryptographic class

Independent of dollar damage assessment, the bug is a TSS signature-binding failure: a single TSS signature authorizes multiple distinct on-chain outcomes. Direct match for three Critical focus areas in the program's scope:
- Cryptographic flaws — direct match
- Unauthorized transaction — direct match (destination program executes with account list the TSS never bound)
- Compromise of the TSS Address that leads to unauthorized transactions — partial (TSS key uncompromised but authorization non-binding)

## 5. Suggested Fix

Must be applied simultaneously and identically in both `gateway_message.go` (Go) and `validate_message_hash.rs` (Rust). Hash semantics change; migration requires pausing the gateway, draining in-flight CCTXs, deploying on-chain upgrade, switching zetaclient, unpausing.

**Option 1 (recommended, minimal): length-prefix data** in both `MsgExecute.Hash()` (~L381) and `MsgExecuteSPL.Hash()` (~L722):

```go
dataLen := make([]byte, 4)
binary.BigEndian.PutUint32(dataLen, uint32(len(msg.data)))
message = append(message, dataLen...)
message = append(message, msg.data...)
```

Mirror in Rust `validate_message_hash`.

**Option 2:** count-prefix `remainingAccounts`. Equivalent mitigation.

**Option 3 (long-term):** replace ad-hoc concatenation with Borsh-serialized typed `ExecutePreimage` struct. Borsh length-prefixes `Vec<u8>` and `Vec<Pubkey>` automatically; eliminates this class for any future variable-length field.

## Validation Steps

Three test files prove the collision at both layers (Go signing side + Rust on-chain validator side). All tests PASS at the pinned commits with no modifications to production code (only single-line re-export added to lib.rs for test reachability).

(PoC files and screenshots of test results are provided in the attachments section / `poc/` folder)

### Reproduction Steps

**Step 1: Clone node at pinned commit**

```
git clone https://github.com/zeta-chain/node && cd node
git checkout 9a516a34db15ccf991eb1cf93ba90d5c1eee87fe
```

**Step 2:** Place the two Go test files in `pkg/contracts/solana/`

**Step 3: Run the Go tests**

```
go test -v -run 'Ambiguity' ./pkg/contracts/solana/...
go test -v -run 'NoCallRevertCollision' ./pkg/contracts/solana/...
```

**Step 4: Clone protocol-contracts-solana at pinned commit**

```
cd .. && git clone https://github.com/zeta-chain/protocol-contracts-solana
cd protocol-contracts-solana
git checkout 0852ac80202fc10ed35ba5d7e342c887c8c9a110
```

**Step 5:** Apply the single-line re-export to `programs/gateway/src/lib.rs`

Add this line near the top of the file (after existing `pub use` statements):

```rust
pub use utils::validate_message_hash::validate_message_hash;
```

**Step 6:** Place `validate_message_hash_collision.rs` in `programs/gateway/tests/`

**Step 7: Run the Rust integration test**

```
cargo test --test validate_message_hash_collision -- --nocapture
```

### Expected Output — Go tests (proves Hash() collision in L1 node)

```
=== RUN Test_MsgExecuteHashAmbiguity
--- PASS: Test_MsgExecuteHashAmbiguity (0.00s)
=== RUN Test_MsgExecuteSPLHashAmbiguity
--- PASS: Test_MsgExecuteSPLHashAmbiguity (0.00s)
=== RUN Test_MsgExecuteRevertHashAmbiguity
--- PASS: Test_MsgExecuteRevertHashAmbiguity (0.00s)
PASS
ok github.com/zeta-chain/node/pkg/contracts/solana (cached)

=== RUN Test_MsgExecute_NoCallRevertCollision
--- PASS: Test_MsgExecute_NoCallRevertCollision (0.00s)
=== RUN Test_MsgExecuteSPL_NoCallRevertCollision
--- PASS: Test_MsgExecuteSPL_NoCallRevertCollision (0.00s)
PASS
ok github.com/zeta-chain/node/pkg/contracts/solana (cached)
```

### Expected Output — Rust test (proves on-chain validator accepts both splits)

```
running 3 tests
Computed message hash: [162, 174, 1, 101, 160, 131, 121, 197, 234, 74, 135, 74, 214, 141, 129, 159, 172, 251, 154, 182, 12, 251, 26, 123, 55, 16, 244, 121, 214, 5, 0, 229]
Computed message hash: [137, 58, 170, 200, 16, 159, 182, 237, 127, 102, 128, 111, 34, 29, 150, 149, 49, 142, 233, 140, 161, 9, 209, 30, 203, 99, 17, 97, 192, 89, 65, 245]
Computed message hash: [162, 174, 1, 101, 160, 131, 121, 197, 234, 74, 135, 74, 214, 141, 129, 159, 172, 251, 154, 182, 12, 251, 26, 123, 55, 16, 244, 121, 214, 5, 0, 229]
test execute_sol_revert_split_collision_accepted_by_real_validator ... ok
Computed message hash: [137, 58, 170, 200, 16, 159, 182, 237, 127, 102, 128, 111, 34, 29, 150, 149, 49, 142, 233, 140, 161, 9, 209, 30, 203, 99, 17, 97, 192, 89, 65, 245]
test execute_sol_split_collision_accepted_by_real_validator ... ok
Computed message hash: [145, 149, 155, 167, 54, 30, 136, 56, 112, 89, 122, 38, 212, 51, 171, 127, 193, 217, 169, 110, 10, 189, 14, 168, 212, 196, 158, 199, 217, 150, 194, 95]
Computed message hash: [145, 149, 155, 167, 54, 30, 136, 56, 112, 89, 122, 38, 212, 51, 171, 127, 193, 217, 169, 110, 10, 189, 14, 168, 212, 196, 158, 199, 217, 150, 194, 95]
test execute_spl_token_split_collision_accepted_by_real_validator ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### What the Tests Prove

**Test 1 (Go, Ambiguity):** The production `NewMsgExecute(...)` and `NewMsgExecuteSPL(...)` constructors produce identical `Hash()` outputs when called with two different (data, remainingAccounts) splits whose concatenation is byte-equal. Three sub-tests cover Execute-Call, Execute-Revert, ExecuteSPL-Call, ExecuteSPL-Revert variants.

**Test 2 (Go, NoCallRevertCollision):** Confirms the 1-byte instruction id at fixed offset 9 in the preimage prevents any cross-collision between Call mode (id=5) and Revert mode (id=8). Included to demonstrate the bug is scoped to (data, remainingAccounts) ambiguity only, not the broader instruction layout.

**Test 3 (Rust, Integration):** Calls the unmodified production `validate_message_hash` function directly via single-line re-export. Computes the digest the TSS would have signed for variant A, then invokes the validator twice with that same digest — once with split A, once with split B — and asserts both return `Ok(())`.

### Note

The Rust integration test invokes `validate_message_hash` directly rather than the full `validate_message` wrapper (which would also exercise nonce consumption). This is intentional: the irreducible cryptographic flaw being demonstrated is hash-preimage ambiguity at the validator level. Nonce dynamics are analyzed separately in section 3.3 of the main report and are part of the front-running threat model, not the cryptographic primitive itself.
