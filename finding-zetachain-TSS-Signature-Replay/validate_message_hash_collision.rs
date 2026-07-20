//! Integration test for the hash-preimage ambiguity in
//! programs/gateway/src/utils/validate_message_hash.rs (lines 10-48).
//!
//! This test calls the production validate_message_hash function
//! directly — re-exported from the gateway crate — with two distinct
//! (additional_data_tail, remaining_accounts) splits and the same
//! provided message_hash. Both calls return Ok(()), demonstrating
//! that the on-chain validator accepts a TSS-signed digest under
//! either split.
//!
//! There is no wrapping mock dispatcher: the function under test is
//! the same symbol the production program calls.

use anchor_lang::solana_program::account_info::AccountInfo;
use anchor_lang::solana_program::keccak::hash as keccak;
use anchor_lang::solana_program::pubkey::Pubkey;
use gateway::{validate_message_hash, InstructionId};

const ZETACHAIN_PREFIX: &[u8] = b"ZETACHAIN";

/// Build a placeholder AccountInfo whose only meaningful field is the
/// pubkey. validate_message_hash only consumes account.key()
/// (line 38: account.key().to_bytes()), so lamports / data / owner
/// / writable bits are irrelevant to the check we're exercising.
fn dummy_account_info<'a>(
      key: &'a Pubkey,
      lamports: &'a mut u64,
      data: &'a mut [u8],
      owner: &'a Pubkey,
  ) -> AccountInfo<'a> {
      AccountInfo::new(
                key, /* is_signer / false, / is_writable */ false, lamports, data, owner,
                /* executable / false, / rent_epoch */ 0,
            )
}

/// Reproduce validate_message_hash's buffer layout to compute the
/// digest the TSS would have signed for split A. This is just keccak
/// math; it is not a substitute for the validator under test, which is
/// invoked unmodified in the assertions below.
fn expected_hash(
      instruction_id: InstructionId,
      chain_id: u64,
      nonce: u64,
      amount: Option<u64>,
      additional_data: &[&[u8]],
      remaining_keys: &[Pubkey],
  ) -> [u8; 32] {
      let mut buf = Vec::new();
      buf.extend_from_slice(ZETACHAIN_PREFIX);
      buf.push(instruction_id as u8);
      buf.extend_from_slice(&chain_id.to_be_bytes());
      buf.extend_from_slice(&nonce.to_be_bytes());
      if let Some(a) = amount {
                buf.extend_from_slice(&a.to_be_bytes());
      }
      for d in additional_data {
                buf.extend_from_slice(d);
      }
      for k in remaining_keys {
                buf.extend_from_slice(&k.to_bytes());
      }
      keccak(&buf).to_bytes()
}

#[test]
fn execute_sol_split_collision_accepted_by_real_validator() {
      // ---- shared envelope fields (the bits the TSS actually intends to authorize) ----
    let chain_id: u64 = 7001;
      let nonce: u64 = 42;
      let amount: u64 = 500_000_000;
      let destination_program = Pubkey::new_unique();
      let dest_bytes = destination_program.to_bytes();
      let sender_eth: [u8; 20] = [0xAB; 20];

    // ---- legitimate split (variant A): three pubkeys live INSIDE data ----
    let p1 = Pubkey::new_unique();
      let p2 = Pubkey::new_unique();
      let p3 = Pubkey::new_unique();

    let mut data_a: Vec<u8> = b"opaque-cross-chain-payload-".to_vec();
      data_a.extend_from_slice(&p1.to_bytes());
      data_a.extend_from_slice(&p2.to_bytes());
      data_a.extend_from_slice(&p3.to_bytes());

    let additional_a: [&[u8]; 3] = [&dest_bytes, &sender_eth, &data_a];
      let remaining_keys_a: Vec<Pubkey> = vec![];

    // Compute the hash the TSS would have signed for split A.
    let message_hash = expected_hash(
              InstructionId::ExecuteSol,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &remaining_keys_a,
          );

    // ---- malicious split (variant B): same trailing bytes, repartitioned ----
    let data_b = b"opaque-cross-chain-payload-".to_vec();
      let remaining_keys_b: Vec<Pubkey> = vec![p1, p2, p3];
      let additional_b: [&[u8]; 3] = [&dest_bytes, &sender_eth, &data_b];

    // Sanity: the locally-built buffers for A and B are byte-identical
    // (which is why the digest is the same).
    let hash_b_local = expected_hash(
              InstructionId::ExecuteSol,
              chain_id,
              nonce,
              Some(amount),
              &additional_b,
              &remaining_keys_b,
          );
      assert_eq!(
                message_hash, hash_b_local,
                "splits A and B must produce identical local keccak digests"
            );

    // Build the AccountInfo slices the production validator expects.
    // We materialize backing storage (lamports + data buffers) outside
    // the AccountInfo constructor so the borrows live long enough.
    let owner = Pubkey::default();

    // Variant A: empty remaining_accounts.
    let remaining_a: Vec<AccountInfo> = Vec::new();

    // Variant B: three account infos, keys = p1, p2, p3.
    let mut lamports_b: [u64; 3] = [0, 0, 0];
      let mut data_b1: Vec<u8> = Vec::new();
      let mut data_b2: Vec<u8> = Vec::new();
      let mut data_b3: Vec<u8> = Vec::new();

    // Construct each AccountInfo separately so each gets its own
    // exclusive borrow of its lamports/data slot.
    let (lamp_b1_slice, rest) = lamports_b.split_at_mut(1);
      let (lamp_b2_slice, lamp_b3_slice) = rest.split_at_mut(1);
      let ai_b1 = dummy_account_info(&p1, &mut lamp_b1_slice[0], &mut data_b1, &owner);
      let ai_b2 = dummy_account_info(&p2, &mut lamp_b2_slice[0], &mut data_b2, &owner);
      let ai_b3 = dummy_account_info(&p3, &mut lamp_b3_slice[0], &mut data_b3, &owner);
      let remaining_b: Vec<AccountInfo> = vec![ai_b1, ai_b2, ai_b3];

    // ---- THE TEST: the real validator accepts BOTH splits against the same hash ----
    let result_a = validate_message_hash(
              InstructionId::ExecuteSol,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &message_hash,
              Some(&remaining_a),
          );
      assert!(
                result_a.is_ok(),
                "production validator rejected split A: {:?}",
                result_a
            );

    let result_b = validate_message_hash(
              InstructionId::ExecuteSol,
              chain_id,
              nonce,
              Some(amount),
              &additional_b,
              &message_hash,
              Some(&remaining_b),
          );
      assert!(
                result_b.is_ok(),
                "production validator rejected split B (the malicious one): {:?}",
                result_b
            );

    // ---- the splits are observably different ----
    assert_ne!(
              data_a, data_b,
              "the two splits must differ in their data element"
          );
      assert_eq!(remaining_a.len(), 0);
      assert_eq!(remaining_b.len(), 3);
}

#[test]
fn execute_spl_token_split_collision_accepted_by_real_validator() {
      // Same shape, one extra fixed-length prefix element (mint || dest_pda_ata).
    // Source: programs/gateway/src/instructions/execute.rs lines 183-188.
    let chain_id: u64 = 7001;
      let nonce: u64 = 7;
      let amount: u64 = 250_000;
      let mint = Pubkey::new_unique();
      let dest_pda_ata = Pubkey::new_unique();
      let mint_bytes = mint.to_bytes();
      let ata_bytes = dest_pda_ata.to_bytes();
      let sender_eth: [u8; 20] = [0x11; 20];

    let p1 = Pubkey::new_unique();
      let p2 = Pubkey::new_unique();

    let mut data_a: Vec<u8> = b"on_call".to_vec();
      data_a.extend_from_slice(&p1.to_bytes());
      data_a.extend_from_slice(&p2.to_bytes());

    let additional_a: [&[u8]; 4] = [&mint_bytes, &ata_bytes, &sender_eth, &data_a];
      let remaining_keys_a: Vec<Pubkey> = vec![];

    let message_hash = expected_hash(
              InstructionId::ExecuteSplToken,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &remaining_keys_a,
          );

    // Variant B
    let data_b = b"on_call".to_vec();
      let additional_b: [&[u8]; 4] = [&mint_bytes, &ata_bytes, &sender_eth, &data_b];

    let owner = Pubkey::default();
      let remaining_a: Vec<AccountInfo> = Vec::new();

    let mut lamports_b: [u64; 2] = [0, 0];
      let mut db1: Vec<u8> = Vec::new();
      let mut db2: Vec<u8> = Vec::new();
      let (l1, l2) = lamports_b.split_at_mut(1);
      let ai_b1 = dummy_account_info(&p1, &mut l1[0], &mut db1, &owner);
      let ai_b2 = dummy_account_info(&p2, &mut l2[0], &mut db2, &owner);
      let remaining_b: Vec<AccountInfo> = vec![ai_b1, ai_b2];

    let result_a = validate_message_hash(
              InstructionId::ExecuteSplToken,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &message_hash,
              Some(&remaining_a),
          );
      assert!(result_a.is_ok(), "split A rejected: {:?}", result_a);

    let result_b = validate_message_hash(
              InstructionId::ExecuteSplToken,
              chain_id,
              nonce,
              Some(amount),
              &additional_b,
              &message_hash,
              Some(&remaining_b),
          );
      assert!(result_b.is_ok(), "split B rejected: {:?}", result_b);
}

#[test]
fn execute_sol_revert_split_collision_accepted_by_real_validator() {
      // The revert path uses InstructionId::ExecuteSolRevert and a 32-byte
    // Solana-pubkey sender (instead of the 20-byte EVM address used by
    // ExecuteSol). Trailing layout ... || data || rem_accs is identical,
    // so the same boundary shift applies.
    // Source: programs/gateway/src/instructions/execute.rs handle_sol_revert
    //         + handle_sol_common at lines 56-70.
    let chain_id: u64 = 7001;
      let nonce: u64 = 13;
      let amount: u64 = 100_000;
      let destination_program = Pubkey::new_unique();
      let dest_bytes = destination_program.to_bytes();
      let sender_solana = Pubkey::new_unique();
      let sender_bytes = sender_solana.to_bytes();

    let p1 = Pubkey::new_unique();

    let mut data_a: Vec<u8> = b"on_revert".to_vec();
      data_a.extend_from_slice(&p1.to_bytes());

    let additional_a: [&[u8]; 3] = [&dest_bytes, &sender_bytes, &data_a];
      let remaining_keys_a: Vec<Pubkey> = vec![];

    let message_hash = expected_hash(
              InstructionId::ExecuteSolRevert,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &remaining_keys_a,
          );

    let data_b = b"on_revert".to_vec();
      let additional_b: [&[u8]; 3] = [&dest_bytes, &sender_bytes, &data_b];

    let owner = Pubkey::default();
      let remaining_a: Vec<AccountInfo> = Vec::new();

    let mut lamp = 0u64;
      let mut data_buf: Vec<u8> = Vec::new();
      let ai_b1 = dummy_account_info(&p1, &mut lamp, &mut data_buf, &owner);
      let remaining_b: Vec<AccountInfo> = vec![ai_b1];

    let result_a = validate_message_hash(
              InstructionId::ExecuteSolRevert,
              chain_id,
              nonce,
              Some(amount),
              &additional_a,
              &message_hash,
              Some(&remaining_a),
          );
      assert!(result_a.is_ok(), "revert split A rejected: {:?}", result_a);

    let result_b = validate_message_hash(
              InstructionId::ExecuteSolRevert,
              chain_id,
              nonce,
              Some(amount),
              &additional_b,
              &message_hash,
              Some(&remaining_b),
          );
      assert!(result_b.is_ok(), "revert split B rejected: {:?}", result_b);
}
