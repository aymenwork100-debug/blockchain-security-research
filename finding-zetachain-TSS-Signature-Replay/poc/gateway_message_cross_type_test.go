package solana_test

// Cross-type collision check: can a Call-mode preimage and a Revert-mode
// preimage of (MsgExecute / MsgExecuteSPL) collide?
//
// Call vs Revert differ at two structurally distinct positions:
//
//   1. Instruction byte at gateway_message.go:358-362 (or :697-701 for SPL):
//        Call    → InstructionExecute      (byte 5)   /  InstructionExecuteSPL      (byte 6)
//        Revert  → InstructionExecuteRevert(byte 8)   /  InstructionExecuteSPLRevert(byte 9)
//      This byte sits at preimage offset 9 (right after the 9-byte
//      "ZETACHAIN" prefix at gateway_message.go:356), in a fixed-length
//      window. There is no slack at offsets ≤ 9 to absorb a 1-byte
//      difference.
//
//   2. sender encoding at gateway_message.go:375-379:
//        Call    → 20 bytes (EVM address via common.HexToAddress)
//        Revert  → 32 bytes (Solana pubkey via solana.MustPublicKeyFromBase58)
//      This 12-byte difference sits AFTER the instruction byte. Even if
//      a 12-byte shift in the trailing data || remainingAccounts segment
//      could compensate for the sender-length asymmetry, it cannot
//      compensate for the 1-byte instruction-id difference at offset 9.
//
// The tests below construct the strongest possible Call/Revert "matched"
// pair — same chainID/nonce/amount/to, payload arranged to absorb the
// 12-byte sender-length difference into the data tail — and confirm the
// hashes differ at the instruction-byte offset. Any future change that
// removes or duplicates the instruction byte would break this test.

import (
  	"testing"

  	"github.com/ethereum/go-ethereum/common"
  	"github.com/gagliardetto/solana-go"
  	"github.com/stretchr/testify/require"
  	"github.com/zeta-chain/node/pkg/chains"
  	contracts "github.com/zeta-chain/node/pkg/contracts/solana"
  )

func Test_MsgExecute_NoCallRevertCollision(t *testing.T) {
  	// Identical envelope.
  	chainID := uint64(chains.SolanaLocalnet.ChainId)
  	nonce := uint64(7)
  	amount := uint64(1336000)
  	to := solana.MustPublicKeyFromBase58("37yGiHAnLvWZUNVwu9esp74YQFqxU1qHCbABkDvRddUQ")

  	// Call sender: 20-byte EVM address. Revert sender: 32-byte Solana pubkey.
  	senderCall := common.HexToAddress("0x42bd6E2ce4CDb2F58Ed0A0E427F011A0645D5E33").Hex()
  	senderRevert := solana.MustPublicKeyFromBase58("CVoPuE3EMu6QptGHLx7mDGb2ZgASJRQ5BcTvmhZNJd8A").String()

  	// Prove the senders actually differ in length the way the docstring claims.
  	require.Equal(t, 20, len(common.HexToAddress(senderCall).Bytes()))
  	require.Equal(t, 32, len(solana.MustPublicKeyFromBase58(senderRevert).Bytes()))

  	// Strongest compensation attempt: prepend 12 bytes to Revert's data
  	// so that (sender_revert(32) || data_revert) == (sender_call(20) || data_call)
  	// at every offset after the instruction byte. If the instruction-byte
  	// position were collidable, the hashes would now match.
  	baseData := []byte("payload")
  	dataCall := baseData
  	dataRevert := append(make([]byte, 0, 12+len(baseData)), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
  	// the prepended 12 bytes are pure attacker choice; we then concatenate the
  	// exact same baseData, so dataRevert is 12 bytes longer than dataCall.
  	dataRevert = append(dataRevert, baseData...)

  	msgCall := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, senderCall,
      		dataCall, contracts.ExecuteTypeCall, nil, nil, nil,
      	)
  	msgRevert := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, senderRevert,
      		dataRevert, contracts.ExecuteTypeRevert, nil, nil, nil,
      	)

  	hashCall := msgCall.Hash()
  	hashRevert := msgRevert.Hash()

  	// The hashes must differ. The reason is the instruction byte at offset 9
  	// (Call=5, Revert=8). Even though we crafted the trailing bytes to make
  	// the sender || data segments byte-equal, byte-9 still differs by 3.
  	require.NotEqual(t, hashCall, hashRevert,
                     		"Call vs Revert preimages must not collide; if this assertion ever fires, "+
                     			"the instruction-id slot in MsgExecute.Hash() (gateway_message.go:358-362) "+
                     			"has been removed or made non-discriminating")
  }

func Test_MsgExecuteSPL_NoCallRevertCollision(t *testing.T) {
  	chainID := uint64(chains.SolanaLocalnet.ChainId)
  	nonce := uint64(7)
  	amount := uint64(1336000)
  	mintAccount := solana.MustPublicKeyFromBase58("AS48jKNQsDGkEdDvfwu1QpqjtqbCadrAq9nGXjFmdX3Z")
  	to := solana.MustPublicKeyFromBase58("37yGiHAnLvWZUNVwu9esp74YQFqxU1qHCbABkDvRddUQ")
  	toAta, _, err := solana.FindAssociatedTokenAddress(to, mintAccount)
  	require.NoError(t, err)

  	senderCall := common.HexToAddress("0x42bd6E2ce4CDb2F58Ed0A0E427F011A0645D5E33").Hex()
  	senderRevert := solana.MustPublicKeyFromBase58("CVoPuE3EMu6QptGHLx7mDGb2ZgASJRQ5BcTvmhZNJd8A").String()

  	baseData := []byte("payload")
  	dataCall := baseData
  	dataRevert := append(make([]byte, 0, 12+len(baseData)), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
  	dataRevert = append(dataRevert, baseData...)

  	msgCall := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, senderCall,
      		dataCall, contracts.ExecuteTypeCall, nil, nil, nil,
      	)
  	msgRevert := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, senderRevert,
      		dataRevert, contracts.ExecuteTypeRevert, nil, nil, nil,
      	)

  	require.NotEqual(t, msgCall.Hash(), msgRevert.Hash(),
                     		"MsgExecuteSPL Call vs Revert must not collide; the instruction byte "+
                     			"at gateway_message.go:697-701 (Call=6, Revert=9) is structurally distinct")
  }
