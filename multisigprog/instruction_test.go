package multisigprog_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/tpkeeper/solana-go-sdk/client"
	"github.com/tpkeeper/solana-go-sdk/common"
	"github.com/tpkeeper/solana-go-sdk/multisigprog"
	"github.com/tpkeeper/solana-go-sdk/sysprog"
	"github.com/tpkeeper/solana-go-sdk/types"
)

func TestCreateMultisig(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	res, err := c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}
	feePayer := types.AccountFromPrivateKeyBytes([]byte{179, 95, 213, 234, 125, 167, 246, 188, 230, 134, 181, 219, 31, 146, 239, 75, 190, 124, 112, 93, 187, 140, 178, 119, 90, 153, 207, 178, 137, 5, 53, 71, 116, 28, 190, 12, 249, 238, 110, 135, 109, 21, 196, 36, 191, 19, 236, 175, 229, 204, 68, 180, 130, 102, 71, 239, 41, 53, 152, 159, 175, 124, 180, 6})

	multisigAccount := types.NewAccount()
	accountA := types.NewAccount()
	accountB := types.NewAccount()
	accountC := types.NewAccount()
	multiSigner, nonce, err := common.FindProgramAddress([][]byte{multisigAccount.PublicKey.Bytes()}, common.MultisigProgramID)
	if err != nil {
		t.Fatal(err)
	}
	owners := []common.PublicKey{accountA.PublicKey, accountB.PublicKey, accountC.PublicKey}

	rawTx, err := types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				multisigAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				200,
			), multisigprog.CreateMultisig(
				multisigAccount.PublicKey,
				owners,
				2,
				uint8(nonce),
			),
		},
		Signers:         []types.Account{feePayer, multisigAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}

	txSig, err := c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}

	t.Log("createMultisigAccount txHash:", txSig)
	t.Log("feePayer:", feePayer.PublicKey.ToBase58())
	t.Log("multisigAccount:", multisigAccount.PublicKey.ToBase58())

	// rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
	// 	Instructions: []types.Instruction{
	// 		multisigprog.CreateMultisig(
	// 			multisigAccount.PublicKey,
	// 			owners,
	// 			2,
	// 			uint8(nonce),
	// 		),
	// 	},
	// 	Signers:         []types.Account{multisigAccount},
	// 	FeePayer:        multisigAccount.PublicKey,
	// 	RecentBlockHash: res.Blockhash,
	// })
	// if err != nil {
	// 	t.Fatalf("generate tx error, err: %v\n", err)
	// }

	// txSig, err = c.SendRawTransaction(context.Background(), rawTx)
	// if err != nil {
	// 	t.Fatalf("send tx error, err: %v\n", err)
	// }
	// t.Log("createMultisig txHash:", txSig)
	t.Log("multiSigner:", multiSigner.ToBase58())

}

func TestCreateAccountEncode(t *testing.T) {
	data, err := common.SerializeData(struct {
		Instruction sysprog.Instruction
		Lamports    uint64
		Space       uint64
		Owner       common.PublicKey
	}{
		Instruction: sysprog.InstructionCreateAccount,
		Lamports:    2282880,
		Space:       200,
		Owner:       common.PublicKeyFromString("31tvk3urDFKEP2bBGGjq38wEVkGdRUjuc8oyZtzYVn9x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(data) != "0000000080d5220000000000c8000000000000001df216622f4fab96d8ebdbf5f12ff4eae1e001496ec1c29e5b4fb3e20f83da0b" {
		t.Fatal("CreateAccountEncode failed")
	}
}

func TestCreateMultisigEncode(t *testing.T) {
	// 	ownerA: EBGtN5bmAB62mFF3PdNkd8qkd11khf1BP6gJqicEnnBR
	// ownerB: GmNSbLgMhvDpfcT9gweUWrZCvbaJjQyAx3arZW8QFj3q
	// ownerC: Ans2xqmLQTCp4pFgPyQzaABnjsxPVJyir3pNik7hbo5G

	owners := []common.PublicKey{
		common.PublicKeyFromString("EBGtN5bmAB62mFF3PdNkd8qkd11khf1BP6gJqicEnnBR"),
		common.PublicKeyFromString("GmNSbLgMhvDpfcT9gweUWrZCvbaJjQyAx3arZW8QFj3q"),
		common.PublicKeyFromString("Ans2xqmLQTCp4pFgPyQzaABnjsxPVJyir3pNik7hbo5G"),
	}

	data, err := common.SerializeData(struct {
		Instruction multisigprog.Instruction
		Owners      []common.PublicKey
		Threshold   uint64
		Nonce       uint8
	}{
		Instruction: multisigprog.InstructionCreateMultisig,
		Owners:      owners,
		Threshold:   2,
		Nonce:       253,
	})
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(data) != "f4a3cfbe2a656d8303000000c3c9b333fb4f057651b8cf7659ecc656a7c13c1fbd7228cfad26a0fa00b78ca8ea3d1a6a4e7b75886741b7646704c33eab8532b4960991e873a7708781053acc9178e4668d1448e7269f1bf92acb4a001a669a8fb1839b839a5b9cd160d5f93f0200000000000000fd" {
		t.Fatal("TestCreateMultisigEncode failed")
	}
}

// 00000000c3c9b333fb4f057651b8cf7659ecc656a7c13c1fbd7228cfad26a0fa00b78ca8ea3d1a6a4e7b75886741b7646704c33eab8532b4960991e873a7708781053acc9178e4668d1448e7269f1bf92acb4a001a669a8fb1839b839a5b9cd160d5f93f0200000000000000fd
// 03000000c3c9b333fb4f057651b8cf7659ecc656a7c13c1fbd7228cfad26a0fa00b78ca8ea3d1a6a4e7b75886741b7646704c33eab8532b4960991e873a7708781053acc9178e4668d1448e7269f1bf92acb4a001a669a8fb1839b839a5b9cd160d5f93f0200000000000000fd
// f4a3cfbe2a656d83
