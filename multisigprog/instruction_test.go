package multisigprog_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/tpkeeper/solana-go-sdk/client"
	"github.com/tpkeeper/solana-go-sdk/common"
	"github.com/tpkeeper/solana-go-sdk/multisigprog"
	"github.com/tpkeeper/solana-go-sdk/stakeprog"
	"github.com/tpkeeper/solana-go-sdk/sysprog"
	"github.com/tpkeeper/solana-go-sdk/types"
)

func TestMultisigTransfer(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	res, err := c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}
	feePayer := types.AccountFromPrivateKeyBytes([]byte{179, 95, 213, 234, 125, 167, 246, 188, 230, 134, 181, 219, 31, 146, 239, 75, 190, 124, 112, 93, 187, 140, 178, 119, 90, 153, 207, 178, 137, 5, 53, 71, 116, 28, 190, 12, 249, 238, 110, 135, 109, 21, 196, 36, 191, 19, 236, 175, 229, 204, 68, 180, 130, 102, 71, 239, 41, 53, 152, 159, 175, 124, 180, 6})

	_, err = c.RequestAirdrop(context.Background(), feePayer.PublicKey.ToBase58(), 10e9)
	if err != nil {
		t.Fatal(err)
	}

	multisigAccount := types.NewAccount()
	transactionAccount := types.NewAccount()
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
			),
			multisigprog.CreateMultisig(
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
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err := c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}

	t.Log("createMultisig txHash:", txHash)
	t.Log("feePayer:", feePayer.PublicKey.ToBase58())
	t.Log("multisig account:", multisigAccount.PublicKey.ToBase58())
	t.Log("transaction account:", transactionAccount.PublicKey.ToBase58())
	t.Log("multiSigner:", multiSigner.ToBase58())
	t.Log("accountA", accountA.PublicKey.ToBase58())
	t.Log("accountB", accountB.PublicKey.ToBase58())
	t.Log("accountC", accountC.PublicKey.ToBase58())

	//send 2 sol to account multisigner
	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.Transfer(
				feePayer.PublicKey,
				multiSigner,
				2000000000,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	txUsedAccounts := []multisigprog.TransactionUsedAccount{
		{
			Pubkey:     multiSigner,
			IsSigner:   true,
			IsWritable: true,
		},
		{
			Pubkey:     accountA.PublicKey,
			IsSigner:   false,
			IsWritable: true,
		},
	}

	transferInstruct := sysprog.Transfer(multiSigner, accountA.PublicKey, 1000000000)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				transactionAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				1000,
			),
		},
		Signers:         []types.Account{feePayer, transactionAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate create account tx error, err: %v\n", err)
	}
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("create transaction account hash ", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.CreateTransaction(
				common.SystemProgramID,
				txUsedAccounts,
				transferInstruct.Data,
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountA.PublicKey,
			),
		},
		Signers:         []types.Account{accountA, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate createTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Create Transaction txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.Approve(
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountB.PublicKey,
			),
		},
		Signers:         []types.Account{accountB, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate Approve tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Approve txHash:", txHash)

	remainingAccounts := []types.AccountMeta{
		{
			PubKey:     multiSigner,
			IsWritable: true,
			IsSigner:   false,
		},
		{
			PubKey:     accountA.PublicKey,
			IsWritable: true,
			IsSigner:   false,
		},
		{
			PubKey:     common.SystemProgramID,
			IsWritable: false,
			IsSigner:   false,
		},

		{
			PubKey:     common.MultisigProgramID,
			IsWritable: false,
			IsSigner:   false,
		},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.ExecuteTransaction(
				multisigAccount.PublicKey,
				multiSigner,
				transactionAccount.PublicKey,
				remainingAccounts,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate ExecuteTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("ExecuteTransaction txHash:", txHash)

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

func TestCreateTransactionEncode(t *testing.T) {
	multiSigner := common.PublicKeyFromString("HqJYsLD9pUVU2k6SsVXYDUbMhxo8rSU8saz2dTHhHyrt")
	accountA := common.PublicKeyFromString("F5awAMuj12auUYowaDwJHmuyKu5wxVqSn6Px87Mq5ymt")
	txUsedAccounts := []multisigprog.TransactionUsedAccount{
		{
			Pubkey:     multiSigner,
			IsSigner:   true,
			IsWritable: true,
		},
		{
			Pubkey:     accountA,
			IsSigner:   false,
			IsWritable: true,
		},
	}
	transferInstruct := sysprog.Transfer(multiSigner, accountA, 1000000000)

	data, err := common.SerializeData(struct {
		Instruction       multisigprog.Instruction
		TxUsedProgramID   common.PublicKey
		TxUsedAccounts    []multisigprog.TransactionUsedAccount
		TxInstructionData []byte
	}{
		Instruction:       multisigprog.InstructionCreateTransaction,
		TxUsedProgramID:   common.SystemProgramID,
		TxUsedAccounts:    txUsedAccounts,
		TxInstructionData: transferInstruct.Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("hex", hex.EncodeToString(data))
	t.Log("hex", hex.EncodeToString(transferInstruct.Data))
	if hex.EncodeToString(data) != "9207a387662c6afa000000000000000000000000000000000000000000000000000000000000000002000000fa1ab67f21842ba007d95d580b0e2f10158213914c25297ef6c2ca8b64339dad0101d1304f2dec3a966aef913b4fa7128a5967a3388e7db6fbfd544708934179642b00010c0000000200000000ca9a3b00000000" {
		t.Fatal("TestCreateMultisigEncode failed")
	}
}

func TestDecodeBlockHash(t *testing.T) {
	bts, _ := base58.Decode("5BHS9nELmmRXU3PjHPPLvq8WZFej3QbzD7sm3XGdnTe9")
	t.Log("bts", hex.EncodeToString(bts))
	a0, _ := hex.DecodeString("741cbe0cf9ee6e876d15c424bf13ecafe5cc44b4826647ef2935989faf7cb406")
	t.Log(base58.Encode(a0))
	a1, _ := hex.DecodeString("ad18ced39b21a5db962fc624926dbd329d9a366c1247e8d46afabcf4b6f85a04")
	t.Log(base58.Encode(a1))
	a2, _ := hex.DecodeString("730ca98ea9102311f5fed863ae1b5d9e2611185044c54391e7f49d2de73bc19e")
	t.Log(base58.Encode(a2))
	a3, _ := hex.DecodeString("06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000")
	t.Log(base58.Encode(a3))
	a4, _ := hex.DecodeString("489f06d61e0eacb7c70cb77bc61378b4592404d566a7f695c859f673f8fff9c0")
	t.Log(base58.Encode(a4))
	a5, _ := hex.DecodeString("8c78a414865fd46375d0ff861a917425f375a69ca3ec51a46223f58d3af8efd9")
	t.Log(base58.Encode(a5))
	a7, _ := hex.DecodeString("02ecfa8e8d9c1b690ce8ecdbcbffcab4ee3cbbd28a1bfbc461e2a5c7c72fd6076e6c198e875bb944041f768938cc701c134881dfe5ea899e15c6b65ce69d78aa0cb53d7a26c46a66dcffafcbfde4e816952dea4fb7c6f6428ac2741a498a4ee05386dea9b6fc0c6672ceb017ab0d72fdec67e2e0358f3884fcb7e46d14265cb30602010306741cbe0cf9ee6e876d15c424bf13ecafe5cc44b4826647ef2935989faf7cb406ad18ced39b21a5db962fc624926dbd329d9a366c1247e8d46afabcf4b6f85a04730ca98ea9102311f5fed863ae1b5d9e2611185044c54391e7f49d2de73bc19e06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000489f06d61e0eacb7c70cb77bc61378b4592404d566a7f695c859f673f8fff9c08c78a414865fd46375d0ff861a917425f375a69ca3ec51a46223f58d3af8efd953da38e1d967a736d37c32a2ca9e82f41dd00f416db8f2d48080a06c7f29cc620104040502010380019207a387662c6afa000000000000000000000000000000000000000000000000000000000000000002000000c886d0a583199cc093143c89901fa9f4d554aefd1e24d3ccba1e780d36a937ae0101ad18ced39b21a5db962fc624926dbd329d9a366c1247e8d46afabcf4b6f85a0400010c0000000200000000ca9a3b00000000")
	t.Log(base58.Encode(a7))

}

func TestGetTx(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)
	tx, err := c.GetConfirmedTransaction(context.Background(), "3F6Dkh1JfX8zaVQgbRSNqwigqhGSmErvWPRz7D27CTUcWpf1j2dkWkc4m6u7K6gehqnGp1DPTAvgJELF7QpDaYje")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%+v", tx.Transaction.Message))
}

func TestMultisigStake(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	res, err := c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}
	feePayer := types.AccountFromPrivateKeyBytes([]byte{179, 95, 213, 234, 125, 167, 246, 188, 230, 134, 181, 219, 31, 146, 239, 75, 190, 124, 112, 93, 187, 140, 178, 119, 90, 153, 207, 178, 137, 5, 53, 71, 116, 28, 190, 12, 249, 238, 110, 135, 109, 21, 196, 36, 191, 19, 236, 175, 229, 204, 68, 180, 130, 102, 71, 239, 41, 53, 152, 159, 175, 124, 180, 6})

	_, err = c.RequestAirdrop(context.Background(), feePayer.PublicKey.ToBase58(), 10e9)
	if err != nil {
		t.Fatal(err)
	}

	multisigAccount := types.NewAccount()
	transactionAccount := types.NewAccount()
	stakeAccount := types.NewAccount()
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
				stakeAccount.PublicKey,
				common.StakeProgramID,
				2000000000,
				200,
			),
			stakeprog.Initialize(
				stakeAccount.PublicKey,
				stakeprog.Authorized{
					Staker:     multiSigner,
					Withdrawer: multiSigner,
				},
				stakeprog.Lockup{},
			),
		},
		Signers:         []types.Account{feePayer, stakeAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err := c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("createStakeAccount txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				multisigAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				200,
			),
			multisigprog.CreateMultisig(
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
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("createMultisig txHash:", txHash)

	t.Log("feePayer:", feePayer.PublicKey.ToBase58())
	t.Log("multisig account:", multisigAccount.PublicKey.ToBase58())
	t.Log("transaction account:", transactionAccount.PublicKey.ToBase58())
	t.Log("multiSigner:", multiSigner.ToBase58())
	t.Log("stakeAccount", stakeAccount.PublicKey.ToBase58())
	t.Log("accountA", accountA.PublicKey.ToBase58())
	t.Log("accountB", accountB.PublicKey.ToBase58())
	t.Log("accountC", accountC.PublicKey.ToBase58())

	//send 2 sol to account multisigner
	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.Transfer(
				feePayer.PublicKey,
				multiSigner,
				2000000000,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("send sol to multisigner txHash:", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	validatorPubkey := common.PublicKeyFromString("5MMCR4NbTZqjthjLGywmeT66iwE9J9f7kjtxzJjwfUx2")
	stakeInstruction := stakeprog.DelegateStake(stakeAccount.PublicKey, multiSigner, validatorPubkey)
	txUsedAccounts := []multisigprog.TransactionUsedAccount{
		{Pubkey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{Pubkey: validatorPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.SysVarClockPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.SysVarStakeHistoryPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.StakeConfigPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: multiSigner, IsSigner: true, IsWritable: false},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				transactionAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				1000,
			),
		},
		Signers:         []types.Account{feePayer, transactionAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate create account tx error, err: %v\n", err)
	}
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("create transaction account hash ", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.CreateTransaction(
				common.StakeProgramID,
				txUsedAccounts,
				stakeInstruction.Data,
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountA.PublicKey,
			),
		},
		Signers:         []types.Account{accountA, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate createTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Create Transaction txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.Approve(
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountB.PublicKey,
			),
		},
		Signers:         []types.Account{accountB, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate Approve tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Approve txHash:", txHash)

	remainingAccounts := []types.AccountMeta{

		{
			PubKey:     common.StakeProgramID,
			IsWritable: false,
			IsSigner:   false,
		},

		{
			PubKey:     common.MultisigProgramID,
			IsWritable: false,
			IsSigner:   false,
		},
		{PubKey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{PubKey: validatorPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.SysVarClockPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.SysVarStakeHistoryPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.StakeConfigPubkey, IsSigner: false, IsWritable: false},
		{PubKey: multiSigner, IsSigner: false, IsWritable: false},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.ExecuteTransaction(
				multisigAccount.PublicKey,
				multiSigner,
				transactionAccount.PublicKey,
				remainingAccounts,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate ExecuteTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("ExecuteTransaction txHash:", txHash)

}

func TestMultisigSplit(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	res, err := c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}
	feePayer := types.AccountFromPrivateKeyBytes([]byte{179, 95, 213, 234, 125, 167, 246, 188, 230, 134, 181, 219, 31, 146, 239, 75, 190, 124, 112, 93, 187, 140, 178, 119, 90, 153, 207, 178, 137, 5, 53, 71, 116, 28, 190, 12, 249, 238, 110, 135, 109, 21, 196, 36, 191, 19, 236, 175, 229, 204, 68, 180, 130, 102, 71, 239, 41, 53, 152, 159, 175, 124, 180, 6})

	_, err = c.RequestAirdrop(context.Background(), feePayer.PublicKey.ToBase58(), 10e9)
	if err != nil {
		t.Fatal(err)
	}

	multisigAccount := types.NewAccount()
	transactionAccount := types.NewAccount()
	splitTransactionAccount := types.NewAccount()
	stakeAccount := types.NewAccount()
	splitStakeAccount := types.NewAccount()
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
				stakeAccount.PublicKey,
				common.StakeProgramID,
				2000000000,
				200,
			),
			stakeprog.Initialize(
				stakeAccount.PublicKey,
				stakeprog.Authorized{
					Staker:     multiSigner,
					Withdrawer: multiSigner,
				},
				stakeprog.Lockup{},
			),
		},
		Signers:         []types.Account{feePayer, stakeAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err := c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("createStakeAccount txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				multisigAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				200,
			),
			multisigprog.CreateMultisig(
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
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("createMultisig txHash:", txHash)

	t.Log("feePayer:", feePayer.PublicKey.ToBase58())
	t.Log("multisig account:", multisigAccount.PublicKey.ToBase58())
	t.Log("transaction account:", transactionAccount.PublicKey.ToBase58())
	t.Log("splitTransaction account:", splitTransactionAccount.PublicKey.ToBase58())
	t.Log("multiSigner:", multiSigner.ToBase58())
	t.Log("stakeAccount", stakeAccount.PublicKey.ToBase58())
	t.Log("splitStakeAccount", splitStakeAccount.PublicKey.ToBase58())
	t.Log("accountA", accountA.PublicKey.ToBase58())
	t.Log("accountB", accountB.PublicKey.ToBase58())
	t.Log("accountC", accountC.PublicKey.ToBase58())

	//send 2 sol to account multisigner
	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.Transfer(
				feePayer.PublicKey,
				multiSigner,
				2000000000,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate tx error, err: %v\n", err)
	}
	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("send sol to multisigner txHash:", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	validatorPubkey := common.PublicKeyFromString("5MMCR4NbTZqjthjLGywmeT66iwE9J9f7kjtxzJjwfUx2")
	stakeInstruction := stakeprog.DelegateStake(stakeAccount.PublicKey, multiSigner, validatorPubkey)
	txUsedAccounts := []multisigprog.TransactionUsedAccount{
		{Pubkey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{Pubkey: validatorPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.SysVarClockPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.SysVarStakeHistoryPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: common.StakeConfigPubkey, IsSigner: false, IsWritable: false},
		{Pubkey: multiSigner, IsSigner: true, IsWritable: false},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				transactionAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				1000,
			),
		},
		Signers:         []types.Account{feePayer, transactionAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate create account tx error, err: %v\n", err)
	}
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("create transaction account hash ", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.CreateTransaction(
				common.StakeProgramID,
				txUsedAccounts,
				stakeInstruction.Data,
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountA.PublicKey,
			),
		},
		Signers:         []types.Account{accountA, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate createTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Create Transaction txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.Approve(
				multisigAccount.PublicKey,
				transactionAccount.PublicKey,
				accountB.PublicKey,
			),
		},
		Signers:         []types.Account{accountB, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate Approve tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Approve txHash:", txHash)

	remainingAccounts := []types.AccountMeta{

		{
			PubKey:     common.StakeProgramID,
			IsWritable: false,
			IsSigner:   false,
		},

		{
			PubKey:     common.MultisigProgramID,
			IsWritable: false,
			IsSigner:   false,
		},
		{PubKey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{PubKey: validatorPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.SysVarClockPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.SysVarStakeHistoryPubkey, IsSigner: false, IsWritable: false},
		{PubKey: common.StakeConfigPubkey, IsSigner: false, IsWritable: false},
		{PubKey: multiSigner, IsSigner: false, IsWritable: false},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.ExecuteTransaction(
				multisigAccount.PublicKey,
				multiSigner,
				transactionAccount.PublicKey,
				remainingAccounts,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate ExecuteTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("ExecuteTransaction txHash:", txHash)

	//================================================
	// split operate

	splitInstruction := stakeprog.Split(stakeAccount.PublicKey, multiSigner, splitStakeAccount.PublicKey, 1e8)
	txUsedAccounts = []multisigprog.TransactionUsedAccount{
		{Pubkey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{Pubkey: splitStakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{Pubkey: multiSigner, IsSigner: true, IsWritable: false},
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				splitTransactionAccount.PublicKey,
				common.MultisigProgramID,
				1000000000,
				1000,
			),
			sysprog.CreateAccount(
				feePayer.PublicKey,
				splitStakeAccount.PublicKey,
				common.StakeProgramID,
				1000000000,
				200,
			),
		},
		Signers:         []types.Account{feePayer, splitTransactionAccount, splitStakeAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		t.Fatalf("generate create account tx error, err: %v\n", err)
	}
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("create transaction account hash ", txHash)

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.CreateTransaction(
				common.StakeProgramID,
				txUsedAccounts,
				splitInstruction.Data,
				multisigAccount.PublicKey,
				splitTransactionAccount.PublicKey,
				accountA.PublicKey,
			),
		},
		Signers:         []types.Account{accountA, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate createTransaction tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Create Transaction txHash:", txHash)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.Approve(
				multisigAccount.PublicKey,
				splitTransactionAccount.PublicKey,
				accountB.PublicKey,
			),
		},
		Signers:         []types.Account{accountB, feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate Approve tx error, err: %v\n", err)
	}

	// t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("Approve txHash:", txHash)

	remainingAccounts = []types.AccountMeta{
		{PubKey: stakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{PubKey: splitStakeAccount.PublicKey, IsSigner: false, IsWritable: true},
		{PubKey: multiSigner, IsSigner: false, IsWritable: false},
		{PubKey: common.StakeProgramID, IsWritable: false, IsSigner: false},
	}

	res, err = c.GetRecentBlockhash(context.Background())
	if err != nil {
		t.Fatalf("get recent block hash error, err: %v\n", err)
	}

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			multisigprog.ExecuteTransaction(
				multisigAccount.PublicKey,
				multiSigner,
				splitTransactionAccount.PublicKey,
				remainingAccounts,
			),
		},
		Signers:         []types.Account{feePayer},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})

	if err != nil {
		t.Fatalf("generate ExecuteTransaction tx error, err: %v\n", err)
	}

	t.Log("rawtx base58:", base58.Encode(rawTx))
	txHash, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		t.Fatalf("send tx error, err: %v\n", err)
	}
	t.Log("ExecuteTransaction txHash:", txHash)

}

func TestSplit(t *testing.T) {
	splitNewToNew()
}

func splitNewToNew() {
	c := client.NewClient(client.DevnetRPCEndpoint)

	res, err := c.GetRecentBlockhash(context.Background())
	if err != nil {
		log.Fatalf("get recent block hash error, err: %v\n", err)
	}
	feePayer := types.AccountFromPrivateKeyBytes([]byte{179, 95, 213, 234, 125, 167, 246, 188, 230, 134, 181, 219, 31, 146, 239, 75, 190, 124, 112, 93, 187, 140, 178, 119, 90, 153, 207, 178, 137, 5, 53, 71, 116, 28, 190, 12, 249, 238, 110, 135, 109, 21, 196, 36, 191, 19, 236, 175, 229, 204, 68, 180, 130, 102, 71, 239, 41, 53, 152, 159, 175, 124, 180, 6})

	c.RequestAirdrop(context.Background(), feePayer.PublicKey.ToBase58(), 10e9)

	newStakeAccount := types.NewAccount()
	newSplitStakeAccount := types.NewAccount()

	rawTx, err := types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				newStakeAccount.PublicKey,
				common.StakeProgramID,
				2000000000,
				200,
			),
			stakeprog.Initialize(
				newStakeAccount.PublicKey,
				stakeprog.Authorized{
					Staker:     feePayer.PublicKey,
					Withdrawer: feePayer.PublicKey,
				},
				stakeprog.Lockup{},
			),
		},
		Signers:         []types.Account{feePayer, newStakeAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		log.Fatalf("generate tx error, err: %v\n", err)
	}

	txSig, err := c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		log.Fatalf("send tx error, err: %v\n", err)
	}

	log.Println("txHash:", txSig)

	rawTx, err = types.CreateRawTransaction(types.CreateRawTransactionParam{
		Instructions: []types.Instruction{
			sysprog.CreateAccount(
				feePayer.PublicKey,
				newSplitStakeAccount.PublicKey,
				common.StakeProgramID,
				1000000000,
				200,
			),
			stakeprog.Split(
				newStakeAccount.PublicKey,
				feePayer.PublicKey,
				newSplitStakeAccount.PublicKey,
				1e8,
			),
		},
		Signers:         []types.Account{feePayer, newSplitStakeAccount},
		FeePayer:        feePayer.PublicKey,
		RecentBlockHash: res.Blockhash,
	})
	if err != nil {
		log.Fatalf("generate tx error, err: %v\n", err)
	}

	txSig, err = c.SendRawTransaction(context.Background(), rawTx)
	if err != nil {
		log.Fatalf("send tx error, err: %v\n", err)
	}

	log.Println("txHash:", txSig)
}
