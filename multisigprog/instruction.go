package multisigprog

import (
	"crypto/sha256"

	"github.com/tpkeeper/solana-go-sdk/common"
	"github.com/tpkeeper/solana-go-sdk/types"
)

type Instruction [8]byte

var (
	InstructionCreateMultisig     Instruction
	InstructionCreateTransaction  Instruction
	InstructionApprove            Instruction
	InstructionExecuteTransaction Instruction
)

func init() {
	createMultisigHash := sha256.Sum256([]byte("global::create_multisig"))
	copy(InstructionCreateMultisig[:], createMultisigHash[:8])
	createTransactionHash := sha256.Sum256([]byte("global::create_transaction"))
	copy(InstructionCreateTransaction[:], createTransactionHash[:8])
	approveHash := sha256.Sum256([]byte("global::approve"))
	copy(InstructionApprove[:], approveHash[:8])
	executeTransactionHash := sha256.Sum256([]byte("global::execute_transaction"))
	copy(InstructionExecuteTransaction[:], executeTransactionHash[:8])
}

func CreateMultisig(
	multisigAccount common.PublicKey,
	owners []common.PublicKey,
	threshold uint64,
	nonce uint8) types.Instruction {

	data, err := common.SerializeData(struct {
		Instruction Instruction
		Owners      []common.PublicKey
		Threshold   uint64
		Nonce       uint8
	}{
		Instruction: InstructionCreateMultisig,
		Owners:      owners,
		Threshold:   threshold,
		Nonce:       nonce,
	})
	if err != nil {
		panic(err)
	}

	return types.Instruction{
		ProgramID: common.MultisigProgramID,
		Accounts: []types.AccountMeta{
			{PubKey: multisigAccount, IsSigner: false, IsWritable: true},
			{PubKey: common.SysVarRentPubkey, IsSigner: false, IsWritable: false},
		},
		Data: data,
	}
}

type TransactionUsedAccount struct {
	Pubkey     common.PublicKey
	IsSigner   bool
	IsWritable bool
}

func CreateTransaction(
	txUsedProgramID common.PublicKey,
	txUsedAccounts []TransactionUsedAccount,
	txInstructionData []byte,
	multisigAccount common.PublicKey,
	txAccount common.PublicKey,
	proposalAccount common.PublicKey) types.Instruction {

	data, err := common.SerializeData(struct {
		Instruction       Instruction
		TxUsedProgramID   common.PublicKey
		TxUsedAccounts    []TransactionUsedAccount
		TxInstructionData []byte
	}{
		Instruction:       InstructionCreateTransaction,
		TxUsedProgramID:   txUsedProgramID,
		TxUsedAccounts:    txUsedAccounts,
		TxInstructionData: txInstructionData,
	})
	if err != nil {
		panic(err)
	}

	return types.Instruction{
		ProgramID: common.MultisigProgramID,
		Accounts: []types.AccountMeta{
			{PubKey: multisigAccount, IsSigner: false, IsWritable: false},
			{PubKey: txAccount, IsSigner: false, IsWritable: true},
			{PubKey: proposalAccount, IsSigner: true, IsWritable: false},
			{PubKey: common.SysVarRentPubkey, IsSigner: false, IsWritable: false},
		},
		Data: data,
	}
}
