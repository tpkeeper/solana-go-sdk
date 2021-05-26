package multisigprog

import (
	"crypto/sha256"

	"github.com/tpkeeper/solana-go-sdk/common"
	"github.com/tpkeeper/solana-go-sdk/types"
)

type Instruction [8]byte

var (
	InstructionCreateMultisig Instruction
	// InstructionCreateTransaction
	// InstructionApprove
	// InstructionSetOwners
	// InstructionChangeThreshold
	// InstructionExecuteTransaction
)

func init() {
	createMultisigHash := sha256.Sum256([]byte("global::create_multisig"))
	copy(InstructionCreateMultisig[:], createMultisigHash[:8])
}

func CreateMultisig(multisigAccount common.PublicKey, owners []common.PublicKey, threshold uint64, nonce uint8) types.Instruction {
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
			{PubKey: multisigAccount, IsSigner: true, IsWritable: true},
			{PubKey: common.SysVarRentPubkey, IsSigner: false, IsWritable: false},
		},
		Data: data,
	}
}
