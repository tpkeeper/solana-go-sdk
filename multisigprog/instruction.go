package multisigprog

import (
	"github.com/tpkeeper/solana-go-sdk/common"
	"github.com/tpkeeper/solana-go-sdk/types"
)

type Instruction uint32

const (
	InstructionCreateMultisig Instruction = iota
	InstructionCreateTransaction
	InstructionApprove
	InstructionSetOwners
	InstructionChangeThreshold
	InstructionExecuteTransaction
)

func CreateMultisig(multisigAccount common.PublicKey, owners []common.PublicKey, threshold uint64, nonce uint8) types.Instruction {
	data, err := common.SerializeData(struct {
		Owners    []common.PublicKey
		Threshold uint64
		Nonce     uint8
	}{
		Owners:    owners,
		Threshold: threshold,
		Nonce:     nonce,
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
