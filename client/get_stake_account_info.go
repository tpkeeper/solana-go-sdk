package client

import (
	"context"
	"encoding/base64"
	"fmt"

	bin "github.com/dfuse-io/binary"
	"github.com/tpkeeper/solana-go-sdk/common"
)

type StakeAccount struct {
	Type uint32
	Info struct {
		Meta struct {
			RentExemptReserve uint64
			Authorized        struct {
				Staker     common.PublicKey
				Withdrawer common.PublicKey
				Lockup     struct {
					UnixTimeStamp uint64
					Epoch         uint64
					Custodian     common.PublicKey
				}
			}
		}
		Stake struct {
			Delegation struct {
				Voter              common.PublicKey
				Stake              uint64
				ActivationEpoch    uint64
				DeactivationEpoch  uint64
				WarmupCooldownRate uint64
			}
			CreditsObserved uint64
		}
	}
}

func (s *Client) GetStakeAccountInfo(ctx context.Context, account string,
	cfg GetAccountInfoConfig) (*StakeAccount, error) {

	accountInfo, err := s.GetAccountInfo(ctx, account, cfg)
	if err != nil {
		return nil, err
	}

	accountDataInterface, ok := accountInfo.Data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("account data err")
	}
	if len(accountDataInterface) != 2 {
		return nil, fmt.Errorf("account data length err")
	}
	accountDataBase64, ok := accountDataInterface[0].(string)
	if !ok {
		return nil, fmt.Errorf("get account base64 failed")
	}

	accountDataBts, err := base64.StdEncoding.DecodeString(accountDataBase64)
	if err != nil {
		return nil, err
	}
	if len(accountDataBts) <= 8 {
		return nil, fmt.Errorf("no account data bytes")
	}

	stakeAccountInfo := StakeAccount{}
	err = bin.NewDecoder(accountDataBts).Decode(&stakeAccountInfo)
	if err != nil {
		return nil, err
	}
	return &stakeAccountInfo, nil
}
