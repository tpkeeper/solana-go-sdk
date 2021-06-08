package client

import (
	"context"
	"encoding/base64"
	"fmt"

	bin "github.com/dfuse-io/binary"
	"github.com/tpkeeper/solana-go-sdk/common"
)

var GetStakeAccountInfoConfigDefault = GetAccountInfoConfig{
	Encoding: GetAccountInfoConfigEncodingBase64,
	DataSlice: GetAccountInfoConfigDataSlice{
		Offset: 0,
		Length: 200,
	},
}

type StakeAccount struct {
	Type uint32
	Info struct {
		Meta struct {
			RentExemptReserve int64
			Authorized        struct {
				Staker     common.PublicKey
				Withdrawer common.PublicKey
				Lockup     struct {
					UnixTimeStamp int64
					Epoch         uint64
					Custodian     common.PublicKey
				}
			}
		}
		Stake struct {
			Delegation struct {
				Voter              common.PublicKey
				Stake              int64
				ActivationEpoch    int64
				DeactivationEpoch  int64
				WarmupCooldownRate float64
			}
			CreditsObserved uint64
		}
	}
}

func (s *Client) GetStakeAccountInfo(ctx context.Context, account string) (*StakeAccount, error) {

	accountInfo, err := s.GetAccountInfo(ctx, account, GetStakeAccountInfoConfigDefault)
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
