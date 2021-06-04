package client_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/tpkeeper/solana-go-sdk/client"
)


func TestAccountInfo(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	wg := sync.WaitGroup{}
	wg.Add(10)

	for i := 0; i < 10; i++ {
		go func() {
			accountInfo, err := c.GetMultisigTxAccountInfo(context.Background(), "D6nA6QHpYQDMeudHLwZqgwyCJfRSKWfzW4kyaKqmnsr4",
				client.GetAccountInfoConfig{
					Encoding: client.GetAccountInfoConfigEncodingBase64,
					DataSlice: client.GetAccountInfoConfigDataSlice{
						Offset: 0,
						Length: 1000,
					},
				})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(fmt.Printf("%+v", accountInfo))
			wg.Done()
		}()
	}

	wg.Wait()
}

func TestGetAccountInfo(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	accountInfo, err := c.GetStakeAccountInfo(context.Background(), "BNgbgqnVYLM97cD8XaW1ST6or56UnJB2HYXp5xwGHkTc",
		client.GetAccountInfoConfig{
			Encoding: client.GetAccountInfoConfigEncodingBase64,
			DataSlice: client.GetAccountInfoConfigDataSlice{
				Offset: 0,
				Length: 200,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%+v", accountInfo.Info.Stake.Delegation.Voter.ToBase58()))

	tx, err := c.GetConfirmedTransaction(context.Background(), "4nZS9xAHJtLrMHW3urxezd14NeRN8ux37uAA2nL8goSPexiXe3HPNSMaaZFPyeGXM9kodgW69uCtuDGrhWUYRZ8a")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(fmt.Sprintf("%+v", tx))

}