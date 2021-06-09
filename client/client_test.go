package client_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/tpkeeper/solana-go-sdk/client"
	"github.com/tpkeeper/solana-go-sdk/common"
)

func TestAccountInfo(t *testing.T) {
	c := client.NewClient(client.DevnetRPCEndpoint)

	wg := sync.WaitGroup{}
	wg.Add(10)

	for i := 0; i < 10; i++ {
		go func() {
			accountInfo, err := c.GetMultisigTxAccountInfo(context.Background(), "D6nA6QHpYQDMeudHLwZqgwyCJfRSKWfzW4kyaKqmnsr4")
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
	account, err := c.GetAccountInfo(context.Background(), "DiPx1Vyo5khyG8XKTc8Tu4fL9qc57VSqfr7qh3xLxqjX",
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

	t.Log(account)

	accountInfo, err := c.GetStakeAccountInfo(context.Background(), "DiPx1Vyo5khyG8XKTc8Tu4fL9qc57VSqfr7qh3xLxqjX")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%+v", accountInfo))


	accountInfo, err = c.GetStakeAccountInfo(context.Background(), "mNzHTv7KtARcYyJiaXH3SU2oSnLoXKVJxcxDknC2kae")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%+v", accountInfo))

	accountInfo, err = c.GetStakeAccountInfo(context.Background(), "HoyKcWNCz77ZFvXoJHjHZN1q9czQcBHq8McFpLSCzDHp")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%+v", accountInfo))
	
	

	tx, err := c.GetConfirmedTransaction(context.Background(), "4nZS9xAHJtLrMHW3urxezd14NeRN8ux37uAA2nL8goSPexiXe3HPNSMaaZFPyeGXM9kodgW69uCtuDGrhWUYRZ8a")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(fmt.Sprintf("%+v", tx))
	t.Log(hex.EncodeToString(common.PublicKeyFromString("DRtThFS61F2WhHkT5woKFhNTtiLHDjss3aykKQkmZ7wy").Bytes()))
}
