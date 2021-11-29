package types

import (
	"encoding/json"
	"fmt"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"math/big"
	"testing"
)

func TestParams(t *testing.T) {
	to, err := address.NewFromString("t1lhtzzv6zbi6bpnsu76kfvsrxgyz4ojyxs5cev3q")
	if err != nil {
		panic(err)
	}
	to2, err := address.NewFromString("")
	if err != nil {
		panic(err)
	}
	var r = Receive{
		To:     to,
		Value:  abi.TokenAmount{Int:new(big.Int).SetUint64(1)},
		Method: 0,
		Params: nil,
	}
	var r2 = Receive{
		To:     to2,
		Value:  abi.TokenAmount{Int:new(big.Int).SetUint64(1)},
		Method: 0,
		Params: nil,
	}
	var test = ClassicalParams{Params:[]Receive{r, r2}}
	by, err := json.Marshal(test)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(by))
}
