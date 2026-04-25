package fuzzer

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
)

type txPreflightClient interface {
	EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error)
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}
