package fuzzer

import (
	"math/big"
	"strings"
	"testing"

	"github.com/1033309821/ECST/config"
	"github.com/1033309821/ECST/utils"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTxFuzzerFailsWhenReplayEndpointsPerGroupExceedsAvailableAccounts(t *testing.T) {
	cfg := &TxFuzzConfig{
		RPCEndpoint: "http://node-a:8545",
		MultiNode: &MultiNodeConfig{
			RPCEndpoints: []string{"http://node-a:8545", "http://node-b:8545"},
		},
		Replay: &TxReplayConfig{
			Enabled:           true,
			GroupCount:        1,
			EndpointsPerGroup: 2,
			TxType:            "legacy",
			PayloadSize:       16,
		},
	}

	_, err := NewTxFuzzer(cfg, []config.Account{
		mustReplayAccount(t, strings.Repeat("1", 64)),
	}, zeroLogger())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay")
	assert.Contains(t, err.Error(), "accounts")
}

func TestBuildReplayPlanProducesStableGroupIDFixedPayloadAndDistinctEndpointSenders(t *testing.T) {
	replayCfg := &TxReplayConfig{
		Enabled:           true,
		GroupCount:        2,
		EndpointsPerGroup: 2,
		TxType:            "dynamic",
		PayloadSize:       32,
	}
	multiNode := &MultiNodeConfig{
		RPCEndpoints: []string{"http://node-a:8545", "http://node-b:8545", "http://node-c:8545"},
		EndpointLabels: map[string]string{
			"http://node-a:8545": "geth",
			"http://node-b:8545": "reth",
			"http://node-c:8545": "erigon",
		},
	}
	accounts := []config.Account{
		mustReplayAccount(t, strings.Repeat("1", 64)),
		mustReplayAccount(t, strings.Repeat("2", 64)),
		mustReplayAccount(t, strings.Repeat("3", 64)),
	}

	first, err := buildTxReplayPlan(replayCfg, multiNode, accounts)
	require.NoError(t, err)
	second, err := buildTxReplayPlan(replayCfg, multiNode, accounts)
	require.NoError(t, err)
	require.Len(t, first.Groups, 2)
	require.Len(t, second.Groups, 2)

	assert.Equal(t, first.Groups[0].ID, second.Groups[0].ID)
	assert.Equal(t, first.Groups[0].TxType, second.Groups[0].TxType)
	assert.Equal(t, first.Groups[0].To, second.Groups[0].To)
	assert.Equal(t, first.Groups[0].Payload, second.Groups[0].Payload)
	require.Len(t, first.Groups[0].Assignments, 2)
	assert.Equal(t, first.Groups[0].Payload, first.Groups[0].Assignments[0].Payload)
	assert.Equal(t, first.Groups[0].Payload, first.Groups[0].Assignments[1].Payload)

	senderA := first.Groups[0].Assignments[0].Account.Address
	senderB := first.Groups[0].Assignments[1].Account.Address
	assert.NotEqual(t, senderA, senderB, "replay senders must be distinct per endpoint")
	assert.Equal(t, 0, first.Groups[0].Assignments[0].EndpointIndex)
	assert.Equal(t, 1, first.Groups[0].Assignments[1].EndpointIndex)
	assert.Equal(t, "geth", first.Groups[0].Assignments[0].Client)
	assert.Equal(t, "reth", first.Groups[0].Assignments[1].Client)
	assert.Equal(t, first.Groups[0].Assignments[0].Endpoint, first.Groups[1].Assignments[0].Endpoint)
	assert.Equal(t, first.Groups[0].Assignments[0].Account.Address, first.Groups[1].Assignments[0].Account.Address)
}

func zeroLogger() utils.Logger {
	return utils.Logger{}
}

func mustReplayAccount(t *testing.T, hexKey string) config.Account {
	t.Helper()
	privateKey, err := crypto.HexToECDSA(hexKey)
	require.NoError(t, err)
	return config.Account{
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
		PrivateKey: hexKey,
	}
}

func TestValidateReplayFundingRejectsZeroBalanceAccounts(t *testing.T) {
	cfg := &TxFuzzConfig{
		MultiNode: &MultiNodeConfig{
			RPCEndpoints: []string{"http://node-a:8545", "http://node-b:8545"},
		},
		Replay: &TxReplayConfig{
			Enabled:           true,
			GroupCount:        1,
			EndpointsPerGroup: 2,
			TxType:            "legacy",
			PayloadSize:       16,
		},
	}
	accounts := []config.Account{
		mustReplayAccount(t, strings.Repeat("1", 64)),
		mustReplayAccount(t, strings.Repeat("2", 64)),
	}
	clients := map[string]txRPCClient{
		"http://node-a:8545": &fakeTxRPCClient{balance: bigIntString("0")},
		"http://node-b:8545": &fakeTxRPCClient{balance: bigIntString("5")},
	}

	err := validateReplayFunding(cfg, accounts, clients)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not funded")
}

func TestValidateReplayConfigRejectsDuplicateReplaySenderAddresses(t *testing.T) {
	cfg := &TxFuzzConfig{
		MultiNode: &MultiNodeConfig{
			RPCEndpoints: []string{"http://node-a:8545", "http://node-b:8545"},
		},
		Replay: &TxReplayConfig{
			Enabled:           true,
			GroupCount:        1,
			EndpointsPerGroup: 2,
			TxType:            "legacy",
			PayloadSize:       16,
		},
	}
	accounts := []config.Account{
		mustReplayAccount(t, strings.Repeat("1", 64)),
		mustReplayAccount(t, strings.Repeat("1", 64)),
	}

	err := validateReplayConfig(cfg, accounts)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "distinct")
}

func TestReplayGasLimitCoversFloorDataGasForDynamicPayload(t *testing.T) {
	payload := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	}

	gasLimit, err := replayGasLimit(types.DynamicFeeTxType, payload, nil)

	require.NoError(t, err)
	floorDataGas, err := core.FloorDataGas(payload)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, gasLimit, floorDataGas)
}

func bigIntString(v string) *big.Int {
	n, _ := new(big.Int).SetString(v, 10)
	return n
}
