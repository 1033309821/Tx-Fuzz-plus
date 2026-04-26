package main

import (
	"math/big"
	"testing"
	"time"

	"github.com/1033309821/ECST/config"
	"github.com/stretchr/testify/assert"
)

func TestBuildTxFuzzConfigUsesAllRPCEndpointsForMultiNodeScheduling(t *testing.T) {
	txCfg := config.TxFuzzingConfig{
		RPCEndpoint:     "http://stale:8545",
		RPCEndpoints:    []string{"http://node-a:8545", "http://node-b:8545"},
		ChainID:         3151908,
		MaxGasPrice:     200,
		MaxGasLimit:     8_000_000,
		TxPerSecond:     10,
		FuzzDurationSec: 60,
		Seed:            99,
	}

	got := buildTxFuzzConfig(txCfg)

	assert.Equal(t, "http://node-a:8545", got.RPCEndpoint)
	assert.Equal(t, big.NewInt(200), got.MaxGasPrice)
	assert.Equal(t, 60*time.Second, got.FuzzDuration)
	if assert.NotNil(t, got.MultiNode) {
		assert.Equal(t, []string{"http://node-a:8545", "http://node-b:8545"}, got.MultiNode.RPCEndpoints)
		assert.Equal(t, 0.5, got.MultiNode.LoadDistribution["http://node-a:8545"])
		assert.Equal(t, 0.5, got.MultiNode.LoadDistribution["http://node-b:8545"])
		assert.True(t, got.MultiNode.FailoverEnabled)
	}
}

func TestBuildTxFuzzConfigFallsBackToSingleEndpoint(t *testing.T) {
	txCfg := config.TxFuzzingConfig{
		RPCEndpoint:     "http://single:8545",
		MaxGasPrice:     200,
		MaxGasLimit:     8_000_000,
		TxPerSecond:     10,
		FuzzDurationSec: 60,
	}

	got := buildTxFuzzConfig(txCfg)

	assert.Equal(t, "http://single:8545", got.RPCEndpoint)
	assert.Nil(t, got.MultiNode)
}

func TestBuildTxFuzzConfigMapsTxResultRecordingOptions(t *testing.T) {
	txCfg := config.TxFuzzingConfig{
		RPCEndpoint:             "http://single:8545",
		FuzzDurationSec:         60,
		TxResultMappingEnabled:  true,
		TxResultLogPath:         "output/custom-attempts.jsonl",
		ReceiptDrainDurationSec: 7,
		ConfirmBlocks:           2,
	}

	got := buildTxFuzzConfig(txCfg)

	assert.Equal(t, "output/custom-attempts.jsonl", got.TxResultLogPath)
	assert.Equal(t, 7*time.Second, got.ReceiptDrainDuration)
	assert.True(t, got.EnableTracking)
	assert.Equal(t, uint64(2), got.ConfirmBlocks)
}

func TestBuildTxFuzzConfigMapsReplayLaneConfig(t *testing.T) {
	txCfg := config.TxFuzzingConfig{
		RPCEndpoints: []string{"http://node-a:8545", "http://node-b:8545"},
		MaxGasPrice:  200,
		MaxGasLimit:  8_000_000,
		Replay: config.TxReplayConfig{
			Enabled:           true,
			GroupCount:        3,
			EndpointsPerGroup: 2,
			TxType:            "dynamic",
			PayloadSize:       48,
		},
		EndpointLabels: map[string]string{
			"http://node-a:8545": "geth",
			"http://node-b:8545": "reth",
		},
	}

	got := buildTxFuzzConfig(txCfg)

	if assert.NotNil(t, got.MultiNode) {
		assert.Equal(t, "geth", got.MultiNode.EndpointLabels["http://node-a:8545"])
		assert.Equal(t, "reth", got.MultiNode.EndpointLabels["http://node-b:8545"])
	}
	if assert.NotNil(t, got.Replay) {
		assert.True(t, got.Replay.Enabled)
		assert.Equal(t, 3, got.Replay.GroupCount)
		assert.Equal(t, 2, got.Replay.EndpointsPerGroup)
		assert.Equal(t, "dynamic", got.Replay.TxType)
		assert.Equal(t, 48, got.Replay.PayloadSize)
	}
	assert.True(t, got.EnableTracking, "replay mode needs actual-outcome tracking enabled")
}
