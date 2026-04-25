package fuzzer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPreflightCallMsgUsesLegacyFeeFieldsOnly(t *testing.T) {
	attempt := &txAttemptContext{
		Account: common.HexToAddress("0xabc"),
		Tx:      types.NewTransaction(1, common.HexToAddress("0xfeed"), big.NewInt(7), 21_000, big.NewInt(9), []byte{0x01}),
	}

	call := buildPreflightCallMsg(attempt)

	require.NotNil(t, call.GasPrice)
	assert.Equal(t, big.NewInt(9), call.GasPrice)
	assert.Nil(t, call.GasFeeCap)
	assert.Nil(t, call.GasTipCap)
}

func TestBuildPreflightCallMsgUsesDynamicFeeFieldsOnly(t *testing.T) {
	attempt := &txAttemptContext{
		Account: common.HexToAddress("0xabc"),
		Tx: types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(3151908),
			Nonce:     2,
			To:        ptrAddress(common.HexToAddress("0xbeef")),
			Value:     big.NewInt(11),
			Gas:       25_000,
			GasFeeCap: big.NewInt(30),
			GasTipCap: big.NewInt(5),
			Data:      []byte{0x02, 0x03},
		}),
	}

	call := buildPreflightCallMsg(attempt)

	assert.Nil(t, call.GasPrice)
	require.NotNil(t, call.GasFeeCap)
	require.NotNil(t, call.GasTipCap)
	assert.Equal(t, big.NewInt(30), call.GasFeeCap)
	assert.Equal(t, big.NewInt(5), call.GasTipCap)
}

func TestBuildPreflightCallMsgUsesAccessListLegacyFeeOnly(t *testing.T) {
	accessList := types.AccessList{{Address: common.HexToAddress("0xbeef")}}
	attempt := &txAttemptContext{
		Account: common.HexToAddress("0xabc"),
		Tx: types.NewTx(&types.AccessListTx{
			ChainID:    big.NewInt(3151908),
			Nonce:      3,
			To:         ptrAddress(common.HexToAddress("0xcafe")),
			Value:      big.NewInt(13),
			Gas:        31_000,
			GasPrice:   big.NewInt(17),
			Data:       []byte{0x04},
			AccessList: accessList,
		}),
	}

	call := buildPreflightCallMsg(attempt)

	require.NotNil(t, call.GasPrice)
	assert.Equal(t, big.NewInt(17), call.GasPrice)
	assert.Nil(t, call.GasFeeCap)
	assert.Nil(t, call.GasTipCap)
	assert.Equal(t, accessList, call.AccessList)
}

func TestTxExpectationRecorderAppendsEventsAndRejectsPostCloseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expectations.jsonl")
	recorder, err := newTxExpectationRecorder(path)
	require.NoError(t, err)

	event := txExpectationEvent{
		SchemaVersion:    txExpectationSchemaVersion,
		Event:            txExpectationEvidenceRecorded,
		RunID:            "run-1",
		AttemptID:        "attempt-1",
		Timestamp:        time.Now().UTC(),
		Endpoint:         "http://node-a",
		StaticVerdict:    txExpectationSuccess,
		StaticReason:     "basic_envelope_valid",
		PreflightVerdict: txExpectationUnknown,
		PreflightReason:  "client_unavailable",
		PayloadHash:      "payload-hash",
	}
	require.NoError(t, recorder.Append(event))
	require.NoError(t, recorder.Close())

	var got []txExpectationEvent
	readJSONLinesInto(t, path, &got)
	require.Len(t, got, 1)
	assert.Equal(t, txExpectationEvidenceRecorded, got[0].Event)
	assert.Equal(t, txExpectationUnknown, got[0].PreflightVerdict)

	err = recorder.Append(event)
	require.Error(t, err)
	assert.ErrorIs(t, err, errTxRecorderClosed)
}

func TestTxFuzzerCaptureExpectationSkipsAttemptsWithoutTransaction(t *testing.T) {
	tf := newTestTxFuzzerWithExpectationRecorder(t, filepath.Join(t.TempDir(), "expectations.jsonl"))
	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")

	stored := tf.captureExpectationEvidence(attempt)

	assert.False(t, stored)
	assert.Equal(t, int64(0), tf.txAnomalyProjection.Summary().ExpectationCount)
	assert.Empty(t, readRawLinesIfExists(t, tf.txExpectationLogPath))
}

func TestTxFuzzerCaptureExpectationRecordsUnknownPreflightWhenUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expectations.jsonl")
	tf := newTestTxFuzzerWithExpectationRecorder(t, path)
	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")
	tx := types.NewTransaction(7, common.HexToAddress("0xfeed"), big.NewInt(1), 21_000, big.NewInt(2), []byte{0xaa, 0xbb})
	attempt.AttachTransaction(tx, false, "")

	stored := tf.captureExpectationEvidence(attempt)

	require.True(t, stored)
	var got []txExpectationEvent
	readJSONLinesInto(t, path, &got)
	require.Len(t, got, 1)
	assert.Equal(t, txExpectationSuccess, got[0].StaticVerdict)
	assert.Equal(t, "basic_envelope_valid", got[0].StaticReason)
	assert.Equal(t, txExpectationUnknown, got[0].PreflightVerdict)
	assert.Equal(t, txPreflightReasonClientUnavailable, got[0].PreflightReason)
	assert.Equal(t, payloadHash(tx.Data()), got[0].PayloadHash)
	assert.Equal(t, int64(1), tf.txAnomalyProjection.Summary().ExpectationCount)
}

func TestTxFuzzerCaptureExpectationRecordsPreflightFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expectations.jsonl")
	tf := newTestTxFuzzerWithExpectationRecorder(t, path)
	preflight := &fakePreflightClient{estimateGasErr: errors.New("intrinsic gas too low")}
	tf.preflightClients = map[string]txPreflightClient{"http://node-a": preflight}

	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")
	tx := types.NewTransaction(9, common.HexToAddress("0xbeef"), big.NewInt(5), 21_000, big.NewInt(3), []byte{0x01})
	attempt.AttachTransaction(tx, true, "bitflip")

	stored := tf.captureExpectationEvidence(attempt)

	require.True(t, stored)
	var got []txExpectationEvent
	readJSONLinesInto(t, path, &got)
	require.Len(t, got, 1)
	assert.Equal(t, txExpectationFailure, got[0].PreflightVerdict)
	assert.Equal(t, txPreflightReasonSimulationFailed, got[0].PreflightReason)
	assert.Equal(t, 1, preflight.estimateGasCalls)
}

func newTestTxFuzzerWithExpectationRecorder(t *testing.T, expectationPath string) *TxFuzzer {
	t.Helper()
	tf := newTestTxFuzzerWithRecorder(t, filepath.Join(t.TempDir(), "attempts.jsonl"), 0)
	recorder, err := newTxExpectationRecorder(expectationPath)
	require.NoError(t, err)
	tf.txExpectationRecorder = recorder
	tf.txExpectationLogPath = expectationPath
	tf.txAnomalyProjection = newTxAnomalyProjection()
	return tf
}

type fakePreflightClient struct {
	estimateGasCalls int
	callCalls        int
	estimateGas      uint64
	estimateGasErr   error
	callResult       []byte
	callErr          error
}

func (f *fakePreflightClient) EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error) {
	f.estimateGasCalls++
	if f.estimateGasErr != nil {
		return 0, f.estimateGasErr
	}
	if f.estimateGas == 0 {
		return call.Gas, nil
	}
	return f.estimateGas, nil
}

func (f *fakePreflightClient) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	f.callCalls++
	if f.callErr != nil {
		return nil, f.callErr
	}
	return append([]byte(nil), f.callResult...), nil
}

func readJSONLinesInto[T any](t *testing.T, path string, out *[]T) {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	var values []T
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var v T
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &v))
		values = append(values, v)
	}
	require.NoError(t, scanner.Err())
	*out = values
}

func readRawLinesIfExists(t *testing.T, path string) [][]byte {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return readRawJSONLines(t, path)
}

func TestTxFuzzerFinalizeWritesAnomalyArtifactsAndRunSummaryFields(t *testing.T) {
	tempDir := t.TempDir()
	attemptPath := filepath.Join(tempDir, "tx_attempts_run.jsonl")
	expectationPath := filepath.Join(tempDir, "tx_expectations_run.jsonl")
	anomalyPath := filepath.Join(tempDir, "tx_anomalies_run.jsonl")
	anomalySummaryPath := filepath.Join(tempDir, "tx_anomaly_summary_run.json")

	tf := newTestTxFuzzerWithRecorder(t, attemptPath, 0)
	expectationRecorder, err := newTxExpectationRecorder(expectationPath)
	require.NoError(t, err)
	anomalyRecorder, err := newTxAnomalyRecorder(anomalyPath)
	require.NoError(t, err)
	tf.txExpectationRecorder = expectationRecorder
	tf.txExpectationLogPath = expectationPath
	tf.txAnomalyRecorder = anomalyRecorder
	tf.txAnomalyLogPath = anomalyPath
	tf.txAnomalySummaryPath = anomalySummaryPath
	tf.txAnomalyProjection = newTxAnomalyProjection()

	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")
	tx := types.NewTransaction(11, common.HexToAddress("0xbeef"), big.NewInt(5), 21_000, big.NewInt(3), []byte{0x01, 0x02})
	attempt.AttachTransaction(tx, false, "")
	require.True(t, tf.captureExpectationEvidence(attempt))
	tf.finishTxAttemptAccepted(attempt, 5*time.Millisecond, 0)
	require.True(t, tf.recordReceiptObservation(attempt.AttemptID, "http://node-a", &types.Receipt{Status: types.ReceiptStatusFailed, BlockNumber: big.NewInt(5), TxHash: tx.Hash(), GasUsed: 21000}, txReceiptReverted, true))

	summary := tf.Finalize(time.Now())

	assert.Equal(t, expectationPath, summary.ExpectationLogPath)
	assert.Equal(t, anomalyPath, summary.AnomalyLogPath)
	assert.Equal(t, anomalySummaryPath, summary.AnomalySummaryPath)
	assert.Equal(t, int64(1), summary.ExpectationCount)
	assert.Equal(t, int64(1), summary.AnomalyCount)
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyPredictionActualMismatch)])

	var anomalies []txAnomalyEvent
	readJSONLinesInto(t, anomalyPath, &anomalies)
	require.Len(t, anomalies, 1)
	assert.Equal(t, txAnomalyPredictionActualMismatch, anomalies[0].Type)

	data, err := os.ReadFile(anomalySummaryPath)
	require.NoError(t, err)
	var anomalySummary TxAnomalySummary
	require.NoError(t, json.Unmarshal(data, &anomalySummary))
	assert.Equal(t, int64(1), anomalySummary.AnomalyCount)
	assert.Equal(t, int64(1), anomalySummary.ExpectationCount)
}

func TestTxFuzzerFinalizeWritesReplayGroupCompletenessToExpectationArtifacts(t *testing.T) {
	tempDir := t.TempDir()
	attemptPath := filepath.Join(tempDir, "tx_attempts_run.jsonl")
	expectationPath := filepath.Join(tempDir, "tx_expectations_run.jsonl")

	tf := newTestTxFuzzerWithRecorder(t, attemptPath, 0)
	expectationRecorder, err := newTxExpectationRecorder(expectationPath)
	require.NoError(t, err)
	tf.txExpectationRecorder = expectationRecorder
	tf.txExpectationLogPath = expectationPath
	tf.txAnomalyProjection = newTxAnomalyProjection()

	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")
	attempt.Replay = &txReplayAttemptMetadata{
		GroupID:        "replay-group-9",
		EndpointIndex:  0,
		ScheduledCount: 2,
		Client:         "geth",
	}
	tx := types.NewTransaction(21, common.HexToAddress("0xbeef"), big.NewInt(5), 21_000, big.NewInt(3), []byte{0x01, 0x02})
	attempt.AttachTransaction(tx, false, "")
	require.True(t, tf.captureExpectationEvidence(attempt))
	tf.finishTxAttemptAccepted(attempt, 5*time.Millisecond, 0)

	tf.Finalize(time.Now())

	var events []txExpectationEvent
	readJSONLinesInto(t, expectationPath, &events)
	require.Len(t, events, 2)
	assert.Equal(t, txExpectationReplayGroupStatusRecorded, events[1].Event)
	require.NotNil(t, events[1].ReplayGroupComplete)
	assert.False(t, *events[1].ReplayGroupComplete)
	assert.Equal(t, "replay-group-9", events[1].ReplayGroupID)
}

func TestTxFuzzerCaptureExpectationBoundsPreflightWithTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expectations.jsonl")
	tf := newTestTxFuzzerWithExpectationRecorder(t, path)
	tf.preflightTimeout = 5 * time.Millisecond
	blocking := &blockingPreflightClient{}
	tf.preflightClients = map[string]txPreflightClient{"http://node-a": blocking}

	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")
	tx := types.NewTransaction(13, common.HexToAddress("0xfeed"), big.NewInt(1), 21_000, big.NewInt(2), []byte{0xaa})
	attempt.AttachTransaction(tx, false, "")

	stored := tf.captureExpectationEvidence(attempt)

	require.True(t, stored)
	var got []txExpectationEvent
	readJSONLinesInto(t, path, &got)
	require.Len(t, got, 1)
	assert.Equal(t, txExpectationUnknown, got[0].PreflightVerdict)
	assert.Equal(t, txPreflightReasonTimedOut, got[0].PreflightReason)
	assert.Equal(t, 1, blocking.estimateGasCalls)
}

func TestTxFuzzerSetExecutionContextRebindsActiveSendContext(t *testing.T) {
	tf := &TxFuzzer{}
	oldCtx, oldCancel := context.WithCancel(context.Background())
	tf.sendCtx = oldCtx
	tf.sendCancel = oldCancel

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	tf.setExecutionContext(parent)
	cancelParent()

	select {
	case <-tf.activeSendContext().Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("active send context should follow caller cancellation")
	}
}

type blockingPreflightClient struct {
	estimateGasCalls int
}

func (b *blockingPreflightClient) EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error) {
	b.estimateGasCalls++
	<-ctx.Done()
	return 0, ctx.Err()
}

func (b *blockingPreflightClient) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func ptrAddress(v common.Address) *common.Address {
	return &v
}
