package fuzzer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTxAttemptRecorderAppendsEventsAndRejectsPostCloseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	recorder, err := newTxAttemptRecorder(path)
	require.NoError(t, err)

	event := txAttemptEvent{
		SchemaVersion: 1,
		Event:         txEventSendAttempt,
		RunID:         "run-1",
		AttemptID:     "attempt-1",
		Stage:         txStageSend,
		SendStatus:    txSendAccepted,
		Endpoint:      "http://node-a",
		Account:       common.HexToAddress("0xabc").Hex(),
		Nonce:         uint64Ptr(12),
		TxHash:        common.HexToHash("0x123").Hex(),
		ReturnedHash:  common.HexToHash("0x123").Hex(),
		LatencyMS:     int64Ptr(42),
		PayloadLength: intPtr(128),
		PayloadHash:   "payload-hash",
	}
	require.NoError(t, recorder.Append(event))
	require.NoError(t, recorder.Close())

	lines := readJSONLines[txAttemptEvent](t, path)
	require.Len(t, lines, 1)
	assert.Equal(t, txEventSendAttempt, lines[0].Event)
	assert.Equal(t, txSendAccepted, lines[0].SendStatus)
	assert.Equal(t, lines[0].TxHash, lines[0].ReturnedHash)
	assert.NotContains(t, string(mustReadFile(t, path)), "private_key")

	err = recorder.Append(event)
	require.Error(t, err)
	assert.ErrorIs(t, err, errTxRecorderClosed)
}

func TestTxProjectionDerivesLayeredSummaryAndSealsTerminalReceiptState(t *testing.T) {
	projection := newTxAttemptProjection()
	accepted := txAttemptEvent{RunID: "run-1", AttemptID: "attempt-accepted", Event: txEventSendAttempt, SendStatus: txSendAccepted}
	rejected := txAttemptEvent{RunID: "run-1", AttemptID: "attempt-rejected", Event: txEventSendAttempt, SendStatus: txSendRejected, ErrorClass: string(SendErrorNonce)}
	projection.RecordSendAttempt(accepted)
	projection.RecordSendAttempt(rejected)

	mined := txReceiptObservationEvent{RunID: "run-1", AttemptID: accepted.AttemptID, Event: txEventReceiptObservation, ReceiptStatus: txReceiptMined, Terminal: false}
	confirmed := mined
	confirmed.ReceiptStatus = txReceiptConfirmed
	confirmed.Terminal = true
	lateTimeout := mined
	lateTimeout.ReceiptStatus = txReceiptTimeout
	lateTimeout.Terminal = true

	assert.True(t, projection.RecordReceiptObservation(mined, 2), "mined should be recorded while awaiting confirmations")
	assert.True(t, projection.RecordReceiptObservation(confirmed, 2), "confirmed should terminally seal the attempt")
	assert.False(t, projection.RecordReceiptObservation(lateTimeout, 2), "late terminal observations must not mutate sealed attempts")

	summary := projection.Summary()
	assert.Equal(t, int64(2), summary.AttemptCount)
	assert.Equal(t, int64(1), summary.SendStatusCounts[string(txSendAccepted)])
	assert.Equal(t, int64(1), summary.SendStatusCounts[string(txSendRejected)])
	assert.Equal(t, int64(1), summary.ReceiptStatusCounts[string(txReceiptConfirmed)])
	assert.Zero(t, summary.ReceiptStatusCounts[string(txReceiptTimeout)])
	assert.Equal(t, int64(1), summary.ErrorClassCounts[string(SendErrorNonce)])
}

func TestTxProjectionDoesNotMutateWhenAppendFails(t *testing.T) {
	projection := newTxAttemptProjection()
	event := txAttemptEvent{RunID: "run-1", AttemptID: "attempt-1", Event: txEventSendAttempt, SendStatus: txSendAccepted}

	stored := projection.RecordSendAttemptWithAppend(event, func() error { return errors.New("disk full") })

	assert.False(t, stored)
	assert.Zero(t, projection.Summary().AttemptCount)
}

func TestTxFuzzerRecordsPreSendErrorBeforeTransactionHashExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	attempt := tf.beginTxAttempt("http://node-a")
	attempt.Account = common.HexToAddress("0xabc")

	tf.finishTxAttemptRejected(attempt, txStageNonceFetch, errors.New("i/o timeout fetching nonce"), 3*time.Millisecond, 0)
	require.NoError(t, tf.txAttemptRecorder.Close())

	lines := readJSONLines[txAttemptEvent](t, path)
	require.Len(t, lines, 1)
	got := lines[0]
	assert.Equal(t, txSendPreSendError, got.SendStatus)
	assert.Equal(t, txStageNonceFetch, got.Stage)
	assert.Equal(t, "http://node-a", got.Endpoint)
	assert.Equal(t, common.HexToAddress("0xabc").Hex(), got.Account)
	assert.Nil(t, got.Nonce)
	assert.Empty(t, got.TxHash)
	assert.Equal(t, string(SendErrorNetwork), got.ErrorClass)
}

func TestTxFuzzerRecordsRejectedSendAttemptToJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	attempt := tf.beginTxAttempt("http://node-a")
	tx := types.NewTransaction(7, common.HexToAddress("0xdead"), big.NewInt(1), 21000, big.NewInt(2), []byte{0xaa, 0xbb})
	attempt.AttachTransaction(tx, false, "")

	tf.finishTxAttemptRejected(attempt, txStageSend, errors.New("nonce too low"), 17*time.Millisecond, 2)
	require.NoError(t, tf.txAttemptRecorder.Close())

	lines := readJSONLines[txAttemptEvent](t, path)
	require.Len(t, lines, 1)
	got := lines[0]
	assert.Equal(t, txSendRejected, got.SendStatus)
	assert.Equal(t, txStageSend, got.Stage)
	assert.Equal(t, "http://node-a", got.Endpoint)
	assert.Equal(t, uint64(7), *got.Nonce)
	assert.Equal(t, tx.Hash().Hex(), got.TxHash)
	assert.Equal(t, string(SendErrorNonce), got.ErrorClass)
	assert.Equal(t, SendErrorNonce.Action(), got.ErrorAction)
	assert.Contains(t, got.ErrorMessage, "nonce too low")
	assert.Equal(t, int64(17), *got.LatencyMS)
	assert.Equal(t, 2, got.RetryCount)
}

func TestTxFuzzerRecordsAcceptedSendAndReceiptObservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 2)
	attempt := tf.beginTxAttempt("http://node-a")
	tx := types.NewTransaction(9, common.HexToAddress("0xbeef"), big.NewInt(5), 22000, big.NewInt(3), []byte{0x01})
	attempt.AttachTransaction(tx, true, "bitflip")
	tf.finishTxAttemptAccepted(attempt, 11*time.Millisecond, 1)

	receipt := &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(10), TxHash: tx.Hash(), GasUsed: 21000, TransactionIndex: 3}
	assert.True(t, tf.recordReceiptObservation(attempt.AttemptID, "http://node-b", receipt, txReceiptMined, false))
	assert.True(t, tf.recordConfirmationObservation(attempt.AttemptID, "http://node-b", 12, true))
	require.NoError(t, tf.txAttemptRecorder.Close())

	sends := readJSONLines[txAttemptEvent](t, path)
	require.Len(t, sends, 3)
	assert.Equal(t, txEventSendAttempt, sends[0].Event)
	assert.Equal(t, txSendAccepted, sends[0].SendStatus)
	assert.Equal(t, tx.Hash().Hex(), sends[0].TxHash)
	assert.Equal(t, tx.Hash().Hex(), sends[0].ReturnedHash)

	var mined, confirmed map[string]any
	for _, raw := range readRawJSONLines(t, path)[1:] {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		switch m["receipt_status"] {
		case string(txReceiptMined):
			mined = m
		case string(txReceiptConfirmed):
			confirmed = m
		}
	}
	require.NotNil(t, mined)
	require.NotNil(t, confirmed)
	assert.Equal(t, "http://node-a", mined["send_endpoint"])
	assert.Equal(t, "http://node-b", mined["lookup_endpoint"])
	assert.Equal(t, false, mined["terminal"])
	assert.Equal(t, true, confirmed["terminal"])

	summary := tf.BuildRunSummary(time.Now())
	assert.Equal(t, path, summary.AttemptLogPath)
	assert.Equal(t, int64(1), summary.AttemptCount)
	assert.Equal(t, int64(1), summary.SendStatusCounts[string(txSendAccepted)])
	assert.Equal(t, int64(1), summary.ReceiptStatusCounts[string(txReceiptConfirmed)])
}

func TestTxFuzzerSendTransactionWithRetryReportsActualRetryCount(t *testing.T) {
	tf := newTestTxFuzzerWithRecorder(t, filepath.Join(t.TempDir(), "attempts.jsonl"), 0)
	client := &fakeTxRPCClient{sendErrors: []error{errors.New("i/o timeout"), nil}}
	tf.clients = map[string]txRPCClient{"http://node-a": client}
	tf.nodeHealth = map[string]bool{"http://node-a": true}
	tf.circuitBreakers = map[string]*CircuitBreaker{"http://node-a": NewCircuitBreaker(3, time.Second)}

	retries, err := tf.sendTransactionWithRetry("http://node-a", types.NewTransaction(1, common.Address{}, big.NewInt(1), 21000, big.NewInt(1), nil), &TxFuzzConfig{MultiNode: &MultiNodeConfig{MaxRetries: 3, RetryDelay: time.Nanosecond}})

	require.NoError(t, err)
	assert.Equal(t, 1, retries)
	assert.Equal(t, 2, client.sendCalls)
}

func TestTxFuzzerMonitorUsesLookupEndpointClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	attempt := tf.beginTxAttempt("http://node-a")
	tx := types.NewTransaction(1, common.HexToAddress("0xfeed"), big.NewInt(1), 21000, big.NewInt(1), nil)
	attempt.AttachTransaction(tx, false, "")
	tf.finishTxAttemptAccepted(attempt, time.Millisecond, 0)
	lookup := &fakeTxRPCClient{receipt: &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(5), TxHash: tx.Hash(), GasUsed: 21000}}
	tf.clients = map[string]txRPCClient{"http://node-a": lookup}
	tf.nodeHealth = map[string]bool{"http://node-a": true}
	tf.ctx = context.Background()
	tf.receiptPollInterval = time.Nanosecond

	tf.monitorTransactionForAttempt(attempt.AttemptID, tx.Hash(), "http://node-a", 0)

	assert.Equal(t, 1, lookup.receiptCalls)
	assert.Equal(t, int64(1), tf.BuildRunSummary(time.Now()).ReceiptStatusCounts[string(txReceiptMined)])
	var mined map[string]any
	for _, raw := range readRawJSONLines(t, path) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		if m["receipt_status"] == string(txReceiptMined) {
			mined = m
		}
	}
	require.NotNil(t, mined)
	assert.Equal(t, "http://node-a", mined["lookup_endpoint"])
}

func TestTxFuzzerFinalizeDrainsMonitorBeforePendingShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	tf.receiptDrainDuration = 100 * time.Millisecond
	attempt := tf.beginTxAttempt("http://node-a")
	tx := types.NewTransaction(1, common.HexToAddress("0xfeed"), big.NewInt(1), 21000, big.NewInt(1), nil)
	attempt.AttachTransaction(tx, false, "")
	tf.finishTxAttemptAccepted(attempt, time.Millisecond, 0)
	tf.monitorWG.Add(1)
	go func() {
		defer tf.monitorWG.Done()
		time.Sleep(10 * time.Millisecond)
		tf.recordReceiptObservation(attempt.AttemptID, "http://node-a", &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(5), TxHash: tx.Hash(), GasUsed: 21000}, txReceiptMined, true)
	}()

	summary := tf.Finalize(time.Now())

	assert.Equal(t, int64(1), summary.ReceiptStatusCounts[string(txReceiptMined)])
	assert.Zero(t, summary.ReceiptStatusCounts[string(txReceiptPendingAtShutdown)])
}

func TestTxFuzzerBeginSendRejectsNewWorkAfterFinalizing(t *testing.T) {
	tf := newTestTxFuzzerWithRecorder(t, filepath.Join(t.TempDir(), "attempts.jsonl"), 0)
	tf.sendMu.Lock()
	tf.finalizing.Store(true)
	tf.sendMu.Unlock()

	assert.False(t, tf.beginSend())
}

func TestTxFuzzerFinalizeCancelsInFlightSendBeforeClosingRecorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	tf.receiptDrainDuration = 200 * time.Millisecond
	sendCtx, sendCancel := context.WithCancel(context.Background())
	tf.sendCtx = sendCtx
	tf.sendCancel = sendCancel

	tf.sendWG.Add(1)
	released := make(chan struct{})
	go func() {
		defer tf.sendWG.Done()
		<-tf.sendCtx.Done()
		close(released)
	}()

	tf.Finalize(time.Now())

	select {
	case <-released:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Finalize must cancel and drain in-flight sends before closing the recorder")
	}
	assert.ErrorIs(t, tf.txAttemptRecorder.Append(txAttemptEvent{RunID: tf.runID, AttemptID: "late", Event: txEventSendAttempt}), errTxRecorderClosed)
}

func TestTxFuzzerFinalizeCancelsContextAfterDrainAndSealing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	ctx, cancel := context.WithCancel(context.Background())
	tf.ctx = ctx
	tf.cancel = cancel

	tf.Finalize(time.Now())

	select {
	case <-tf.ctx.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Finalize must cancel the tx fuzzer context after the receipt drain/seal phase")
	}
}

func TestTxFuzzerFinalizeSealsPendingAttemptsExactlyOnceAndClosesRecorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempts.jsonl")
	tf := newTestTxFuzzerWithRecorder(t, path, 0)
	attempt := tf.beginTxAttempt("http://node-a")
	tx := types.NewTransaction(1, common.HexToAddress("0xfeed"), big.NewInt(1), 21000, big.NewInt(1), nil)
	attempt.AttachTransaction(tx, false, "")
	tf.finishTxAttemptAccepted(attempt, time.Millisecond, 0)

	summary := tf.Finalize(time.Now())
	assert.Equal(t, int64(1), summary.ReceiptStatusCounts[string(txReceiptPendingAtShutdown)])
	assert.True(t, tf.finalizing.Load())

	assert.False(t, tf.recordReceiptObservation(attempt.AttemptID, "http://node-a", &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(2)}, txReceiptMined, true))
	err := tf.txAttemptRecorder.Append(txAttemptEvent{RunID: tf.runID, AttemptID: "late", Event: txEventSendAttempt})
	assert.ErrorIs(t, err, errTxRecorderClosed)

	var pendingCount int
	for _, raw := range readRawJSONLines(t, path) {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		if m["receipt_status"] == string(txReceiptPendingAtShutdown) {
			pendingCount++
		}
	}
	assert.Equal(t, 1, pendingCount)
}

func newTestTxFuzzerWithRecorder(t *testing.T, path string, confirmBlocks uint64) *TxFuzzer {
	t.Helper()
	recorder, err := newTxAttemptRecorder(path)
	require.NoError(t, err)
	started := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	return &TxFuzzer{
		runID:               "run-test",
		chainID:             big.NewInt(1),
		txAttemptRecorder:   recorder,
		txAttemptLogPath:    path,
		txAttemptProjection: newTxAttemptProjection(),
		confirmBlocks:       confirmBlocks,
		txRecords:           make(map[common.Hash]*TransactionRecord),
		stats:               &TxStats{StartTime: started, LastUpdateTime: started},
		errorClassCounts:    make(map[SendErrorClass]int64),
		nodeHealth:          map[string]bool{"http://node-a": true},
		clients:             make(map[string]txRPCClient),
	}
}

func readJSONLines[T any](t *testing.T, path string) []T {
	t.Helper()
	raw := readRawJSONLines(t, path)
	out := make([]T, 0, len(raw))
	for _, line := range raw {
		var v T
		require.NoError(t, json.Unmarshal(line, &v))
		out = append(out, v)
	}
	return out
}

func readRawJSONLines(t *testing.T, path string) [][]byte {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	var lines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		lines = append(lines, line)
	}
	require.NoError(t, scanner.Err())
	return lines
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func uint64Ptr(v uint64) *uint64 { return &v }
func int64Ptr(v int64) *int64    { return &v }
func intPtr(v int) *int          { return &v }

type fakeTxRPCClient struct {
	sendErrors   []error
	sendCalls    int
	receipt      *types.Receipt
	receiptErr   error
	receiptCalls int
	blockNumber  uint64
	balance      *big.Int
}

func (f *fakeTxRPCClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	if f.sendCalls < len(f.sendErrors) {
		err := f.sendErrors[f.sendCalls]
		f.sendCalls++
		return err
	}
	f.sendCalls++
	return nil
}

func (f *fakeTxRPCClient) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	f.receiptCalls++
	if f.receiptErr != nil {
		return nil, f.receiptErr
	}
	if f.receipt == nil {
		return nil, fmt.Errorf("not found")
	}
	return f.receipt, nil
}

func (f *fakeTxRPCClient) BlockNumber(ctx context.Context) (uint64, error) { return f.blockNumber, nil }
func (f *fakeTxRPCClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return 0, nil
}
func (f *fakeTxRPCClient) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	return 0, nil
}
func (f *fakeTxRPCClient) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	if f.balance == nil {
		return big.NewInt(1), nil
	}
	return new(big.Int).Set(f.balance), nil
}
func (f *fakeTxRPCClient) ChainID(ctx context.Context) (*big.Int, error) { return big.NewInt(1), nil }
func (f *fakeTxRPCClient) Close()                                        {}
