package fuzzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const txAttemptSchemaVersion = 1

type txEventType string

const (
	txEventSendAttempt        txEventType = "tx_send_attempt"
	txEventReceiptObservation txEventType = "tx_receipt_observation"
)

type txStage string

const (
	txStageEndpointSelection txStage = "endpoint_selection"
	txStageAccountDecode     txStage = "account_decode"
	txStageNonceFetch        txStage = "nonce_fetch"
	txStageTxGeneration      txStage = "tx_generation"
	txStageSend              txStage = "send"
)

type txSendStatus string

const (
	txSendAccepted     txSendStatus = "accepted"
	txSendRejected     txSendStatus = "rejected"
	txSendPreSendError txSendStatus = "pre_send_error"
)

type txReceiptStatus string

const (
	txReceiptAwaitingReceipt   txReceiptStatus = "awaiting_receipt"
	txReceiptMined             txReceiptStatus = "mined"
	txReceiptReverted          txReceiptStatus = "reverted"
	txReceiptConfirmed         txReceiptStatus = "confirmed"
	txReceiptTimeout           txReceiptStatus = "timeout"
	txReceiptPendingAtShutdown txReceiptStatus = "pending_at_shutdown"
)

var errTxRecorderClosed = errors.New("tx attempt recorder is closed")

type txAttemptEvent struct {
	SchemaVersion int          `json:"schema_version"`
	Event         txEventType  `json:"event"`
	RunID         string       `json:"run_id"`
	AttemptID     string       `json:"attempt_id"`
	Timestamp     time.Time    `json:"timestamp"`
	Stage         txStage      `json:"stage"`
	SendStatus    txSendStatus `json:"send_status"`
	Endpoint      string       `json:"endpoint,omitempty"`
	Account       string       `json:"account,omitempty"`
	Nonce         *uint64      `json:"nonce,omitempty"`
	ChainID       string       `json:"chain_id,omitempty"`
	TxHash        string       `json:"tx_hash,omitempty"`
	ReturnedHash  string       `json:"returned_hash,omitempty"`
	TxType        *uint8       `json:"tx_type,omitempty"`
	To            string       `json:"to,omitempty"`
	Value         string       `json:"value,omitempty"`
	Gas           *uint64      `json:"gas,omitempty"`
	GasPrice      string       `json:"gas_price,omitempty"`
	GasFeeCap     string       `json:"gas_fee_cap,omitempty"`
	GasTipCap     string       `json:"gas_tip_cap,omitempty"`
	PayloadLength *int         `json:"payload_length,omitempty"`
	PayloadHash   string       `json:"payload_hash,omitempty"`
	MutationUsed  *bool        `json:"mutation_used,omitempty"`
	MutationType  string       `json:"mutation_type,omitempty"`
	LatencyMS     *int64       `json:"latency_ms,omitempty"`
	RetryCount    int          `json:"retry_count"`
	ErrorClass    string       `json:"error_class,omitempty"`
	ErrorAction   string       `json:"error_action,omitempty"`
	ErrorMessage  string       `json:"error_message,omitempty"`
}

type txReceiptObservationEvent struct {
	SchemaVersion     int             `json:"schema_version"`
	Event             txEventType     `json:"event"`
	RunID             string          `json:"run_id"`
	AttemptID         string          `json:"attempt_id"`
	Timestamp         time.Time       `json:"timestamp"`
	TxHash            string          `json:"tx_hash,omitempty"`
	SendEndpoint      string          `json:"send_endpoint,omitempty"`
	LookupEndpoint    string          `json:"lookup_endpoint,omitempty"`
	ReceiptStatus     txReceiptStatus `json:"receipt_status"`
	BlockNumber       *uint64         `json:"block_number,omitempty"`
	BlockHash         string          `json:"block_hash,omitempty"`
	TransactionIndex  *uint           `json:"transaction_index,omitempty"`
	GasUsed           *uint64         `json:"gas_used,omitempty"`
	EffectiveGasPrice string          `json:"effective_gas_price,omitempty"`
	ContractAddress   string          `json:"contract_address,omitempty"`
	LogsCount         *int            `json:"logs_count,omitempty"`
	Terminal          bool            `json:"terminal"`
}

type txAttemptRecorder struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func newTxAttemptRecorder(path string) (*txAttemptRecorder, error) {
	if path == "" {
		return nil, fmt.Errorf("tx attempt log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create tx attempt log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open tx attempt log: %w", err)
	}
	return &txAttemptRecorder{file: file}, nil
}

func (r *txAttemptRecorder) Append(event any) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errTxRecorderClosed
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal tx attempt event: %w", err)
	}
	data = append(data, '\n')
	if _, err := r.file.Write(data); err != nil {
		return fmt.Errorf("append tx attempt event: %w", err)
	}
	return nil
}

func (r *txAttemptRecorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.file.Close()
}

type TxResultSummary struct {
	AttemptCount        int64            `json:"attempt_count"`
	AttemptLogPath      string           `json:"attempt_log_path,omitempty"`
	SendStatusCounts    map[string]int64 `json:"send_status_counts,omitempty"`
	ReceiptStatusCounts map[string]int64 `json:"receipt_status_counts,omitempty"`
	ErrorClassCounts    map[string]int64 `json:"error_class_counts,omitempty"`
}

type txAttemptProjection struct {
	mu       sync.Mutex
	attempts map[string]*txAttemptState
}

type txAttemptState struct {
	sendStatus    txSendStatus
	receiptStatus txReceiptStatus
	terminal      bool
	errorClass    string
}

func newTxAttemptProjection() *txAttemptProjection {
	return &txAttemptProjection{attempts: make(map[string]*txAttemptState)}
}

func (p *txAttemptProjection) RecordSendAttempt(event txAttemptEvent) {
	p.RecordSendAttemptWithAppend(event, nil)
}

func (p *txAttemptProjection) RecordSendAttemptWithAppend(event txAttemptEvent, appendEvent func() error) bool {
	if p == nil || event.AttemptID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if appendEvent != nil {
		if err := appendEvent(); err != nil {
			return false
		}
	}
	state := p.ensureLocked(event.AttemptID)
	state.sendStatus = event.SendStatus
	state.errorClass = event.ErrorClass
	if event.SendStatus == txSendAccepted && state.receiptStatus == "" {
		state.receiptStatus = txReceiptAwaitingReceipt
	}
	return true
}

func (p *txAttemptProjection) RecordReceiptObservation(event txReceiptObservationEvent, confirmBlocks uint64) bool {
	return p.RecordReceiptObservationWithAppend(event, confirmBlocks, nil)
}

func (p *txAttemptProjection) RecordReceiptObservationWithAppend(event txReceiptObservationEvent, confirmBlocks uint64, appendEvent func() error) bool {
	if p == nil || event.AttemptID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.ensureLocked(event.AttemptID)
	if state.terminal {
		return false
	}
	if appendEvent != nil {
		if err := appendEvent(); err != nil {
			return false
		}
	}
	terminal := event.Terminal || isTerminalReceiptStatus(event.ReceiptStatus, confirmBlocks)
	state.receiptStatus = event.ReceiptStatus
	state.terminal = terminal
	return true
}

func (p *txAttemptProjection) PendingAcceptedAttemptIDs() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make([]string, 0)
	for id, state := range p.attempts {
		if state.sendStatus == txSendAccepted && !state.terminal {
			ids = append(ids, id)
		}
	}
	return ids
}

func (p *txAttemptProjection) Summary() TxResultSummary {
	summary := TxResultSummary{
		SendStatusCounts:    make(map[string]int64),
		ReceiptStatusCounts: make(map[string]int64),
		ErrorClassCounts:    make(map[string]int64),
	}
	if p == nil {
		return summary
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, state := range p.attempts {
		summary.AttemptCount++
		if state.sendStatus != "" {
			summary.SendStatusCounts[string(state.sendStatus)]++
		}
		if state.receiptStatus != "" {
			summary.ReceiptStatusCounts[string(state.receiptStatus)]++
		}
		if state.errorClass != "" {
			summary.ErrorClassCounts[state.errorClass]++
		}
	}
	return summary
}

func (p *txAttemptProjection) ensureLocked(attemptID string) *txAttemptState {
	state := p.attempts[attemptID]
	if state == nil {
		state = &txAttemptState{}
		p.attempts[attemptID] = state
	}
	return state
}

func isTerminalReceiptStatus(status txReceiptStatus, confirmBlocks uint64) bool {
	switch status {
	case txReceiptConfirmed, txReceiptTimeout, txReceiptPendingAtShutdown, txReceiptReverted:
		return true
	case txReceiptMined:
		return confirmBlocks == 0
	default:
		return false
	}
}

type txAttemptContext struct {
	RunID        string
	AttemptID    string
	Endpoint     string
	StartedAt    time.Time
	Account      common.Address
	Nonce        *uint64
	TxHash       common.Hash
	TxHashSet    bool
	Tx           *types.Transaction
	MutationUsed bool
	MutationType string
}

func (a *txAttemptContext) AttachTransaction(tx *types.Transaction, mutationUsed bool, mutationType string) {
	if a == nil || tx == nil {
		return
	}
	a.Tx = tx
	a.MutationUsed = mutationUsed
	a.MutationType = mutationType
	nonce := tx.Nonce()
	a.Nonce = &nonce
	a.TxHash = tx.Hash()
	a.TxHashSet = true
}

func payloadHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stringBig(v *big.Int) string {
	if v == nil {
		return ""
	}
	return v.String()
}

func DefaultTxResultLogPath(outputDir string, enabled bool) string {
	return defaultTxResultLogPath(outputDir, enabled)
}

func siblingTxArtifactPath(basePath string, prefix string, ext string) string {
	if basePath == "" {
		return ""
	}
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	stem = strings.TrimPrefix(stem, "tx_attempts_")
	return filepath.Join(dir, prefix+stem+ext)
}
