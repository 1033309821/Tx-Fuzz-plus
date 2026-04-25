package fuzzer

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

const txExpectationSchemaVersion = 1

type txExpectationEventType string

const txExpectationEvidenceRecorded txExpectationEventType = "tx_expectation_recorded"

type txExpectationVerdict string

const (
	txExpectationSuccess txExpectationVerdict = "expect_success"
	txExpectationFailure txExpectationVerdict = "expect_failure"
	txExpectationUnknown txExpectationVerdict = "unknown"
)

const (
	txStaticReasonBasicEnvelopeValid    = "basic_envelope_valid"
	txStaticReasonIntrinsicGasTooLow    = "intrinsic_gas_too_low"
	txStaticReasonMissingAttemptContext = "missing_attempt_context"

	txPreflightReasonClientUnavailable = "client_unavailable"
	txPreflightReasonSimulationFailed  = "simulation_error"
	txPreflightReasonSimulationPassed  = "simulation_succeeded"
	txPreflightReasonTimedOut          = "simulation_timeout"
	txPreflightReasonContextCancelled  = "context_cancelled"
)

type txExpectationEvent struct {
	SchemaVersion    int                    `json:"schema_version"`
	Event            txExpectationEventType `json:"event"`
	RunID            string                 `json:"run_id"`
	AttemptID        string                 `json:"attempt_id"`
	Timestamp        time.Time              `json:"timestamp"`
	Endpoint         string                 `json:"endpoint,omitempty"`
	Account          string                 `json:"account,omitempty"`
	Nonce            *uint64                `json:"nonce,omitempty"`
	TxHash           string                 `json:"tx_hash,omitempty"`
	To               string                 `json:"to,omitempty"`
	PayloadHash      string                 `json:"payload_hash,omitempty"`
	StaticVerdict    txExpectationVerdict   `json:"static_verdict"`
	StaticReason     string                 `json:"static_reason,omitempty"`
	PreflightVerdict txExpectationVerdict   `json:"preflight_verdict"`
	PreflightReason  string                 `json:"preflight_reason,omitempty"`
}

func newTxExpectationRecorder(path string) (*txAttemptRecorder, error) {
	return newTxAttemptRecorder(path)
}

func (tf *TxFuzzer) captureExpectationEvidence(attempt *txAttemptContext) bool {
	if tf == nil || attempt == nil || !attemptExpectationEligible(attempt) {
		return false
	}

	event := txExpectationEvent{
		SchemaVersion: txExpectationSchemaVersion,
		Event:         txExpectationEvidenceRecorded,
		RunID:         attempt.RunID,
		AttemptID:     attempt.AttemptID,
		Timestamp:     time.Now(),
		Endpoint:      attempt.Endpoint,
		PayloadHash:   payloadHash(attempt.Tx.Data()),
	}
	if attempt.Account != (common.Address{}) {
		event.Account = attempt.Account.Hex()
	}
	if attempt.Nonce != nil {
		nonce := *attempt.Nonce
		event.Nonce = &nonce
	}
	if attempt.TxHashSet {
		event.TxHash = attempt.TxHash.Hex()
	}
	if attempt.Tx.To() != nil {
		event.To = attempt.Tx.To().Hex()
	}

	event.StaticVerdict, event.StaticReason = staticExpectationVerdict(attempt)
	event.PreflightVerdict, event.PreflightReason = tf.preflightExpectationVerdict(attempt)

	return tf.recordExpectationEvent(event)
}

func attemptExpectationEligible(attempt *txAttemptContext) bool {
	if attempt == nil || attempt.Tx == nil {
		return false
	}
	if attempt.Endpoint == "" || attempt.Account == (common.Address{}) || attempt.Nonce == nil {
		return false
	}
	return true
}

func staticExpectationVerdict(attempt *txAttemptContext) (txExpectationVerdict, string) {
	if !attemptExpectationEligible(attempt) {
		return txExpectationUnknown, txStaticReasonMissingAttemptContext
	}
	if attempt.Tx.Gas() < 21000 {
		return txExpectationFailure, txStaticReasonIntrinsicGasTooLow
	}
	return txExpectationSuccess, txStaticReasonBasicEnvelopeValid
}

func (tf *TxFuzzer) preflightExpectationVerdict(attempt *txAttemptContext) (txExpectationVerdict, string) {
	client := tf.getPreflightClient(attempt.Endpoint)
	if client == nil {
		return txExpectationUnknown, txPreflightReasonClientUnavailable
	}

	call := ethereum.CallMsg{
		From:      attempt.Account,
		To:        attempt.Tx.To(),
		Gas:       attempt.Tx.Gas(),
		GasPrice:  attempt.Tx.GasPrice(),
		GasFeeCap: attempt.Tx.GasFeeCap(),
		GasTipCap: attempt.Tx.GasTipCap(),
		Value:     attempt.Tx.Value(),
		Data:      attempt.Tx.Data(),
	}

	ctx := tf.activeSendContext()
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := tf.preflightTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := client.EstimateGas(ctx, call); err != nil {
		if ctx.Err() != nil {
			return txExpectationUnknown, txPreflightReasonForContextErr(ctx.Err())
		}
		return txExpectationFailure, txPreflightReasonSimulationFailed
	}
	if _, err := client.CallContract(ctx, call, nil); err != nil {
		if ctx.Err() != nil {
			return txExpectationUnknown, txPreflightReasonForContextErr(ctx.Err())
		}
		return txExpectationFailure, txPreflightReasonSimulationFailed
	}
	return txExpectationSuccess, txPreflightReasonSimulationPassed
}

func (tf *TxFuzzer) getPreflightClient(endpoint string) txPreflightClient {
	if tf == nil {
		return nil
	}
	if endpoint != "" {
		tf.clientsMutex.RLock()
		client := tf.preflightClients[endpoint]
		tf.clientsMutex.RUnlock()
		if client != nil {
			return client
		}
	}
	return tf.preflightClient
}

func txPreflightReasonForContextErr(err error) string {
	switch err {
	case context.DeadlineExceeded:
		return txPreflightReasonTimedOut
	case context.Canceled:
		return txPreflightReasonContextCancelled
	default:
		return txPreflightReasonSimulationFailed
	}
}

func (tf *TxFuzzer) recordExpectationEvent(event txExpectationEvent) bool {
	if tf == nil || tf.txAnomalyProjection == nil {
		return false
	}
	stored := tf.txAnomalyProjection.RecordExpectationWithAppend(event, func() error {
		if tf.txExpectationRecorder == nil {
			return nil
		}
		return tf.txExpectationRecorder.Append(event)
	})
	if !stored && tf.logger.Logger != nil {
		tf.logger.Warn("failed to append tx expectation event")
	}
	return stored
}
