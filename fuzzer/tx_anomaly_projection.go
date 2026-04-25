package fuzzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const txAnomalySchemaVersion = 1

type txAnomalyEventType string

const txAnomalyEvidenceDetected txAnomalyEventType = "tx_anomaly_detected"

type txAnomalyType string

const (
	txAnomalyPredictionActualMismatch     txAnomalyType = "prediction_actual_mismatch"
	txAnomalyPredictionSourceDisagreement txAnomalyType = "prediction_source_disagreement"
	txAnomalyCrossNodeOutcomeDisagreement txAnomalyType = "cross_node_outcome_disagreement"
)

type txAnomalyEvent struct {
	SchemaVersion     int                  `json:"schema_version"`
	Event             txAnomalyEventType   `json:"event"`
	RunID             string               `json:"run_id"`
	AttemptID         string               `json:"attempt_id,omitempty"`
	Timestamp         time.Time            `json:"timestamp"`
	Type              txAnomalyType        `json:"type"`
	Endpoint          string               `json:"endpoint,omitempty"`
	PayloadHash       string               `json:"payload_hash,omitempty"`
	StaticVerdict     txExpectationVerdict `json:"static_verdict,omitempty"`
	PreflightVerdict  txExpectationVerdict `json:"preflight_verdict,omitempty"`
	ActualVerdict     txExpectationVerdict `json:"actual_verdict,omitempty"`
	RelatedAttemptIDs []string             `json:"related_attempt_ids,omitempty"`
	RelatedEndpoints  []string             `json:"related_endpoints,omitempty"`
}

type TxAnomalySummary struct {
	ExpectationCount           int64            `json:"expectation_count"`
	AnomalyCount               int64            `json:"anomaly_count"`
	TotalAttemptCount          int64            `json:"total_attempt_count"`
	ExpectationEligibleCount   int64            `json:"expectation_eligible_attempt_count"`
	AnomalyEligibleCount       int64            `json:"anomaly_eligible_attempt_count"`
	AnomalyTypeCounts          map[string]int64 `json:"anomaly_type_counts,omitempty"`
	ExcludedPreTxFailureCounts map[string]int64 `json:"excluded_pre_tx_failure_counts,omitempty"`
}

type txAnomalyProjection struct {
	mu       sync.Mutex
	attempts map[string]*txAnomalyAttemptState
}

type txAnomalyAttemptState struct {
	runID                string
	attemptID            string
	endpoint             string
	payloadHash          string
	staticVerdict        txExpectationVerdict
	preflightVerdict     txExpectationVerdict
	expectationRecorded  bool
	excludedPreTxFailure bool
	exclusionStage       txStage
	sendRecorded         bool
	actualVerdict        txExpectationVerdict
	actualRecorded       bool
}

func newTxAnomalyProjection() *txAnomalyProjection {
	return &txAnomalyProjection{attempts: make(map[string]*txAnomalyAttemptState)}
}

func (p *txAnomalyProjection) RecordExpectation(event txExpectationEvent) bool {
	return p.RecordExpectationWithAppend(event, nil)
}

func (p *txAnomalyProjection) RecordExpectationWithAppend(event txExpectationEvent, appendEvent func() error) bool {
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
	state.runID = event.RunID
	state.attemptID = event.AttemptID
	if event.Endpoint != "" {
		state.endpoint = event.Endpoint
	}
	state.payloadHash = event.PayloadHash
	state.staticVerdict = event.StaticVerdict
	state.preflightVerdict = event.PreflightVerdict
	state.expectationRecorded = true
	return true
}

func (p *txAnomalyProjection) RecordSendAttempt(event txAttemptEvent) bool {
	if p == nil || event.AttemptID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.ensureLocked(event.AttemptID)
	state.runID = event.RunID
	state.attemptID = event.AttemptID
	state.sendRecorded = true
	if event.Endpoint != "" {
		state.endpoint = event.Endpoint
	}
	if event.PayloadHash != "" {
		state.payloadHash = event.PayloadHash
	}
	if event.SendStatus == txSendPreSendError && event.Stage != txStageSend {
		state.excludedPreTxFailure = true
		state.exclusionStage = event.Stage
		return true
	}
	if event.SendStatus == txSendRejected && event.Stage == txStageSend {
		state.actualVerdict = txExpectationFailure
		state.actualRecorded = true
	}
	return true
}

func (p *txAnomalyProjection) RecordReceiptObservation(event txReceiptObservationEvent, confirmBlocks uint64) bool {
	if p == nil || event.AttemptID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.ensureLocked(event.AttemptID)
	state.runID = event.RunID
	state.attemptID = event.AttemptID
	switch event.ReceiptStatus {
	case txReceiptConfirmed:
		state.actualVerdict = txExpectationSuccess
		state.actualRecorded = true
	case txReceiptMined:
		if confirmBlocks == 0 || event.Terminal {
			state.actualVerdict = txExpectationSuccess
			state.actualRecorded = true
		}
	case txReceiptReverted:
		state.actualVerdict = txExpectationFailure
		state.actualRecorded = true
	case txReceiptTimeout, txReceiptPendingAtShutdown:
		state.actualVerdict = txExpectationUnknown
		state.actualRecorded = true
	}
	return true
}

func (p *txAnomalyProjection) Summary() TxAnomalySummary {
	_, summary := p.BuildReport()
	return summary
}

func (p *txAnomalyProjection) BuildReport() ([]txAnomalyEvent, TxAnomalySummary) {
	summary := TxAnomalySummary{
		AnomalyTypeCounts:          make(map[string]int64),
		ExcludedPreTxFailureCounts: make(map[string]int64),
	}
	if p == nil {
		return nil, summary
	}

	p.mu.Lock()
	states := make([]txAnomalyAttemptState, 0, len(p.attempts))
	for _, state := range p.attempts {
		states = append(states, *state)
	}
	p.mu.Unlock()

	details := make([]txAnomalyEvent, 0)
	grouped := make(map[string][]txAnomalyAttemptState)
	now := time.Now()

	for _, state := range states {
		if !state.sendRecorded && !state.expectationRecorded {
			continue
		}
		summary.TotalAttemptCount++
		if state.expectationRecorded {
			summary.ExpectationCount++
			summary.ExpectationEligibleCount++
		}
		if !state.sendRecorded {
			continue
		}
		if state.excludedPreTxFailure {
			summary.ExcludedPreTxFailureCounts[string(state.exclusionStage)]++
			continue
		}
		if state.expectationRecorded && state.actualRecorded {
			summary.AnomalyEligibleCount++
		}
		if state.expectationRecorded && state.actualRecorded && state.payloadHash != "" {
			grouped[state.payloadHash] = append(grouped[state.payloadHash], state)
		}
		if state.expectationRecorded && state.staticVerdict != txExpectationUnknown && state.preflightVerdict != txExpectationUnknown && state.staticVerdict != state.preflightVerdict {
			details = append(details, txAnomalyEvent{
				SchemaVersion:    txAnomalySchemaVersion,
				Event:            txAnomalyEvidenceDetected,
				RunID:            state.runID,
				AttemptID:        state.attemptID,
				Timestamp:        now,
				Type:             txAnomalyPredictionSourceDisagreement,
				Endpoint:         state.endpoint,
				PayloadHash:      state.payloadHash,
				StaticVerdict:    state.staticVerdict,
				PreflightVerdict: state.preflightVerdict,
			})
		}
		if state.expectationRecorded && state.actualRecorded {
			mismatch := false
			if state.staticVerdict != txExpectationUnknown && state.staticVerdict != state.actualVerdict {
				mismatch = true
			}
			if state.preflightVerdict != txExpectationUnknown && state.preflightVerdict != state.actualVerdict {
				mismatch = true
			}
			if mismatch {
				details = append(details, txAnomalyEvent{
					SchemaVersion:    txAnomalySchemaVersion,
					Event:            txAnomalyEvidenceDetected,
					RunID:            state.runID,
					AttemptID:        state.attemptID,
					Timestamp:        now,
					Type:             txAnomalyPredictionActualMismatch,
					Endpoint:         state.endpoint,
					PayloadHash:      state.payloadHash,
					StaticVerdict:    state.staticVerdict,
					PreflightVerdict: state.preflightVerdict,
					ActualVerdict:    state.actualVerdict,
				})
			}
		}
	}

	for payload, group := range grouped {
		verdicts := make(map[txExpectationVerdict]struct{})
		attemptIDs := make([]string, 0, len(group))
		endpoints := make([]string, 0, len(group))
		for _, state := range group {
			if !state.actualRecorded {
				continue
			}
			verdicts[state.actualVerdict] = struct{}{}
			attemptIDs = append(attemptIDs, state.attemptID)
			endpoints = append(endpoints, state.endpoint)
		}
		if len(verdicts) <= 1 {
			continue
		}
		sort.Strings(attemptIDs)
		sort.Strings(endpoints)
		details = append(details, txAnomalyEvent{
			SchemaVersion:     txAnomalySchemaVersion,
			Event:             txAnomalyEvidenceDetected,
			RunID:             group[0].runID,
			Timestamp:         now,
			Type:              txAnomalyCrossNodeOutcomeDisagreement,
			PayloadHash:       payload,
			RelatedAttemptIDs: attemptIDs,
			RelatedEndpoints:  endpoints,
		})
	}

	for _, detail := range details {
		summary.AnomalyTypeCounts[string(detail.Type)]++
	}
	summary.AnomalyCount = int64(len(details))
	return details, summary
}

func (p *txAnomalyProjection) ensureLocked(attemptID string) *txAnomalyAttemptState {
	state := p.attempts[attemptID]
	if state == nil {
		state = &txAnomalyAttemptState{attemptID: attemptID}
		p.attempts[attemptID] = state
	}
	return state
}

func newTxAnomalyRecorder(path string) (*txAttemptRecorder, error) {
	return newTxAttemptRecorder(path)
}

func WriteTxAnomalySummaryJSON(path string, summary TxAnomalySummary) error {
	if path == "" {
		return fmt.Errorf("anomaly summary path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create anomaly summary directory: %w", err)
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal anomaly summary: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write anomaly summary: %w", err)
	}
	return nil
}
