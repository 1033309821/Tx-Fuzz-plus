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
	txAnomalyReplayGroupIncomplete        txAnomalyType = "replay_group_incomplete"
)

type txAnomalyEvent struct {
	SchemaVersion          int                       `json:"schema_version"`
	Event                  txAnomalyEventType        `json:"event"`
	RunID                  string                    `json:"run_id"`
	AttemptID              string                    `json:"attempt_id,omitempty"`
	Timestamp              time.Time                 `json:"timestamp"`
	Type                   txAnomalyType             `json:"type"`
	Endpoint               string                    `json:"endpoint,omitempty"`
	PayloadHash            string                    `json:"payload_hash,omitempty"`
	StaticVerdict          txExpectationVerdict      `json:"static_verdict,omitempty"`
	PreflightVerdict       txExpectationVerdict      `json:"preflight_verdict,omitempty"`
	ActualVerdict          txExpectationVerdict      `json:"actual_verdict,omitempty"`
	RelatedAttemptIDs      []string                  `json:"related_attempt_ids,omitempty"`
	RelatedEndpoints       []string                  `json:"related_endpoints,omitempty"`
	ReplayGroupID          string                    `json:"replay_group_id,omitempty"`
	ReplayGroupComplete    *bool                     `json:"replay_group_complete,omitempty"`
	ReplayScheduledCount   int                       `json:"replay_scheduled_count,omitempty"`
	ReplayEndpointIndex    *int                      `json:"replay_endpoint_index,omitempty"`
	ReplayNoiseAnnotations []txReplayNoiseAnnotation `json:"replay_noise_annotations,omitempty"`
	ReplayOutcomes         []txReplayEndpointOutcome `json:"replay_outcomes,omitempty"`
}

type txReplayEndpointOutcome struct {
	Endpoint      string               `json:"endpoint"`
	Client        string               `json:"client,omitempty"`
	AttemptID     string               `json:"attempt_id"`
	ActualVerdict txExpectationVerdict `json:"actual_verdict"`
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

type replayGroupMeta struct {
	complete       bool
	scheduledCount int
	attemptIDs     []string
}

type txAnomalyAttemptState struct {
	runID                  string
	attemptID              string
	endpoint               string
	payloadHash            string
	replayGroupID          string
	replayClient           string
	replayScheduledCount   int
	replayEndpointIndex    *int
	replayNoiseAnnotations []txReplayNoiseAnnotation
	staticVerdict          txExpectationVerdict
	preflightVerdict       txExpectationVerdict
	expectationRecorded    bool
	excludedPreTxFailure   bool
	exclusionStage         txStage
	sendRecorded           bool
	actualVerdict          txExpectationVerdict
	actualRecorded         bool
	actualOutcomeCaptured  bool
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
	state.replayGroupID = event.ReplayGroupID
	state.replayScheduledCount = event.ReplayScheduledCount
	state.replayEndpointIndex = cloneOptionalInt(event.ReplayEndpointIndex)
	state.replayNoiseAnnotations = cloneReplayNoiseAnnotations(event.ReplayNoiseAnnotations)
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
	if event.ReplayGroupID != "" {
		state.replayGroupID = event.ReplayGroupID
	}
	if event.ReplayClient != "" {
		state.replayClient = event.ReplayClient
	}
	if event.ReplayScheduledCount > 0 {
		state.replayScheduledCount = event.ReplayScheduledCount
	}
	if event.ReplayEndpointIndex != nil {
		state.replayEndpointIndex = cloneOptionalInt(event.ReplayEndpointIndex)
	}
	if event.SendStatus == txSendPreSendError && event.Stage != txStageSend {
		state.excludedPreTxFailure = true
		state.exclusionStage = event.Stage
		return true
	}
	if event.SendStatus == txSendRejected && event.Stage == txStageSend {
		state.actualVerdict = txExpectationFailure
		state.actualRecorded = true
		state.actualOutcomeCaptured = true
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
	if event.ReplayGroupID != "" {
		state.replayGroupID = event.ReplayGroupID
	}
	switch event.ReceiptStatus {
	case txReceiptConfirmed:
		state.actualVerdict = txExpectationSuccess
		state.actualRecorded = true
		state.actualOutcomeCaptured = true
	case txReceiptMined:
		if confirmBlocks == 0 || event.Terminal {
			state.actualVerdict = txExpectationSuccess
			state.actualRecorded = true
			state.actualOutcomeCaptured = true
		}
	case txReceiptReverted:
		state.actualVerdict = txExpectationFailure
		state.actualRecorded = true
		state.actualOutcomeCaptured = true
	case txReceiptTimeout, txReceiptPendingAtShutdown:
		state.actualVerdict = txExpectationUnknown
		state.actualRecorded = true
		state.actualOutcomeCaptured = false
	}
	return true
}

func (p *txAnomalyProjection) Summary() TxAnomalySummary {
	_, summary := p.BuildReport()
	return summary
}

func (p *txAnomalyProjection) ReplayGroupStatusEvents() []txExpectationEvent {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	states := make([]txAnomalyAttemptState, 0, len(p.attempts))
	for _, state := range p.attempts {
		states = append(states, *state)
	}
	p.mu.Unlock()
	groupMeta := buildReplayGroupMeta(states)
	events := make([]txExpectationEvent, 0)
	now := time.Now()
	groupStates := make(map[string][]txAnomalyAttemptState)
	for _, state := range states {
		if state.replayGroupID == "" {
			continue
		}
		groupStates[state.replayGroupID] = append(groupStates[state.replayGroupID], state)
	}
	groupIDs := make([]string, 0, len(groupStates))
	for groupID := range groupStates {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Strings(groupIDs)
	for _, groupID := range groupIDs {
		group := groupStates[groupID]
		sort.Slice(group, func(i, j int) bool {
			return group[i].attemptID < group[j].attemptID
		})
		representative := group[0]
		events = append(events, txExpectationEvent{
			SchemaVersion:        txExpectationSchemaVersion,
			Event:                txExpectationReplayGroupStatusRecorded,
			RunID:                representative.runID,
			AttemptID:            representative.attemptID,
			Timestamp:            now,
			Endpoint:             representative.endpoint,
			ReplayGroupID:        groupID,
			ReplayGroupComplete:  boolPtr(groupMeta[groupID].complete),
			ReplayScheduledCount: groupMeta[groupID].scheduledCount,
			ReplayEndpointIndex:  cloneOptionalInt(representative.replayEndpointIndex),
		})
	}
	return events
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

	groupMeta := buildReplayGroupMeta(states)
	details := make([]txAnomalyEvent, 0)
	groupedByPayload := make(map[string][]txAnomalyAttemptState)
	groupedByReplay := make(map[string][]txAnomalyAttemptState)
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
			if state.replayGroupID != "" {
				groupedByReplay[state.replayGroupID] = append(groupedByReplay[state.replayGroupID], state)
			}
			continue
		}
		if state.replayGroupID != "" {
			groupedByReplay[state.replayGroupID] = append(groupedByReplay[state.replayGroupID], state)
		}
		if state.expectationRecorded && state.actualOutcomeCaptured {
			summary.AnomalyEligibleCount++
			if state.replayGroupID == "" && state.payloadHash != "" {
				groupedByPayload[state.payloadHash] = append(groupedByPayload[state.payloadHash], state)
			}
		}
		if state.expectationRecorded && state.staticVerdict != txExpectationUnknown && state.preflightVerdict != txExpectationUnknown && state.staticVerdict != state.preflightVerdict {
			details = append(details, txAnomalyEvent{
				SchemaVersion:          txAnomalySchemaVersion,
				Event:                  txAnomalyEvidenceDetected,
				RunID:                  state.runID,
				AttemptID:              state.attemptID,
				Timestamp:              now,
				Type:                   txAnomalyPredictionSourceDisagreement,
				Endpoint:               state.endpoint,
				PayloadHash:            state.payloadHash,
				StaticVerdict:          state.staticVerdict,
				PreflightVerdict:       state.preflightVerdict,
				ReplayGroupID:          state.replayGroupID,
				ReplayGroupComplete:    replayGroupCompletePtr(groupMeta, state.replayGroupID),
				ReplayScheduledCount:   state.replayScheduledCount,
				ReplayEndpointIndex:    cloneOptionalInt(state.replayEndpointIndex),
				ReplayNoiseAnnotations: cloneReplayNoiseAnnotations(state.replayNoiseAnnotations),
			})
		}
		if state.expectationRecorded && state.actualOutcomeCaptured {
			mismatch := false
			if state.staticVerdict != txExpectationUnknown && state.staticVerdict != state.actualVerdict {
				mismatch = true
			}
			if state.preflightVerdict != txExpectationUnknown && state.preflightVerdict != state.actualVerdict {
				mismatch = true
			}
			if mismatch {
				details = append(details, txAnomalyEvent{
					SchemaVersion:          txAnomalySchemaVersion,
					Event:                  txAnomalyEvidenceDetected,
					RunID:                  state.runID,
					AttemptID:              state.attemptID,
					Timestamp:              now,
					Type:                   txAnomalyPredictionActualMismatch,
					Endpoint:               state.endpoint,
					PayloadHash:            state.payloadHash,
					StaticVerdict:          state.staticVerdict,
					PreflightVerdict:       state.preflightVerdict,
					ActualVerdict:          state.actualVerdict,
					ReplayGroupID:          state.replayGroupID,
					ReplayGroupComplete:    replayGroupCompletePtr(groupMeta, state.replayGroupID),
					ReplayScheduledCount:   state.replayScheduledCount,
					ReplayEndpointIndex:    cloneOptionalInt(state.replayEndpointIndex),
					ReplayNoiseAnnotations: cloneReplayNoiseAnnotations(state.replayNoiseAnnotations),
				})
			}
		}
	}

	for payload, group := range groupedByPayload {
		verdicts := make(map[txExpectationVerdict]struct{})
		attemptIDs := make([]string, 0, len(group))
		endpoints := make([]string, 0, len(group))
		for _, state := range group {
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

	for replayGroupID, group := range groupedByReplay {
		verdicts := make(map[txExpectationVerdict]struct{})
		attemptIDs := make([]string, 0, len(group))
		endpoints := make([]string, 0, len(group))
		outcomes := make([]txReplayEndpointOutcome, 0, len(group))
		scheduledCount := 0
		complete := true
		noiseAnnotations := make([]txReplayNoiseAnnotation, 0)
		for _, state := range group {
			if state.replayScheduledCount > scheduledCount {
				scheduledCount = state.replayScheduledCount
			}
			if !state.actualOutcomeCaptured {
				complete = false
			} else {
				verdicts[state.actualVerdict] = struct{}{}
				outcomes = append(outcomes, txReplayEndpointOutcome{
					Endpoint:      state.endpoint,
					Client:        state.replayClient,
					AttemptID:     state.attemptID,
					ActualVerdict: state.actualVerdict,
				})
			}
			attemptIDs = append(attemptIDs, state.attemptID)
			endpoints = append(endpoints, state.endpoint)
			noiseAnnotations = append(noiseAnnotations, state.replayNoiseAnnotations...)
		}
		if scheduledCount == 0 {
			scheduledCount = len(group)
		}
		if len(group) != scheduledCount {
			complete = false
		}
		sort.Strings(attemptIDs)
		sort.Strings(endpoints)
		sort.Slice(outcomes, func(i, j int) bool {
			if outcomes[i].Endpoint == outcomes[j].Endpoint {
				return outcomes[i].AttemptID < outcomes[j].AttemptID
			}
			return outcomes[i].Endpoint < outcomes[j].Endpoint
		})
		if !complete {
			details = append(details, txAnomalyEvent{
				SchemaVersion:          txAnomalySchemaVersion,
				Event:                  txAnomalyEvidenceDetected,
				RunID:                  group[0].runID,
				Timestamp:              now,
				Type:                   txAnomalyReplayGroupIncomplete,
				RelatedAttemptIDs:      attemptIDs,
				RelatedEndpoints:       endpoints,
				ReplayGroupID:          replayGroupID,
				ReplayGroupComplete:    boolPtr(false),
				ReplayScheduledCount:   scheduledCount,
				ReplayNoiseAnnotations: cloneReplayNoiseAnnotations(noiseAnnotations),
				ReplayOutcomes:         outcomes,
			})
			continue
		}
		if len(verdicts) <= 1 {
			continue
		}
		details = append(details, txAnomalyEvent{
			SchemaVersion:          txAnomalySchemaVersion,
			Event:                  txAnomalyEvidenceDetected,
			RunID:                  group[0].runID,
			Timestamp:              now,
			Type:                   txAnomalyCrossNodeOutcomeDisagreement,
			RelatedAttemptIDs:      attemptIDs,
			RelatedEndpoints:       endpoints,
			ReplayGroupID:          replayGroupID,
			ReplayGroupComplete:    boolPtr(complete),
			ReplayScheduledCount:   scheduledCount,
			ReplayNoiseAnnotations: cloneReplayNoiseAnnotations(noiseAnnotations),
			ReplayOutcomes:         outcomes,
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

func cloneReplayNoiseAnnotations(in []txReplayNoiseAnnotation) []txReplayNoiseAnnotation {
	if len(in) == 0 {
		return nil
	}
	out := make([]txReplayNoiseAnnotation, len(in))
	copy(out, in)
	return out
}

func cloneOptionalInt(in *int) *int {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

func buildReplayGroupMeta(states []txAnomalyAttemptState) map[string]replayGroupMeta {
	meta := make(map[string]replayGroupMeta)
	counts := make(map[string]int)
	for _, state := range states {
		if state.replayGroupID == "" {
			continue
		}
		group := meta[state.replayGroupID]
		if len(group.attemptIDs) == 0 {
			group.complete = true
		}
		if state.replayScheduledCount > group.scheduledCount {
			group.scheduledCount = state.replayScheduledCount
		}
		group.attemptIDs = append(group.attemptIDs, state.attemptID)
		counts[state.replayGroupID]++
		if !state.actualOutcomeCaptured {
			group.complete = false
		}
		meta[state.replayGroupID] = group
	}
	for groupID, group := range meta {
		if group.scheduledCount == 0 {
			group.scheduledCount = counts[groupID]
		}
		if counts[groupID] != group.scheduledCount {
			group.complete = false
		}
		sort.Strings(group.attemptIDs)
		meta[groupID] = group
	}
	return meta
}

func replayGroupCompletePtr(meta map[string]replayGroupMeta, groupID string) *bool {
	if groupID == "" {
		return nil
	}
	group, ok := meta[groupID]
	if !ok {
		return nil
	}
	return boolPtr(group.complete)
}
