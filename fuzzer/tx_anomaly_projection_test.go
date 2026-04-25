package fuzzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTxAnomalyProjectionExcludesPreTxFailuresFromExpectationAndAnomalyCoverage(t *testing.T) {
	projection := newTxAnomalyProjection()
	projection.RecordSendAttempt(txAttemptEvent{
		RunID:      "run-1",
		AttemptID:  "attempt-1",
		Timestamp:  time.Now().UTC(),
		Stage:      txStageNonceFetch,
		SendStatus: txSendPreSendError,
	})

	details, summary := projection.BuildReport()

	assert.Empty(t, details)
	assert.Equal(t, int64(1), summary.TotalAttemptCount)
	assert.Equal(t, int64(0), summary.ExpectationCount)
	assert.Equal(t, int64(0), summary.AnomalyEligibleCount)
	assert.Equal(t, int64(1), summary.ExcludedPreTxFailureCounts[string(txStageNonceFetch)])
}

func TestTxAnomalyProjectionEmitsPredictionSourceAndActualMismatchAnomalies(t *testing.T) {
	projection := newTxAnomalyProjection()
	projection.RecordExpectation(txExpectationEvent{
		RunID:            "run-1",
		AttemptID:        "attempt-1",
		Timestamp:        time.Now().UTC(),
		Endpoint:         "http://node-a",
		PayloadHash:      "payload-1",
		StaticVerdict:    txExpectationSuccess,
		StaticReason:     "basic_envelope_valid",
		PreflightVerdict: txExpectationFailure,
		PreflightReason:  txPreflightReasonSimulationFailed,
	})
	projection.RecordSendAttempt(txAttemptEvent{
		RunID:      "run-1",
		AttemptID:  "attempt-1",
		Timestamp:  time.Now().UTC(),
		Stage:      txStageSend,
		SendStatus: txSendRejected,
		Endpoint:   "http://node-a",
	})

	details, summary := projection.BuildReport()

	require.Len(t, details, 2)
	assert.Equal(t, int64(1), summary.ExpectationCount)
	assert.Equal(t, int64(1), summary.AnomalyEligibleCount)
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyPredictionSourceDisagreement)])
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyPredictionActualMismatch)])
}

func TestTxAnomalyProjectionEmitsCrossNodeDisagreementForSharedPayloadHash(t *testing.T) {
	projection := newTxAnomalyProjection()
	projection.RecordExpectation(txExpectationEvent{
		RunID:            "run-1",
		AttemptID:        "attempt-a",
		Timestamp:        time.Now().UTC(),
		Endpoint:         "http://node-a",
		PayloadHash:      "payload-1",
		StaticVerdict:    txExpectationSuccess,
		PreflightVerdict: txExpectationSuccess,
	})
	projection.RecordExpectation(txExpectationEvent{
		RunID:            "run-1",
		AttemptID:        "attempt-b",
		Timestamp:        time.Now().UTC(),
		Endpoint:         "http://node-b",
		PayloadHash:      "payload-1",
		StaticVerdict:    txExpectationSuccess,
		PreflightVerdict: txExpectationSuccess,
	})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "attempt-a", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-a"})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "attempt-b", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-b"})
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "attempt-a", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptConfirmed, Terminal: true}, 0)
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "attempt-b", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptReverted, Terminal: true}, 0)

	details, summary := projection.BuildReport()

	require.Len(t, details, 2)
	var crossNode *txAnomalyEvent
	for i := range details {
		if details[i].Type == txAnomalyCrossNodeOutcomeDisagreement {
			crossNode = &details[i]
			break
		}
	}
	require.NotNil(t, crossNode)
	assert.ElementsMatch(t, []string{"attempt-a", "attempt-b"}, crossNode.RelatedAttemptIDs)
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyCrossNodeOutcomeDisagreement)])
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyPredictionActualMismatch)])
	assert.Equal(t, int64(2), summary.AnomalyEligibleCount)
}

func TestTxAnomalyProjectionUsesReplayGroupIDWithoutMergingNonReplayPayloadCollisions(t *testing.T) {
	projection := newTxAnomalyProjection()

	projection.RecordExpectation(txExpectationEvent{
		RunID:                "run-1",
		AttemptID:            "replay-a",
		Timestamp:            time.Now().UTC(),
		Endpoint:             "http://node-a",
		PayloadHash:          "shared-payload",
		ReplayGroupID:        "replay-group-1",
		ReplayEndpointIndex:  intPtr(0),
		ReplayScheduledCount: 2,
		StaticVerdict:        txExpectationSuccess,
		PreflightVerdict:     txExpectationSuccess,
	})
	projection.RecordExpectation(txExpectationEvent{
		RunID:                "run-1",
		AttemptID:            "replay-b",
		Timestamp:            time.Now().UTC(),
		Endpoint:             "http://node-b",
		PayloadHash:          "shared-payload",
		ReplayGroupID:        "replay-group-1",
		ReplayEndpointIndex:  intPtr(1),
		ReplayScheduledCount: 2,
		StaticVerdict:        txExpectationSuccess,
		PreflightVerdict:     txExpectationSuccess,
	})
	projection.RecordExpectation(txExpectationEvent{
		RunID:            "run-1",
		AttemptID:        "random-collision",
		Timestamp:        time.Now().UTC(),
		Endpoint:         "http://node-c",
		PayloadHash:      "shared-payload",
		StaticVerdict:    txExpectationSuccess,
		PreflightVerdict: txExpectationSuccess,
	})

	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-a", ReplayGroupID: "replay-group-1", ReplayEndpointIndex: intPtr(0), ReplayScheduledCount: 2})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-b", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-b", ReplayGroupID: "replay-group-1", ReplayEndpointIndex: intPtr(1), ReplayScheduledCount: 2})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "random-collision", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-c"})

	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptConfirmed, Terminal: true}, 0)
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "replay-b", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptReverted, Terminal: true}, 0)
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "random-collision", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptReverted, Terminal: true}, 0)

	details, summary := projection.BuildReport()

	var crossNode *txAnomalyEvent
	for i := range details {
		if details[i].Type == txAnomalyCrossNodeOutcomeDisagreement {
			crossNode = &details[i]
			break
		}
	}
	require.NotNil(t, crossNode)
	assert.Equal(t, "replay-group-1", crossNode.ReplayGroupID)
	assert.ElementsMatch(t, []string{"replay-a", "replay-b"}, crossNode.RelatedAttemptIDs)
	assert.NotContains(t, crossNode.RelatedAttemptIDs, "random-collision")
	assert.Equal(t, int64(1), summary.AnomalyTypeCounts[string(txAnomalyCrossNodeOutcomeDisagreement)])
}

func TestTxAnomalyProjectionExcludesIncompleteReplayGroupsFromCrossNodeDisagreement(t *testing.T) {
	projection := newTxAnomalyProjection()

	projection.RecordExpectation(txExpectationEvent{
		RunID:                "run-1",
		AttemptID:            "replay-a",
		Timestamp:            time.Now().UTC(),
		Endpoint:             "http://node-a",
		ReplayGroupID:        "replay-group-2",
		ReplayEndpointIndex:  intPtr(0),
		ReplayScheduledCount: 2,
		StaticVerdict:        txExpectationSuccess,
		PreflightVerdict:     txExpectationSuccess,
	})
	projection.RecordExpectation(txExpectationEvent{
		RunID:                "run-1",
		AttemptID:            "replay-b",
		Timestamp:            time.Now().UTC(),
		Endpoint:             "http://node-b",
		ReplayGroupID:        "replay-group-2",
		ReplayEndpointIndex:  intPtr(1),
		ReplayScheduledCount: 2,
		StaticVerdict:        txExpectationSuccess,
		PreflightVerdict:     txExpectationSuccess,
	})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-a", ReplayGroupID: "replay-group-2", ReplayEndpointIndex: intPtr(0), ReplayScheduledCount: 2})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-b", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-b", ReplayGroupID: "replay-group-2", ReplayEndpointIndex: intPtr(1), ReplayScheduledCount: 2})
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptConfirmed, Terminal: true}, 0)

	details, summary := projection.BuildReport()

	var incomplete *txAnomalyEvent
	for _, detail := range details {
		assert.NotEqual(t, txAnomalyCrossNodeOutcomeDisagreement, detail.Type)
		if detail.Type == txAnomalyReplayGroupIncomplete {
			incomplete = &detail
		}
	}
	assert.Zero(t, summary.AnomalyTypeCounts[string(txAnomalyCrossNodeOutcomeDisagreement)])
	require.NotNil(t, incomplete)
	assert.Equal(t, "replay-group-2", incomplete.ReplayGroupID)
	require.NotNil(t, incomplete.ReplayGroupComplete)
	assert.False(t, *incomplete.ReplayGroupComplete)
}

func TestTxAnomalyProjectionAnnotatesPreflightOnlyReplayNoiseWithoutCrossNodeDisagreement(t *testing.T) {
	projection := newTxAnomalyProjection()
	noise := []txReplayNoiseAnnotation{{
		Client:     "ethrex",
		Stage:      string(txStageSend),
		ReasonCode: "client_nonce_validation_error",
		Detail:     "Vm execution error: Invalid Transaction: Nonce mismatch: expected 2, got 1",
	}}

	projection.RecordExpectation(txExpectationEvent{
		RunID:                  "run-1",
		AttemptID:              "replay-a",
		Timestamp:              time.Now().UTC(),
		Endpoint:               "http://node-a",
		ReplayGroupID:          "replay-group-3",
		ReplayEndpointIndex:    intPtr(0),
		ReplayScheduledCount:   2,
		StaticVerdict:          txExpectationSuccess,
		PreflightVerdict:       txExpectationFailure,
		ReplayNoiseAnnotations: noise,
	})
	projection.RecordExpectation(txExpectationEvent{
		RunID:                "run-1",
		AttemptID:            "replay-b",
		Timestamp:            time.Now().UTC(),
		Endpoint:             "http://node-b",
		ReplayGroupID:        "replay-group-3",
		ReplayEndpointIndex:  intPtr(1),
		ReplayScheduledCount: 2,
		StaticVerdict:        txExpectationSuccess,
		PreflightVerdict:     txExpectationSuccess,
	})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-a", ReplayGroupID: "replay-group-3", ReplayEndpointIndex: intPtr(0), ReplayScheduledCount: 2})
	projection.RecordSendAttempt(txAttemptEvent{RunID: "run-1", AttemptID: "replay-b", Timestamp: time.Now().UTC(), Stage: txStageSend, SendStatus: txSendAccepted, Endpoint: "http://node-b", ReplayGroupID: "replay-group-3", ReplayEndpointIndex: intPtr(1), ReplayScheduledCount: 2})
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "replay-a", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptConfirmed, Terminal: true}, 0)
	projection.RecordReceiptObservation(txReceiptObservationEvent{RunID: "run-1", AttemptID: "replay-b", Timestamp: time.Now().UTC(), ReceiptStatus: txReceiptConfirmed, Terminal: true}, 0)

	details, summary := projection.BuildReport()

	assert.Zero(t, summary.AnomalyTypeCounts[string(txAnomalyCrossNodeOutcomeDisagreement)])
	var predictionSource *txAnomalyEvent
	for i := range details {
		if details[i].Type == txAnomalyPredictionSourceDisagreement {
			predictionSource = &details[i]
			break
		}
	}
	require.NotNil(t, predictionSource)
	require.Len(t, predictionSource.ReplayNoiseAnnotations, 1)
	assert.Equal(t, "ethrex", predictionSource.ReplayNoiseAnnotations[0].Client)
	assert.Equal(t, "client_nonce_validation_error", predictionSource.ReplayNoiseAnnotations[0].ReasonCode)
}

func TestTxAnomalyProjectionReplayGroupStatusEventsIncludePreExpectationFailures(t *testing.T) {
	projection := newTxAnomalyProjection()
	projection.RecordSendAttempt(txAttemptEvent{
		RunID:                "run-1",
		AttemptID:            "replay-preflight-fail-a",
		Timestamp:            time.Now().UTC(),
		Stage:                txStageNonceFetch,
		SendStatus:           txSendPreSendError,
		Endpoint:             "http://node-a",
		ReplayGroupID:        "replay-group-4",
		ReplayEndpointIndex:  intPtr(0),
		ReplayScheduledCount: 2,
	})
	projection.RecordSendAttempt(txAttemptEvent{
		RunID:                "run-1",
		AttemptID:            "replay-preflight-fail-b",
		Timestamp:            time.Now().UTC(),
		Stage:                txStageEndpointSelection,
		SendStatus:           txSendPreSendError,
		Endpoint:             "http://node-b",
		ReplayGroupID:        "replay-group-4",
		ReplayEndpointIndex:  intPtr(1),
		ReplayScheduledCount: 2,
	})

	events := projection.ReplayGroupStatusEvents()

	require.Len(t, events, 1)
	assert.Equal(t, txExpectationReplayGroupStatusRecorded, events[0].Event)
	require.NotNil(t, events[0].ReplayGroupComplete)
	assert.False(t, *events[0].ReplayGroupComplete)
	assert.Equal(t, "replay-group-4", events[0].ReplayGroupID)
}
