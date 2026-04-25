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
