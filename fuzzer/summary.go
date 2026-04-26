package fuzzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TxRunSummary is the compact, durable summary emitted after a tx fuzz run.
type TxRunSummary struct {
	StartedAt                  time.Time        `json:"started_at"`
	FinishedAt                 time.Time        `json:"finished_at"`
	DurationSeconds            int64            `json:"duration_seconds"`
	EndpointCount              int              `json:"endpoint_count"`
	TotalSent                  int64            `json:"total_sent"`
	TotalMined                 int64            `json:"total_mined"`
	TotalFailed                int64            `json:"total_failed"`
	TotalPending               int64            `json:"total_pending"`
	MutationUsed               int64            `json:"mutation_used"`
	RandomUsed                 int64            `json:"random_used"`
	ErrorClassCounts           map[string]int64 `json:"error_class_counts"`
	AttemptLogPath             string           `json:"attempt_log_path,omitempty"`
	AttemptCount               int64            `json:"attempt_count,omitempty"`
	SendStatusCounts           map[string]int64 `json:"send_status_counts,omitempty"`
	ReceiptStatusCounts        map[string]int64 `json:"receipt_status_counts,omitempty"`
	ExpectationLogPath         string           `json:"expectation_log_path,omitempty"`
	ExpectationCount           int64            `json:"expectation_count,omitempty"`
	AnomalyLogPath             string           `json:"anomaly_log_path,omitempty"`
	AnomalySummaryPath         string           `json:"anomaly_summary_path,omitempty"`
	AnomalyCount               int64            `json:"anomaly_count,omitempty"`
	AnomalyTypeCounts          map[string]int64 `json:"anomaly_type_counts,omitempty"`
	ExpectationEligibleCount   int64            `json:"expectation_eligible_attempt_count,omitempty"`
	AnomalyEligibleCount       int64            `json:"anomaly_eligible_attempt_count,omitempty"`
	ExcludedPreTxFailureCounts map[string]int64 `json:"excluded_pre_tx_failure_counts,omitempty"`
}

// BuildRunSummary snapshots the fuzzer counters without exposing internal locks.
func (tf *TxFuzzer) BuildRunSummary(finishedAt time.Time) TxRunSummary {
	stats := tf.GetStats()

	tf.healthMutex.RLock()
	endpointCount := len(tf.nodeHealth)
	tf.healthMutex.RUnlock()

	resultSummary := TxResultSummary{}
	if tf.txAttemptProjection != nil {
		resultSummary = tf.txAttemptProjection.Summary()
	}
	anomalySummary := TxAnomalySummary{}
	if tf.txAnomalyProjection != nil {
		anomalySummary = tf.txAnomalyProjection.Summary()
	}
	if tf.txAttemptLogPath != "" {
		resultSummary.AttemptLogPath = tf.txAttemptLogPath
	}
	errorClassCounts := tf.ErrorClassCounts()
	if resultSummary.AttemptCount > 0 {
		for class, count := range resultSummary.ErrorClassCounts {
			errorClassCounts[class] = count
		}
	}

	return TxRunSummary{
		StartedAt:                  stats.StartTime,
		FinishedAt:                 finishedAt,
		DurationSeconds:            int64(finishedAt.Sub(stats.StartTime).Seconds()),
		EndpointCount:              endpointCount,
		TotalSent:                  stats.TotalSent,
		TotalMined:                 stats.TotalMined,
		TotalFailed:                stats.TotalFailed,
		TotalPending:               stats.TotalPending,
		MutationUsed:               stats.MutationUsed,
		RandomUsed:                 stats.RandomUsed,
		ErrorClassCounts:           errorClassCounts,
		AttemptLogPath:             resultSummary.AttemptLogPath,
		AttemptCount:               resultSummary.AttemptCount,
		SendStatusCounts:           resultSummary.SendStatusCounts,
		ReceiptStatusCounts:        resultSummary.ReceiptStatusCounts,
		ExpectationLogPath:         tf.txExpectationLogPath,
		ExpectationCount:           anomalySummary.ExpectationCount,
		AnomalyLogPath:             tf.txAnomalyLogPath,
		AnomalySummaryPath:         tf.txAnomalySummaryPath,
		AnomalyCount:               anomalySummary.AnomalyCount,
		AnomalyTypeCounts:          anomalySummary.AnomalyTypeCounts,
		ExpectationEligibleCount:   anomalySummary.ExpectationEligibleCount,
		AnomalyEligibleCount:       anomalySummary.AnomalyEligibleCount,
		ExcludedPreTxFailureCounts: anomalySummary.ExcludedPreTxFailureCounts,
	}
}

// ErrorClassCounts returns a copy of the classified send-error counters.
func (tf *TxFuzzer) ErrorClassCounts() map[string]int64 {
	counts := make(map[string]int64)
	if tf == nil {
		return counts
	}

	tf.errorClassCountsMutex.RLock()
	defer tf.errorClassCountsMutex.RUnlock()

	for class, count := range tf.errorClassCounts {
		counts[string(class)] = count
	}
	return counts
}

func (tf *TxFuzzer) recordErrorClass(class SendErrorClass) {
	if class == SendErrorNone {
		return
	}

	tf.errorClassCountsMutex.Lock()
	defer tf.errorClassCountsMutex.Unlock()

	if tf.errorClassCounts == nil {
		tf.errorClassCounts = make(map[SendErrorClass]int64)
	}
	tf.errorClassCounts[class]++
}

// WriteRunSummaryJSON writes the summary as indented JSON, creating parents as needed.
func WriteRunSummaryJSON(path string, summary TxRunSummary) error {
	if path == "" {
		return fmt.Errorf("summary path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create summary directory: %w", err)
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tx fuzz summary: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write tx fuzz summary: %w", err)
	}
	return nil
}
