package fuzzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTxFuzzerRunSummaryIncludesCountsDurationAndEndpoints(t *testing.T) {
	started := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	f := &TxFuzzer{
		stats: &TxStats{
			TotalSent:      7,
			TotalFailed:    3,
			MutationUsed:   2,
			RandomUsed:     8,
			StartTime:      started,
			LastUpdateTime: started.Add(3 * time.Second),
		},
		errorClassCounts: map[SendErrorClass]int64{
			SendErrorNetwork:                2,
			SendErrorReplacementUnderpriced: 1,
		},
		nodeHealth: map[string]bool{
			"http://127.0.0.1:8545": true,
			"http://127.0.0.1:9545": false,
		},
	}

	summary := f.BuildRunSummary(started.Add(5 * time.Second))

	assert.Equal(t, int64(7), summary.TotalSent)
	assert.Equal(t, int64(3), summary.TotalFailed)
	assert.Equal(t, 2, summary.EndpointCount)
	assert.Equal(t, int64(5), summary.DurationSeconds)
	assert.Equal(t, int64(2), summary.ErrorClassCounts[string(SendErrorNetwork)])
	assert.Equal(t, int64(1), summary.ErrorClassCounts[string(SendErrorReplacementUnderpriced)])
}

func TestWriteRunSummaryJSONCreatesParentAndWritesStableJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "summary.json")
	summary := TxRunSummary{
		StartedAt:        time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
		FinishedAt:       time.Date(2026, 4, 21, 12, 0, 5, 0, time.UTC),
		DurationSeconds:  5,
		EndpointCount:    1,
		TotalSent:        4,
		ErrorClassCounts: map[string]int64{"gas": 2},
	}

	require.NoError(t, WriteRunSummaryJSON(path, summary))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var got TxRunSummary
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, summary.TotalSent, got.TotalSent)
	assert.Equal(t, summary.ErrorClassCounts, got.ErrorClassCounts)
}
