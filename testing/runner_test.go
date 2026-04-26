package testing

import (
	stdtesting "testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryContainsExpectedManualModes(std *stdtesting.T) {
	expectedModes := []string{
		"single",
		"multi",
		"test-soft-limit",
		"test-soft-limit-single",
		"test-soft-limit-report",
		"oneTransaction",
		"largeTransactions",
		"blob-single",
		"blob-multi",
	}

	runners := GetAllRunners()
	for _, mode := range expectedModes {
		runner, ok := GetRunner(mode)
		require.Truef(std, ok, "expected runner %q to be registered", mode)
		require.NotNilf(std, runner, "expected runner %q to be non-nil", mode)
		assert.NotEmptyf(std, runner.Description(), "expected runner %q to have a description", mode)
	}

	assert.Len(std, runners, len(expectedModes))
}

func TestGetRunnerReturnsFalseForUnknownMode(std *stdtesting.T) {
	runner, ok := GetRunner("does-not-exist")
	assert.False(std, ok)
	assert.Nil(std, runner)
}
