package fuzzer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifySendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want SendErrorClass
	}{
		{
			name: "nil",
			err:  nil,
			want: SendErrorNone,
		},
		{
			name: "nonce too low",
			err:  errors.New("max retries exceeded: nonce too low: next nonce 3, tx nonce 2"),
			want: SendErrorNonce,
		},
		{
			name: "replacement underpriced",
			err:  errors.New("max retries exceeded: replacement transaction underpriced"),
			want: SendErrorReplacementUnderpriced,
		},
		{
			name: "already known",
			err:  errors.New("already known"),
			want: SendErrorKnownTransaction,
		},
		{
			name: "insufficient funds",
			err:  errors.New("insufficient funds for gas * price + value"),
			want: SendErrorFunds,
		},
		{
			name: "intrinsic gas too low",
			err:  errors.New("intrinsic gas too low: gas 27679, minimum needed 30128"),
			want: SendErrorGas,
		},
		{
			name: "floor data gas",
			err:  errors.New("insufficient gas for floor data gas cost: gas 55837, minimum needed 59130"),
			want: SendErrorGas,
		},
		{
			name: "network",
			err:  errors.New("dial tcp 127.0.0.1:8545: connection refused"),
			want: SendErrorNetwork,
		},
		{
			name: "txpool full",
			err:  errors.New("txpool is full"),
			want: SendErrorTxPoolFull,
		},
		{
			name: "circuit breaker",
			err:  ErrCircuitBreakerOpen,
			want: SendErrorCircuitBreakerOpen,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("send failed: %w", errors.New("i/o timeout")),
			want: SendErrorNetwork,
		},
		{
			name: "unknown",
			err:  errors.New("some client-specific rejection"),
			want: SendErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifySendError(tt.err))
		})
	}
}

func TestSendErrorClassCircuitBreakerPolicy(t *testing.T) {
	assert.True(t, SendErrorNetwork.AffectsCircuitBreaker())

	assert.False(t, SendErrorNonce.AffectsCircuitBreaker())
	assert.False(t, SendErrorReplacementUnderpriced.AffectsCircuitBreaker())
	assert.False(t, SendErrorKnownTransaction.AffectsCircuitBreaker())
	assert.False(t, SendErrorFunds.AffectsCircuitBreaker())
	assert.False(t, SendErrorGas.AffectsCircuitBreaker())
	assert.False(t, SendErrorTxPoolFull.AffectsCircuitBreaker())
	assert.False(t, SendErrorCircuitBreakerOpen.AffectsCircuitBreaker())
	assert.False(t, SendErrorUnknown.AffectsCircuitBreaker())
}

func TestSendErrorClassActions(t *testing.T) {
	assert.Equal(t, "refresh_nonce", SendErrorNonce.Action())
	assert.Equal(t, "skip_nonce", SendErrorReplacementUnderpriced.Action())
	assert.Equal(t, "record_gas_error", SendErrorGas.Action())
	assert.Equal(t, "count_endpoint_failure", SendErrorNetwork.Action())
	assert.Equal(t, "record_txpool_full", SendErrorTxPoolFull.Action())
	assert.Equal(t, "skip_endpoint", SendErrorCircuitBreakerOpen.Action())
}

func TestCircuitBreakerDoesNotOpenForBusinessErrors(t *testing.T) {
	cb := NewCircuitBreaker(1, 0)

	err := cb.CallClassified(func() error {
		return errors.New("replacement transaction underpriced")
	})

	assert.Error(t, err)
	assert.Equal(t, "closed", cb.state)
}

func TestCircuitBreakerOpensForNetworkErrors(t *testing.T) {
	cb := NewCircuitBreaker(1, 0)

	err := cb.CallClassified(func() error {
		return errors.New("connection refused")
	})

	assert.Error(t, err)
	assert.Equal(t, "open", cb.state)
}
