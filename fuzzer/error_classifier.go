package fuzzer

import (
	"errors"
	"strings"
)

var ErrCircuitBreakerOpen = errors.New("circuit breaker is open")

type SendErrorClass string

const (
	SendErrorNone                   SendErrorClass = "none"
	SendErrorNonce                  SendErrorClass = "nonce"
	SendErrorReplacementUnderpriced SendErrorClass = "replacement"
	SendErrorKnownTransaction       SendErrorClass = "known_transaction"
	SendErrorFunds                  SendErrorClass = "funds"
	SendErrorGas                    SendErrorClass = "gas"
	SendErrorTxPoolFull             SendErrorClass = "txpool_full"
	SendErrorNetwork                SendErrorClass = "network"
	SendErrorCircuitBreakerOpen     SendErrorClass = "circuit_breaker"
	SendErrorUnknown                SendErrorClass = "unknown"
)

func ClassifySendError(err error) SendErrorClass {
	if err == nil {
		return SendErrorNone
	}
	if errors.Is(err, ErrCircuitBreakerOpen) {
		return SendErrorCircuitBreakerOpen
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "circuit breaker is open"):
		return SendErrorCircuitBreakerOpen
	case strings.Contains(msg, "nonce too low") ||
		strings.Contains(msg, "nonce too high") ||
		strings.Contains(msg, "invalid nonce"):
		return SendErrorNonce
	case strings.Contains(msg, "replacement transaction underpriced") ||
		strings.Contains(msg, "replacement underpriced") ||
		strings.Contains(msg, "transaction underpriced"):
		return SendErrorReplacementUnderpriced
	case strings.Contains(msg, "already known") ||
		strings.Contains(msg, "known transaction"):
		return SendErrorKnownTransaction
	case strings.Contains(msg, "insufficient funds"):
		return SendErrorFunds
	case strings.Contains(msg, "txpool is full") ||
		strings.Contains(msg, "transaction pool is full"):
		return SendErrorTxPoolFull
	case strings.Contains(msg, "intrinsic gas too low") ||
		strings.Contains(msg, "insufficient gas for floor data gas cost") ||
		strings.Contains(msg, "gas limit reached") ||
		strings.Contains(msg, "exceeds block gas limit"):
		return SendErrorGas
	case strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "eof") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "network is unreachable"):
		return SendErrorNetwork
	default:
		return SendErrorUnknown
	}
}

func (c SendErrorClass) AffectsCircuitBreaker() bool {
	return c == SendErrorNetwork
}

func (c SendErrorClass) ShouldRetrySend() bool {
	return c == SendErrorNetwork
}

func (c SendErrorClass) Action() string {
	switch c {
	case SendErrorNonce:
		return "refresh_nonce"
	case SendErrorReplacementUnderpriced:
		return "skip_nonce"
	case SendErrorNetwork:
		return "count_endpoint_failure"
	case SendErrorCircuitBreakerOpen:
		return "skip_endpoint"
	case SendErrorKnownTransaction:
		return "record_known_transaction"
	case SendErrorFunds:
		return "record_funds_error"
	case SendErrorGas:
		return "record_gas_error"
	case SendErrorTxPoolFull:
		return "record_txpool_full"
	case SendErrorUnknown:
		return "record_unknown"
	default:
		return "none"
	}
}
