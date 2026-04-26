package fuzzer

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeNonceReader struct {
	nonces map[common.Address]uint64
	calls  int
}

func (f *fakeNonceReader) PendingNonceAt(ctx context.Context, address common.Address) (uint64, error) {
	f.calls++
	return f.nonces[address], nil
}

func TestNonceManagerAllocatesSequentialNoncesPerAccount(t *testing.T) {
	addr := common.HexToAddress("0x1")
	reader := &fakeNonceReader{nonces: map[common.Address]uint64{addr: 7}}
	manager := NewNonceManager()

	first, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)
	second, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)
	third, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)

	assert.Equal(t, uint64(7), first)
	assert.Equal(t, uint64(8), second)
	assert.Equal(t, uint64(9), third)
	assert.Equal(t, 1, reader.calls, "remote pending nonce should only initialize the local stream")
}

func TestNonceManagerTracksAccountsIndependently(t *testing.T) {
	addrA := common.HexToAddress("0xa")
	addrB := common.HexToAddress("0xb")
	reader := &fakeNonceReader{nonces: map[common.Address]uint64{
		addrA: 3,
		addrB: 42,
	}}
	manager := NewNonceManager()

	nonceA, err := manager.Next(context.Background(), reader, addrA)
	require.NoError(t, err)
	nonceB, err := manager.Next(context.Background(), reader, addrB)
	require.NoError(t, err)
	nextA, err := manager.Next(context.Background(), reader, addrA)
	require.NoError(t, err)

	assert.Equal(t, uint64(3), nonceA)
	assert.Equal(t, uint64(42), nonceB)
	assert.Equal(t, uint64(4), nextA)
}

func TestNonceManagerRefreshKeepsAheadLocalNonce(t *testing.T) {
	addr := common.HexToAddress("0x1")
	reader := &fakeNonceReader{nonces: map[common.Address]uint64{addr: 5}}
	manager := NewNonceManager()

	_, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)
	_, err = manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)

	reader.nonces[addr] = 4
	refreshed, err := manager.Refresh(context.Background(), reader, addr)
	require.NoError(t, err)
	next, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)

	assert.Equal(t, uint64(7), refreshed)
	assert.Equal(t, uint64(7), next)
}

func TestNonceManagerRefreshAdvancesStaleLocalNonce(t *testing.T) {
	addr := common.HexToAddress("0x1")
	reader := &fakeNonceReader{nonces: map[common.Address]uint64{addr: 1}}
	manager := NewNonceManager()

	_, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)

	reader.nonces[addr] = 10
	refreshed, err := manager.Refresh(context.Background(), reader, addr)
	require.NoError(t, err)
	next, err := manager.Next(context.Background(), reader, addr)
	require.NoError(t, err)

	assert.Equal(t, uint64(10), refreshed)
	assert.Equal(t, uint64(10), next)
}
