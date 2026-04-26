package fuzzer

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type nonceReader interface {
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

type NonceManager struct {
	mu   sync.Mutex
	next map[common.Address]uint64
}

func NewNonceManager() *NonceManager {
	return &NonceManager{next: make(map[common.Address]uint64)}
}

func (m *NonceManager) Next(ctx context.Context, client nonceReader, address common.Address) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.next[address]; !ok {
		nonce, err := client.PendingNonceAt(ctx, address)
		if err != nil {
			return 0, err
		}
		m.next[address] = nonce
	}

	nonce := m.next[address]
	m.next[address]++
	return nonce, nil
}

func (m *NonceManager) Refresh(ctx context.Context, client nonceReader, address common.Address) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	remoteNonce, err := client.PendingNonceAt(ctx, address)
	if err != nil {
		return 0, err
	}

	if localNonce, ok := m.next[address]; ok && localNonce > remoteNonce {
		return localNonce, nil
	}

	m.next[address] = remoteNonce
	return remoteNonce, nil
}
