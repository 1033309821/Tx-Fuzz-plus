package fuzzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/1033309821/ECST/config"
)

type TxReplayConfig struct {
	Enabled           bool
	GroupCount        int
	EndpointsPerGroup int
	TxType            string
	PayloadSize       int
}

type txReplayPlan struct {
	Groups []txReplayGroup
}

type txReplayGroup struct {
	ID          string
	TxType      uint8
	To          common.Address
	Payload     []byte
	Assignments []txReplayAssignment
}

type txReplayAssignment struct {
	Endpoint      string
	EndpointIndex int
	Client        string
	Account       config.Account
	Payload       []byte
}

func validateReplayConfig(cfg *TxFuzzConfig, accounts []config.Account) error {
	if cfg == nil || cfg.Replay == nil || !cfg.Replay.Enabled {
		return nil
	}
	if cfg.Replay.GroupCount <= 0 {
		return fmt.Errorf("replay group_count must be greater than zero")
	}
	if cfg.Replay.EndpointsPerGroup <= 1 {
		return fmt.Errorf("replay endpoints_per_group must be greater than one")
	}
	if len(accounts) < cfg.Replay.EndpointsPerGroup {
		return fmt.Errorf("replay requires %d funded accounts, got %d", cfg.Replay.EndpointsPerGroup, len(accounts))
	}
	seen := make(map[common.Address]struct{}, cfg.Replay.EndpointsPerGroup)
	for i := 0; i < cfg.Replay.EndpointsPerGroup; i++ {
		address, err := replayAccountAddress(accounts[i])
		if err != nil {
			return err
		}
		if _, exists := seen[address]; exists {
			return fmt.Errorf("replay requires distinct sender accounts per endpoint")
		}
		seen[address] = struct{}{}
	}
	endpoints := replayEndpointsForConfig(cfg)
	if len(endpoints) < cfg.Replay.EndpointsPerGroup {
		return fmt.Errorf("replay requires %d endpoints, got %d", cfg.Replay.EndpointsPerGroup, len(endpoints))
	}
	if _, err := replayTxType(cfg.Replay.TxType); err != nil {
		return err
	}
	return nil
}

func buildTxReplayPlan(replayCfg *TxReplayConfig, multiNode *MultiNodeConfig, accounts []config.Account) (*txReplayPlan, error) {
	if replayCfg == nil || !replayCfg.Enabled {
		return nil, fmt.Errorf("replay is not enabled")
	}
	cfg := &TxFuzzConfig{RPCEndpoint: "", MultiNode: multiNode, Replay: replayCfg}
	if err := validateReplayConfig(cfg, accounts); err != nil {
		return nil, err
	}

	txType, err := replayTxType(replayCfg.TxType)
	if err != nil {
		return nil, err
	}
	payloadSize := replayCfg.PayloadSize
	if payloadSize <= 0 {
		payloadSize = 32
	}

	endpoints := replayEndpointsForConfig(cfg)
	plan := &txReplayPlan{Groups: make([]txReplayGroup, 0, replayCfg.GroupCount)}
	for groupIndex := 0; groupIndex < replayCfg.GroupCount; groupIndex++ {
		payload := deterministicReplayBytes("payload", groupIndex, payloadSize)
		to := common.BytesToAddress(deterministicReplayBytes("recipient", groupIndex, common.AddressLength))
		selectedEndpoints := selectReplayEndpoints(endpoints, replayCfg.EndpointsPerGroup)
		group := txReplayGroup{
			TxType:  txType,
			To:      to,
			Payload: payload,
		}
		group.Assignments = make([]txReplayAssignment, 0, len(selectedEndpoints))
		for assignmentIndex, endpoint := range selectedEndpoints {
			account := accounts[assignmentIndex]
			group.Assignments = append(group.Assignments, txReplayAssignment{
				Endpoint:      endpoint,
				EndpointIndex: assignmentIndex,
				Client:        replayClientLabel(multiNode, endpoint),
				Account:       account,
				Payload:       append([]byte(nil), payload...),
			})
		}
		group.ID = replayGroupID(groupIndex, txType, to, payload, selectedEndpoints)
		plan.Groups = append(plan.Groups, group)
	}

	return plan, nil
}

func replayEndpointsForConfig(cfg *TxFuzzConfig) []string {
	if cfg != nil && cfg.MultiNode != nil && len(cfg.MultiNode.RPCEndpoints) > 0 {
		return append([]string(nil), cfg.MultiNode.RPCEndpoints...)
	}
	if cfg != nil && cfg.RPCEndpoint != "" {
		return []string{cfg.RPCEndpoint}
	}
	return nil
}

func replayTxType(kind string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "legacy":
		return types.LegacyTxType, nil
	case "dynamic", "dynamic_fee", "1559", "eip1559":
		return types.DynamicFeeTxType, nil
	case "access_list", "2930", "eip2930":
		return types.AccessListTxType, nil
	default:
		return 0, fmt.Errorf("unsupported replay tx type %q", kind)
	}
}

func selectReplayEndpoints(endpoints []string, count int) []string {
	selected := make([]string, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, endpoints[i])
	}
	return selected
}

func replayClientLabel(multiNode *MultiNodeConfig, endpoint string) string {
	if multiNode != nil && multiNode.EndpointLabels != nil {
		if client := multiNode.EndpointLabels[endpoint]; client != "" {
			return client
		}
	}
	return endpoint
}

func replayGroupID(groupIndex int, txType uint8, to common.Address, payload []byte, endpoints []string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s|%x|%s", groupIndex, txType, to.Hex(), payload, strings.Join(endpoints, ","))))
	return fmt.Sprintf("replay-%02d-%s", groupIndex, hex.EncodeToString(sum[:6]))
}

func deterministicReplayBytes(prefix string, groupIndex int, size int) []byte {
	out := make([]byte, 0, size)
	for chunk := 0; len(out) < size; chunk++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", prefix, groupIndex, chunk)))
		out = append(out, sum[:]...)
	}
	return append([]byte(nil), out[:size]...)
}

func validateReplayFunding(cfg *TxFuzzConfig, accounts []config.Account, clients map[string]txRPCClient) error {
	if cfg == nil || cfg.Replay == nil || !cfg.Replay.Enabled {
		return nil
	}
	plan, err := buildTxReplayPlan(cfg.Replay, cfg.MultiNode, accounts)
	if err != nil {
		return err
	}
	if len(plan.Groups) == 0 {
		return fmt.Errorf("replay plan is empty")
	}
	ctx := context.Background()
	for _, assignment := range plan.Groups[0].Assignments {
		client := clients[assignment.Endpoint]
		if client == nil {
			return fmt.Errorf("missing replay client for endpoint %s", assignment.Endpoint)
		}
		address, err := replayAccountAddress(assignment.Account)
		if err != nil {
			return err
		}
		balance, err := client.BalanceAt(ctx, address, nil)
		if err != nil {
			return fmt.Errorf("failed to read replay account balance for %s on %s: %w", address.Hex(), assignment.Endpoint, err)
		}
		if balance == nil || balance.Sign() <= 0 {
			return fmt.Errorf("replay account %s is not funded on endpoint %s", address.Hex(), assignment.Endpoint)
		}
	}
	return nil
}

func replayAccountAddress(account config.Account) (common.Address, error) {
	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to derive replay account address: %w", err)
	}
	derived := crypto.PubkeyToAddress(privateKey.PublicKey)
	if account.Address != "" {
		configured := common.HexToAddress(account.Address)
		if configured != derived {
			return common.Address{}, fmt.Errorf("replay account address %s does not match private key", account.Address)
		}
	}
	return derived, nil
}
