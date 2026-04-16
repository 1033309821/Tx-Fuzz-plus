package testing

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/1033309821/ECST/config"
	ethtest "github.com/1033309821/ECST/devp2p/protocol/eth"
	"github.com/1033309821/ECST/transaction"
)

func newSuiteForNode(cfg *config.Config, nodeIndex int) (*ethtest.Suite, *enode.Node, error) {
	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, cfg.GetEngineRPCAddress(nodeIndex), common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create suite: %v", err)
	}

	return s, node, nil
}
