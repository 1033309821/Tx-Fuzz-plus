package main

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"

	ethtest "github.com/1033309821/ECST/devp2p/protocol/eth"
	"github.com/1033309821/ECST/rpc"
	"github.com/1033309821/ECST/transaction"
	"github.com/1033309821/ECST/utils"
)

/*
=== Maximum Nonce Transaction Test POC ===
This POC tests sending transactions with MAXIMUM nonce values to verify how Ethereum clients
handle extreme nonce scenarios in their transaction pools.

🎯 PURPOSE:
- Test client behavior with nonce = math.MaxUint64 (18,446,744,073,709,551,615)
- Verify if clients properly handle queued transactions with extreme nonce values
- Check if clients reject, accept, or queue such transactions

🔧 IMPORTANT: Before running this POC, you MUST modify the following parameters:

1. 🎯 CRITICAL CONFIGURATION (MUST CHANGE):
   - enodeStr: Replace with your target Ethereum node's enode address
   - jwtSecret: Replace with your node's JWT secret (32 bytes hex string)
   - fromAccountPrivateKey: Replace with your account's private key (64 chars hex, no 0x prefix)
   - toAddress: Replace with recipient address
   - chainID: Replace with your network's chain ID
   - nodeName: Replace with your node's name (for identification)

2. 🔢 NONCE TESTING:
   - This POC uses nonce = math.MaxUint64 (maximum possible value)
   - Expected behavior: Transaction should be QUEUED (not pending)
   - This tests client's nonce validation and queuing logic

3. 🌐 NETWORK SETTINGS:
   - RPC URL: Automatically constructed as http://<node_ip>:8545
   - P2P Port: Automatically uses 8551 for authenticated communication
   - Make sure your node allows RPC and P2P connections

4. ⚙️ MODE SWITCH:
   - sendAndQuery = true: Send transaction + Query status (full test)
   - sendAndQuery = false: Only query existing transaction status

📋 USAGE:
1. Update all configuration parameters above
2. Ensure your account has sufficient ETH for gas fees
3. Run: go run maxNonce.go
4. Check the output for transaction status (should be QUEUED)

⚠️ WARNING: This test uses extreme nonce values that may cause unexpected behavior!
*/

func main() {
	// ========== Mode Switch ==========
	// Set to true: Send transaction + Query status
	// Set to false: Query specified transaction status only
	sendAndQuery := true

	// =============================

	// 🔧 CRITICAL: Update these parameters for your environment
	enodeStr := "enode://cf354e506a175e7e490e0ef174a6eb47ff1c96c0c55c89f3a2264e800c8cb6e80944a11b96f401396e48cddb7ab2f8ca405b6d27d77ca6d101936f5882e2e18d@172.16.0.12:30303" // ⚠️ CHANGE: Your node's enode address
	jwtSecret := "0xdc49981516e8e72b401a63e6405495a32dafc3939b5d6d83cc319ac0388bca1b"                                                                                        // ⚠️ CHANGE: Your node's JWT secret
	fromAccountPrivateKey := "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31"                                                                              // ⚠️ CHANGE: Your private key (64 chars, no 0x)
	toAddress := "0xE25583099BA105D9ec0A67f5Ae86D90e50036425"                                                                                                                // ⚠️ CHANGE: Recipient address
	chainID := big.NewInt(3151908)                                                                                                                                           // ⚠️ CHANGE: Your network's chain ID
	nodeName := "geth-lighthouse"                                                                                                                                            // ⚠️ CHANGE: Your node name

	// ========== Setup Phase ==========
	fmt.Println("🚀 Starting Maximum Nonce Transaction Test...")
	fmt.Println()

	// Parse enode (required for both modes)
	fmt.Print("🔗 Parsing enode address... ")
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		fmt.Printf("❌ Failed to parse enode: %v\n", err)
		return
	}
	fmt.Printf("✅ Success\n")
	fmt.Printf("📍 Node info: %s:%d\n", node.IP(), node.TCP())

	// Create RPC client for nonce retrieval
	fmt.Print("🌐 Creating RPC client... ")
	rpcClient := rpc.NewRPCClient(fmt.Sprintf("http://%s:8545", node.IP().String()))
	fmt.Printf("✅ Success\n")

	// Parse private key and get account address
	fmt.Print("🔑 Parsing private key... ")
	prik, err := crypto.HexToECDSA(fromAccountPrivateKey)
	if err != nil {
		fmt.Printf("❌ Failed to parse private key: %v\n", err)
		return
	}
	fromAddress := crypto.PubkeyToAddress(prik.PublicKey)
	fmt.Printf("✅ Success\n")
	fmt.Printf("📤 Sender address: %s\n", fromAddress.Hex())

	// 🔢 NONCE TESTING: Use maximum possible nonce value
	fmt.Print("🔢 Setting maximum nonce value... ")
	// nonce, err := rpcClient.NonceAt(context.Background(), fromAddress, nil)
	// if err != nil {
	// 	fmt.Printf("❌ Failed to get nonce: %v\n", err)
	// 	return
	// }
	nonce := uint64(math.MaxUint64 - 1) // Maximum possible nonce value
	fmt.Printf("✅ Success\n")
	fmt.Printf("📋 Maximum nonce: %d (0x%x)\n", nonce, nonce)
	fmt.Printf("⚠️  This is the maximum possible nonce value!\n")

	var txHash common.Hash

	// ========== Transaction Construction Phase ==========
	// Parse JWT secret for P2P authentication
	fmt.Print("🔐 Parsing JWT secret... ")
	jwtSecretBytes, err := utils.ParseJWTSecretFromHexString(jwtSecret)
	if err != nil {
		fmt.Printf("❌ Failed to parse JWT secret: %v\n", err)
		return
	}
	fmt.Printf("✅ Success\n")

	// Create Suite for P2P communication
	fmt.Print("🏗️ Creating ethtest.Suite... ")
	suite, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecretBytes[:]), nodeName)
	if err != nil {
		fmt.Printf("❌ Failed to create suite: %v\n", err)
		return
	}
	fmt.Printf("✅ Success\n")
	fmt.Printf("📋 Suite info: %s\n", suite.GetElName())

	// Get recipient address
	toAddr := common.HexToAddress(toAddress)
	fmt.Printf("📥 Recipient address: %s\n", toAddr.Hex())

	// ⛽ Gas Configuration (modify if needed)
	fmt.Printf("⛽ Gas configuration:\n")
	fmt.Printf("   - Gas Tip Cap: 3 Gwei\n")
	fmt.Printf("   - Gas Fee Cap: 30 Gwei\n")
	fmt.Printf("   - Gas Limit: 21000\n")
	fmt.Printf("💰 Transfer amount: 100 Wei\n")
	fmt.Printf("🔗 Chain ID: %d\n", chainID.Int64())
	fmt.Printf("🔢 Nonce: %d (MAXIMUM VALUE)\n", nonce)

	// Construct dynamic fee transaction
	fmt.Print("📝 Constructing dynamic fee transaction... ")
	txdata := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(3000000000),  // 3 Gwei
		GasFeeCap: big.NewInt(30000000000), // 30 Gwei
		Gas:       21000,
		To:        &toAddr,
		Value:     big.NewInt(100), // Transfer 100 Wei
	}
	innertx := types.NewTx(txdata)
	fmt.Printf("✅ Success\n")

	// Sign transaction
	fmt.Print("✍️ Signing transaction... ")
	tx, err := types.SignTx(innertx, types.NewLondonSigner(chainID), prik)
	if err != nil {
		fmt.Printf("❌ Failed to sign tx: %v\n", err)
		return
	}
	txHash = tx.Hash()
	fmt.Printf("✅ Success\n")
	fmt.Printf("📋 Transaction hash: %s\n", txHash.Hex())
	// ========== Execution Phase ==========
	if sendAndQuery {
		// Send transaction via P2P protocol
		fmt.Print("📤 Sending transaction via Suite... ")
		err = transaction.SendTxsWithoutRecv(suite, []*types.Transaction{tx})
		if err != nil {
			fmt.Printf("❌ Failed to send tx: %v\n", err)
			return
		}
		fmt.Printf("✅ Success\n")

		fmt.Println()
		fmt.Println("🎉 Maximum nonce transaction sent successfully!")
		fmt.Printf("🔗 Transaction hash: %s\n", txHash.Hex())
		fmt.Printf("📊 Transaction size: %d bytes\n", tx.Size())
		fmt.Printf("🔢 Nonce used: %d (MAXIMUM VALUE)\n", nonce)
		fmt.Println("==========================================")

		// Wait before querying transaction status
		fmt.Println()
		fmt.Println("⏳ Waiting 12 seconds before querying transaction status...")
		time.Sleep(12 * time.Second)

	} else {
		// ========== Query Only Mode ==========
		fmt.Println("🔍 Query only mode, skipping transaction sending")
		fmt.Printf("📋 Query transaction hash: %s\n", txHash.Hex())
		fmt.Printf("🔢 Nonce: %d (MAXIMUM VALUE)\n", nonce)
	}

	// ========== Status Query Phase ==========
	fmt.Println()
	fmt.Print("🔍 Querying transaction status... ")

	err = rpcClient.QueryDetailedTransactionStatus(txHash)
	if err != nil {
		fmt.Printf("❌ Detailed query failed: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Println("✅ Maximum nonce test completed!")
	fmt.Println("==========================================")
}
