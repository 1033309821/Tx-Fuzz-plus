package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0644))

	return path
}

func TestLoadConfigAppliesDefaultsAndGetters(t *testing.T) {
	endpointsPath := writeConfigFile(t, `{
  "execution_nodes": [
    {
      "index": 1,
      "el_client": "geth",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:40101",
      "ws": "127.0.0.1:40102",
      "engine_rpc": "127.0.0.1:40103",
      "enode": "enode://node-a@127.0.0.1:30303"
    },
    {
      "index": 2,
      "el_client": "reth",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:40201",
      "ws": "127.0.0.1:40202",
      "engine_rpc": "127.0.0.1:40203",
      "enode": "enode://node-b@127.0.0.2:30303"
    }
  ],
  "consensus_nodes": [
    {
      "index": 1,
      "cl_client": "lighthouse",
      "el_client": "geth",
      "beacon": "http://127.0.0.1:40301"
    },
    {
      "index": 2,
      "cl_client": "lighthouse",
      "el_client": "reth",
      "beacon": "http://127.0.0.1:40302"
    }
  ]
}`)
	path := writeConfigFile(t, `
server:
  host: "127.0.0.1"
  port: 9000
  timeout: 15
environment:
  endpoints_file: "`+endpointsPath+`"
mode: "manual"
p2p:
  max_peers: 5
  listen_port: 30303
  bootstrap_nodes: ["enode://node-a", "enode://node-b"]
  jwt_secret: "secret"
  node_names: ["node-a", "node-b"]
fuzzing:
  enabled: true
  max_iterations: 10
  mutation_rate: 0.2
  seed: 7
  protocols: ["eth"]
tx_fuzz:
  enabled: true
  rpc_endpoint: "http://127.0.0.1:8545"
  chain_id: 3151908
  max_gas_price: 100
  max_gas_limit: 21000
  tx_per_second: 3
  fuzz_duration_sec: 60
  seed: 99
  use_accounts: true
monitoring:
  enabled: true
  log_level: "info"
  metrics_port: 9090
  report_interval: 30
output:
  directory: "./output"
  format: "json"
  compress: false
log:
  directory: "./logs"
  template: "default"
  auto_generate: true
  include_details: true
paths:
  tx_hashes: "./txhashes.txt"
  tx_hashes_ext: "./txhashes_ext.txt"
test:
  mode: "single"
accounts:
  - address: "0x1"
    private_key: "key1"
`)

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:9000", cfg.GetServerAddress())
	assert.Equal(t, "./output", cfg.GetOutputPath())
	assert.Equal(t, "./logs", cfg.GetLogPath())
	assert.Equal(t, "single", cfg.GetTestMode())
	assert.True(t, cfg.IsFuzzingEnabled())
	assert.True(t, cfg.IsTxFuzzingEnabled())
	assert.True(t, cfg.IsMonitoringEnabled())
	assert.Equal(t, 2, cfg.GetNodeCount())
	assert.Equal(t, "reth-lighthouse", cfg.GetNodeName(1))
	assert.Equal(t, "", cfg.GetNodeName(9))
	assert.Len(t, cfg.GetAccountss(), 1)
	assert.Equal(t, int64(3151908), cfg.ChainID.Int64())
	assert.Equal(t, "3000000000", cfg.DefaultGasTipCap.String())
	assert.Equal(t, "30000000000", cfg.DefaultGasFeeCap.String())
	txCfg := cfg.GetTxFuzzingConfig()
	assert.Equal(t, cfg.TxFuzzing.RPCEndpoints, txCfg.RPCEndpoints)
	assert.Equal(t, "geth", txCfg.EndpointLabels[cfg.TxFuzzing.RPCEndpoints[0]])
	assert.Equal(t, "geth", txCfg.EndpointLabels[cfg.GetRPCURL(0)])
}

func TestLoadConfigRejectsInvalidGasCaps(t *testing.T) {
	path := writeConfigFile(t, `
server:
  host: "localhost"
  port: 8080
  timeout: 30
default_gas_tip_cap: "not-a-number"
`)

	cfg, err := LoadConfig(path)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "invalid default_gas_tip_cap")
}

func TestLoadConfigOverridesEnvironmentFromEndpointsFile(t *testing.T) {
	endpointsPath := writeConfigFile(t, `{
  "execution_nodes": [
    {
      "index": 1,
      "el_client": "geth",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:41001",
      "ws": "127.0.0.1:41002",
      "engine_rpc": "127.0.0.1:41003",
      "enode": "enode://abc@172.16.0.10:30303"
    },
    {
      "index": 2,
      "el_client": "reth",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:42001",
      "ws": "127.0.0.1:42002",
      "engine_rpc": "127.0.0.1:42003",
      "enode": "enode://def@172.16.0.11:30303"
    }
  ],
  "consensus_nodes": [
    {
      "index": 1,
      "cl_client": "lighthouse",
      "el_client": "geth",
      "beacon": "http://127.0.0.1:43001"
    },
    {
      "index": 2,
      "cl_client": "lighthouse",
      "el_client": "reth",
      "beacon": "http://127.0.0.1:43002"
    }
  ]
}`)

	configPath := writeConfigFile(t, `
server:
  host: "127.0.0.1"
  port: 9000
  timeout: 15
environment:
  endpoints_file: "`+endpointsPath+`"
mode: "fuzz"
p2p:
  max_peers: 5
  listen_port: 30303
  bootstrap_nodes: ["enode://stale@127.0.0.1:30303"]
  jwt_secret: "secret"
  node_names: ["stale-node"]
tx_fuzz:
  enabled: true
  rpc_endpoint: "http://stale:8545"
  chain_id: 3151908
  max_gas_price: 100
  max_gas_limit: 21000
  tx_per_second: 3
  fuzz_duration_sec: 60
  seed: 99
monitoring:
  enabled: false
output:
  directory: "./output"
log:
  directory: "./logs"
paths:
  tx_hashes: "./txhashes.txt"
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"enode://abc@172.16.0.10:30303",
		"enode://def@172.16.0.11:30303",
	}, cfg.P2P.BootstrapNodes)
	assert.Equal(t, []string{"geth-lighthouse", "reth-lighthouse"}, cfg.P2P.NodeNames)
	assert.Equal(t, "http://127.0.0.1:41001", cfg.TxFuzzing.RPCEndpoint)
	assert.Equal(t, []string{"http://127.0.0.1:41001", "http://127.0.0.1:42001"}, cfg.TxFuzzing.RPCEndpoints)
	assert.Equal(t, "http://127.0.0.1:42001", cfg.GetRPCURL(1))
	assert.Equal(t, "127.0.0.1:41003", cfg.GetEngineRPCAddress(0))
	assert.Equal(t, "http://127.0.0.1:43002", cfg.GetBeaconURL(1))
	assert.Equal(t, endpointsPath, cfg.Environment.EndpointsFile)
}

func TestLoadConfigEnvVarOverridesEndpointsFilePath(t *testing.T) {
	staleEndpointsPath := writeConfigFile(t, `{"execution_nodes":[],"consensus_nodes":[]}`)
	liveEndpointsPath := writeConfigFile(t, `{
  "execution_nodes": [
    {
      "index": 1,
      "el_client": "besu",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:51001",
      "ws": "127.0.0.1:51002",
      "engine_rpc": "127.0.0.1:51003",
      "enode": "enode://xyz@172.16.0.20:30303"
    }
  ],
  "consensus_nodes": [
    {
      "index": 1,
      "cl_client": "lighthouse",
      "el_client": "besu",
      "beacon": "http://127.0.0.1:53001"
    }
  ]
}`)
	t.Setenv("ECST_ENDPOINTS_FILE", liveEndpointsPath)

	configPath := writeConfigFile(t, `
server:
  host: "localhost"
  port: 8080
  timeout: 30
environment:
  endpoints_file: "`+staleEndpointsPath+`"
p2p:
  jwt_secret: "secret"
tx_fuzz:
  enabled: true
  chain_id: 1
  max_gas_price: 1
  max_gas_limit: 21000
  tx_per_second: 1
  fuzz_duration_sec: 1
output:
  directory: "./output"
log:
  directory: "./logs"
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"besu-lighthouse"}, cfg.P2P.NodeNames)
	assert.Equal(t, "http://127.0.0.1:51001", cfg.GetRPCURL(0))
}

func TestLoadConfigFailsWhenEndpointsFileMissing(t *testing.T) {
	configPath := writeConfigFile(t, `
server:
  host: "localhost"
  port: 8080
  timeout: 30
environment:
  endpoints_file: "/tmp/does-not-exist-endpoints.json"
p2p:
  jwt_secret: "secret"
output:
  directory: "./output"
log:
  directory: "./logs"
`)

	cfg, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read endpoints file")
}

func TestLoadConfigFailsWhenEndpointsFileIncomplete(t *testing.T) {
	endpointsPath := writeConfigFile(t, `{
  "execution_nodes": [
    {
      "index": 1,
      "el_client": "geth",
      "cl_client": "lighthouse",
      "rpc": "127.0.0.1:41001"
    }
  ]
}`)

	configPath := writeConfigFile(t, `
server:
  host: "localhost"
  port: 8080
  timeout: 30
environment:
  endpoints_file: "`+endpointsPath+`"
p2p:
  jwt_secret: "secret"
output:
  directory: "./output"
log:
  directory: "./logs"
`)

	cfg, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "invalid execution node")
}
