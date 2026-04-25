package main

import (
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/1033309821/ECST/config"
	"github.com/1033309821/ECST/fuzzer"
	"github.com/1033309821/ECST/utils"
)

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	resolvedConfigPath, err := resolveConfigPath(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve config path: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(resolvedConfigPath)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	logger, err := utils.NewLogger(cfg.GetLogPath())
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("Starting Fuzz...")
	cfg.PrintConfig()

	if cfg.IsFuzzingEnabled() {
		logger.Info("Initializing fuzzing engine...")
		logger.Info("Target protocols: %v", cfg.Fuzzing.Protocols)
		logger.Info("Max iterations: %d", cfg.Fuzzing.MaxIterations)
	}

	if cfg.IsMonitoringEnabled() {
		logger.Info("Initializing monitoring system...")
		logger.Info("Metrics port: %d", cfg.Monitoring.MetricsPort)
		logger.Info("Log level: %s", cfg.Monitoring.LogLevel)
	}

	if cfg.IsTxFuzzingEnabled() {
		logger.Info("Transaction fuzzing is enabled")
		accounts := cfg.GetAccountss()
		if len(accounts) == 0 {
			logger.Warn("No accounts found for transaction fuzzing")
		} else {
			logger.Info("Found %d accounts for transaction fuzzing", len(accounts))

			fuzzClient, err := fuzzer.NewFuzzClient(*logger)
			if err != nil {
				logger.Error("Failed to create fuzz client: %v", err)
			} else {
				txCfg := cfg.GetTxFuzzingConfig()
				fuzzConfig := buildTxFuzzConfig(txCfg)
				if (txCfg.TxResultMappingEnabled || txCfg.Replay.Enabled) && fuzzConfig.TxResultLogPath == "" {
					fuzzConfig.TxResultLogPath = fuzzer.DefaultTxResultLogPath(cfg.GetOutputPath(), true)
				}

				err = fuzzClient.StartTxFuzzing(fuzzConfig, accounts)
				if err != nil {
					logger.Error("Failed to start transaction fuzzing: %v", err)
				} else {
					logger.Info("Transaction fuzzing started successfully")

					sigChan := make(chan os.Signal, 1)
					signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

					select {
					case <-sigChan:
						logger.Info("Received interrupt signal, stopping transaction fuzzing")
					case <-time.After(fuzzConfig.FuzzDuration):
						logger.Info("Transaction fuzzing duration completed")
					}

					if summary := fuzzClient.StopTxFuzzing(); summary != nil {
						summaryPath := txFuzzSummaryPath(cfg.GetOutputPath(), summary.FinishedAt)
						if err := fuzzer.WriteRunSummaryJSON(summaryPath, *summary); err != nil {
							logger.Error("Failed to write transaction fuzzing summary: %v", err)
						} else {
							logger.Info("Transaction fuzzing summary written: %s", summaryPath)
						}
					}
					logger.Info("Transaction fuzzing stopped")
				}
			}
		}
	}

	logger.Info("Initializing P2P network...")
	logger.Info("Listen port: %d", cfg.P2P.ListenPort)
	logger.Info("Max peers: %d", cfg.P2P.MaxPeers)
	logger.Info("Bootstrap nodes: %d configured", len(cfg.P2P.BootstrapNodes))

	fuzzClient, err := fuzzer.NewFuzzClient(*logger)
	if err != nil {
		logger.Fatal("Failed to create fuzz client: %v", err)
	}
	fuzzClient.Start()

	logger.Info("Creating output directories...")

	outputPath := cfg.GetOutputPath()
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		logger.Fatal("Failed to create output directory '%s': %v", outputPath, err)
	}
	logger.Info("Output directory created/verified: %s", outputPath)

	reportPath := cfg.GetLogPath()
	if err := os.MkdirAll(reportPath, 0755); err != nil {
		logger.Fatal("Failed to create report directory '%s': %v", reportPath, err)
	}
	logger.Info("Report directory created/verified: %s", reportPath)
}

func buildTxFuzzConfig(txCfg config.TxFuzzingConfig) *fuzzer.TxFuzzConfig {
	rpcEndpoints := txCfg.RPCEndpoints
	if len(rpcEndpoints) == 0 && txCfg.RPCEndpoint != "" {
		rpcEndpoints = []string{txCfg.RPCEndpoint}
	}

	rpcEndpoint := txCfg.RPCEndpoint
	if len(rpcEndpoints) > 0 {
		rpcEndpoint = rpcEndpoints[0]
	}

	fuzzConfig := &fuzzer.TxFuzzConfig{
		RPCEndpoint:          rpcEndpoint,
		ChainID:              txCfg.ChainID,
		MaxGasPrice:          big.NewInt(txCfg.MaxGasPrice),
		MaxGasLimit:          txCfg.MaxGasLimit,
		TxPerSecond:          txCfg.TxPerSecond,
		FuzzDuration:         time.Duration(txCfg.FuzzDurationSec) * time.Second,
		Seed:                 txCfg.Seed,
		TxResultLogPath:      txCfg.TxResultLogPath,
		ReceiptDrainDuration: time.Duration(txCfg.ReceiptDrainDurationSec) * time.Second,
		EnableTracking:       txCfg.EnableTracking || txCfg.TxResultMappingEnabled,
		ConfirmBlocks:        txCfg.ConfirmBlocks,
	}
	if len(rpcEndpoints) > 1 {
		fuzzConfig.MultiNode = buildMultiNodeConfig(rpcEndpoints, txCfg.EndpointLabels)
	}
	if txCfg.Replay.Enabled {
		fuzzConfig.Replay = &fuzzer.TxReplayConfig{
			Enabled:           txCfg.Replay.Enabled,
			GroupCount:        txCfg.Replay.GroupCount,
			EndpointsPerGroup: txCfg.Replay.EndpointsPerGroup,
			TxType:            txCfg.Replay.TxType,
			PayloadSize:       txCfg.Replay.PayloadSize,
		}
		fuzzConfig.EnableTracking = true
	}

	return fuzzConfig
}

func buildMultiNodeConfig(rpcEndpoints []string, endpointLabels map[string]string) *fuzzer.MultiNodeConfig {
	loadDistribution := make(map[string]float64, len(rpcEndpoints))
	weight := 1.0 / float64(len(rpcEndpoints))
	for _, endpoint := range rpcEndpoints {
		loadDistribution[endpoint] = weight
	}

	return &fuzzer.MultiNodeConfig{
		RPCEndpoints:        append([]string(nil), rpcEndpoints...),
		LoadDistribution:    loadDistribution,
		FailoverEnabled:     true,
		HealthCheckInterval: 30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          time.Second,
		EndpointLabels:      cloneStringMap(endpointLabels),
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func txFuzzSummaryPath(outputPath string, finishedAt time.Time) string {
	return filepath.Join(outputPath, fmt.Sprintf("tx_fuzz_summary_%s.json", finishedAt.Format("20060102_150405")))
}

func resolveConfigPath(path string) (string, error) {
	candidates := []string{path}
	if path == "config.yaml" {
		candidates = append(candidates, filepath.Join("..", "..", "config.yaml"))
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("config file %q not found", path)
}
