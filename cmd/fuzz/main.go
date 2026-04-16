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
				fuzzConfig := &fuzzer.TxFuzzConfig{
					RPCEndpoint:  txCfg.RPCEndpoint,
					ChainID:      txCfg.ChainID,
					MaxGasPrice:  big.NewInt(txCfg.MaxGasPrice),
					MaxGasLimit:  txCfg.MaxGasLimit,
					TxPerSecond:  txCfg.TxPerSecond,
					FuzzDuration: time.Duration(txCfg.FuzzDurationSec) * time.Second,
					Seed:         txCfg.Seed,
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

					fuzzClient.StopTxFuzzing()
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
