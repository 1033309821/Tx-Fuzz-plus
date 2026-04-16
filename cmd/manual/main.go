package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/1033309821/ECST/config"
	manualtesting "github.com/1033309821/ECST/testing"
	"github.com/1033309821/ECST/utils"
)

const manualVersion = "manual-entrypoint-v1"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the config file")
	mode := flag.String("mode", "", "override test.mode from the config file")
	list := flag.Bool("list", false, "list available manual test modes")
	version := flag.Bool("version", false, "print version information")
	flag.Parse()

	if *version {
		fmt.Println(manualVersion)
		return
	}

	resolvedConfigPath, err := resolveConfigPath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve config path: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *mode != "" {
		cfg.Test.Mode = *mode
	}

	if *list {
		manualtesting.ListAvailableTests()
		return
	}

	if err := prepareManualPaths(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to prepare manual paths: %v\n", err)
		os.Exit(1)
	}

	testMode := cfg.GetTestMode()
	if testMode == "" {
		fmt.Fprintln(os.Stderr, "test.mode is empty; use -mode or set test.mode in the config")
		os.Exit(1)
	}

	runner, ok := manualtesting.GetRunner(testMode)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown test mode %q\n\n", testMode)
		manualtesting.ListAvailableTests()
		os.Exit(1)
	}

	fmt.Printf("Using config: %s\n", resolvedConfigPath)
	fmt.Printf("Selected mode: %s\n", testMode)

	if err := runner.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "manual run failed: %v\n", err)
		os.Exit(1)
	}
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

func prepareManualPaths(cfg *config.Config) error {
	for _, dir := range []string{cfg.GetLogPath(), cfg.GetOutputPath()} {
		if dir == "" {
			continue
		}
		if err := utils.EnsureDir(dir); err != nil {
			return err
		}
	}

	if cfg.Paths.TxHashes != "" {
		parent := filepath.Dir(cfg.Paths.TxHashes)
		if parent != "." && parent != "" {
			if err := utils.EnsureDir(parent); err != nil {
				return err
			}
		}
	}

	return nil
}
