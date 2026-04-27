# ECST

ECST is a Go-based Ethereum testing toolkit centered on two official entrypoints:

1. **Manual lane** — build protocol/message scenarios and send them to target nodes.
2. **Fuzz lane** — start the repository-owned fuzz/orchestration path.

The fuzz lane is still incomplete: it is the official startup surface, but not yet a fully hardened long-running engine.

## ENV
- **Devnet** — a real running multi-client Ethereum development network, typically produced by Kurtosis plus `ethereum-package`.

## Prerequisites

- Go 1.24+
- Docker / Docker Compose for local multi-client testnets
- Git

## Bring up a local Ethereum testnet

We use [`ethpandaops/ethereum-package`](https://github.com/ethpandaops/ethereum-package).

```bash
./scripts/run_ethereum_network.sh -c <ethereum-package.yaml>
```

For full devnet reset / rebuild flows, ECST now also includes:

```bash
./scripts/reset-devnet.sh [OPTIONS] [config_file]
```

Examples:

```bash
# rebuild a devnet from the repository root
./scripts/reset-devnet.sh ../ethpackage/network_params.yaml

# rebuild and write endpoints to a project-local path
./scripts/reset-devnet.sh -n eth5node -o output/endpoints.json ../ethpackage/network_params.yaml
```

`scripts/reset-devnet.sh` resolves **relative output paths against the current working directory**, not against the script directory.  
For example, when run from the repository root:

```bash
./scripts/reset-devnet.sh -o output/endpoints.json ../ethpackage/network_params.yaml
```

the generated endpoints file is written to:

```text
./output/endpoints.json
```

not to `./scripts/output/endpoints.json`.

That script (or your external env bootstrap) should produce an `endpoints.json` file. By default ECST now reads:

```text
~/ethpackage/endpoints.json
```

You can override that path with either:

- `environment.endpoints_file` in `config.yaml`
- environment variable `ECST_ENDPOINTS_FILE`

If you use `scripts/reset-devnet.sh` to write a project-local endpoints file such as `./output/endpoints.json`, make sure your config points to that same path:

```yaml
environment:
  endpoints_file: ./output/endpoints.json
```

This file is the **source of truth** for dynamic environment data. It **strictly overrides**:

- `tx_fuzz.rpc_endpoint` / `tx_fuzz.rpc_endpoints`
- `p2p.bootstrap_nodes`
- `p2p.node_names`

If the endpoints file is missing, malformed, or incomplete, ECST fails fast instead of falling back to stale YAML values.

## Official entrypoints

### 1) Manual entrypoint

Build and run the manual runner from the repository root:

```bash
go build -o manual ./cmd/manual
./manual -config ./config.yaml -mode single
./manual -list
```

Available modes currently include:

- `single`
- `multi`
- `test-soft-limit`
- `test-soft-limit-single`
- `test-soft-limit-report`
- `oneTransaction`
- `largeTransactions`
- `blob-single`
- `blob-multi`

Use `templates/manual_config.yaml` as a starting point if you want a manual-focused config file.

### 2) Fuzz entrypoint

Build and run the repository-owned fuzz startup/orchestration lane:

```bash
go build -o fuzz ./cmd/fuzz
./fuzz ./config.yaml
```

Current limitation: this lane starts the in-repo fuzz path honestly, but the fuzz engine is not yet fully stable, long-running, or analysis-complete.

## Latest fuzz usage

### Standard fuzz run

```bash
go build -o fuzz ./cmd/fuzz
./fuzz ./config.yaml
```

Other important tx fuzz controls used by replay runs:

- `tx_result_mapping_enabled`
- `tx_result_log_path`
- `receipt_drain_duration_sec`
- `enable_tracking`
- `confirm_blocks`
- `seed`
- `max_gas_price`
- `max_gas_limit`

### Replay artifacts

A replay run writes:

- `tx_attempts_*.jsonl`
- `tx_expectations_*.jsonl`
- `tx_anomalies_*.jsonl`
- `tx_anomaly_summary_*.json`
- `tx_fuzz_summary_*.json`

```bash
# run summary
cat output/replay_manual/tx_fuzz_summary_*.json

# replay completeness status
grep tx_replay_group_status_recorded output/replay_manual/tx_expectations_*.jsonl

# incomplete groups
grep replay_group_incomplete output/replay_manual/tx_anomalies_*.jsonl

# actual cross-node disagreements
grep cross_node_outcome_disagreement output/replay_manual/tx_anomalies_*.jsonl
```
## License

MIT. See [LICENSE](LICENSE).
