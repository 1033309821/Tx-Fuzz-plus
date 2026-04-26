# ECST

ECST is a Go-based Ethereum testing toolkit centered on two official entrypoints:

1. **Manual lane** — build protocol/message scenarios and send them to target nodes.
2. **Fuzz lane** — start the repository-owned fuzz/orchestration path.

The fuzz lane is still incomplete: it is the official startup surface, but not yet a fully hardened long-running engine.

## Validation terminology

ECST uses the following validation terms consistently:

- **Unit test** — isolated package-level verification without relying on a running external network.
- **Integration test** — verification across multiple ECST components or external services.
- **Devnet** — a real running multi-client Ethereum development network, typically produced by Kurtosis plus `ethereum-package`.
- **Smoke run / smoke test** — a small, fast, low-cost validation run that checks whether the main path works at all.
- **Devnet smoke run** — a smoke run executed against a real running devnet, not a mocked network.
- **Long-running fuzz run** — a broader fuzz campaign intended for sustained exploration rather than quick validation.

In other words, **smoke** describes the scope and purpose of a run, while **devnet** describes the environment where the run is executed.

## Recent updates

Recent committed work plus the latest replay-lane update add the following capabilities:

1. **Runtime topology now comes from `endpoints.json`**
   - ECST reads execution/consensus endpoint data from an external endpoints file instead of trusting stale YAML topology.
   - `tx_fuzz.rpc_endpoint` / `tx_fuzz.rpc_endpoints`, `p2p.bootstrap_nodes`, and `p2p.node_names` are overridden by the runtime endpoints file.

2. **Transaction fuzzing now has explicit nonce tracking**
   - Sender nonce progression is tracked to reduce avoidable send instability during multi-attempt fuzzing.

3. **Tx fuzzing now emits an auditable evidence pipeline**
   - Per-attempt logs
   - Expectation logs
   - Anomaly logs
   - Anomaly summary
   - Final run summary

4. **Endpoint coverage is visible in artifacts**
   - Attempt/result artifacts now show which endpoint handled each transaction and how the run covered configured nodes.

5. **Deterministic replay lane for cross-node comparison**
   - ECST can now generate deterministic replay groups across multiple execution clients.
   - Replay groups have first-class `replay_group_id`.
   - Replay completeness is tracked.
   - Incomplete groups are auditable but excluded from disagreement classification.
   - Replay disagreement detection keys on `replay_group_id`, not incidental payload collisions.
   - Typed replay noise annotations are emitted for preflight-only client-specific noise.

6. **Replay startup validates sender safety**
   - Replay sender identity is derived from the private key.
   - Distinct replay senders are enforced.
   - Replay accounts must be funded on the target endpoints before startup proceeds.

## Repository layout

```text
ECST/
├── cmd/manual/        # Official manual test runner
├── cmd/fuzz/          # Official fuzz startup/orchestration entry
├── testing/           # Manual scenario/test-mode implementations
├── fuzzer/            # Fuzzing support code
├── transaction/       # Transaction construction and sending helpers
├── devp2p/            # P2P/protocol utilities
├── stress_test/       # Auxiliary stress examples and scripts
├── scripts/           # Shell helpers and verification utilities
├── templates/         # Example YAML configs
└── config.yaml        # Default repository config
```

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

### Deterministic replay run

To run the new replay lane manually, enable `tx_fuzz.replay` in a config file and point `environment.endpoints_file` at a live runtime endpoints file.

If you are rebuilding a devnet from the repository root with the bundled reset script, a practical sequence is:

```bash
./scripts/reset-devnet.sh -n eth5node -o output/endpoints.json ../ethpackage/network_params.yaml
```

and then:

```yaml
environment:
  endpoints_file: ./output/endpoints.json
```

Example:

```yaml
environment:
  endpoints_file: ./output/endpoints.json

output:
  directory: output/replay_manual

tx_fuzz:
  enabled: true
  chain_id: 3151908
  max_gas_price: 20000000000
  max_gas_limit: 8000000
  tx_per_second: 1
  fuzz_duration_sec: 25
  seed: 424242

  tx_result_mapping_enabled: true
  tx_result_log_path: output/replay_manual/tx_attempts_replay.jsonl
  receipt_drain_duration_sec: 8
  enable_tracking: true
  confirm_blocks: 0

  replay:
    enabled: true
    group_count: 2
    endpoints_per_group: 5
    tx_type: dynamic
    payload_size: 48
```

Run it:

```bash
go build -o fuzz ./cmd/fuzz
./fuzz replay.yaml
```

### Replay config fields

`tx_fuzz.replay` currently supports:

- `enabled`
- `group_count`
- `endpoints_per_group`
- `tx_type`
  - `legacy`
  - `dynamic`
  - `access_list`
- `payload_size`

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

If `tx_result_log_path` is explicitly set, the sibling artifact names are derived from that base path automatically.

Useful checks:

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

### Where replay transaction parameters are constructed

Replay-specific transaction content is currently assembled in code, not fully exposed as YAML fields.

- **Replay group planning**: `fuzzer/tx_replay_plan.go`
  - group id
  - endpoint-to-sender assignment
  - fixed recipient
  - fixed payload bytes

- **Replay transaction assembly**: `fuzzer/tx_fuzzer.go`
  - `buildReplayTransaction(...)`
  - value
  - gas limit
  - dynamic fee / legacy fee fields
  - signing

If you need to make replay `to`, `value`, payload contents, or fee knobs fully configurable, this is the code path to extend.

## Auxiliary tooling

- `./stress_test/run_stress_test.sh` — stress-oriented helper flow built around `stress_test/tx_fuzz_example.go`
- `./scripts/verify_blob_test.sh blob-single` — run and verify blob tests through the manual entrypoint
- `poc/` — one-off proof-of-concept experiments such as max-nonce checks

These are useful, but they are **not** additional formal entrypoints.

## Troubleshooting

- **`connection refused`** — confirm RPC endpoints are reachable and the testnet is up.
- **`insufficient funds for gas`** — fund sender accounts or lower gas settings.
- **Low observed TPS** — reduce retries/delay, add more RPC endpoints, or lower target TPS.
- **Fuzz exits early** — treat that as a current limitation of the fuzz lane rather than expected long-run stability.

## License

MIT. See [LICENSE](LICENSE).
