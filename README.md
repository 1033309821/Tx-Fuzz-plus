# ECST

ECST is a Go-based Ethereum testing toolkit centered on two official entrypoints:

1. **Manual lane** — build protocol/message scenarios and send them to target nodes.
2. **Fuzz lane** — start the repository-owned fuzz/orchestration path.

The fuzz lane is still incomplete: it is the official startup surface, but not yet a fully hardened long-running engine.

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

That script (or your external env bootstrap) should produce an `endpoints.json` file. By default ECST now reads:

```text
~/ethpackage/endpoints.json
```

You can override that path with either:

- `environment.endpoints_file` in `config.yaml`
- environment variable `ECST_ENDPOINTS_FILE`

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
