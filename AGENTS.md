# Repository Guidelines

## Project Structure & Module Organization
ECST is a Go-based Ethereum storage and transaction-fuzzing toolkit. Core packages live at the repository root: `account/`, `blob/`, `config/`, `devp2p/`, `ethclient/`, `fuzzer/`, `mutation/`, `rpc/`, `transaction/`, and `utils/`. Scenario runners and protocol checks are under `testing/`, `stress_test/`, `poc/`, and `fuzz_and_exception/`. Operational scripts live in `scripts/`; reusable config examples belong in `templates/`. Official entry points live under `cmd/`, with `cmd/manual` for manual scenario execution and `cmd/fuzz` for fuzz startup/orchestration.

## Build, Test, and Development Commands
- `go build ./...` — compile all packages and catch cross-package build breaks.
- `go test ./...` — run the Go test suite (`testing` + `testify`).
- `go build -o manual ./cmd/manual && ./manual -config ./config.yaml -mode single` — build and run the manual test runner.
- `go build -o fuzz ./cmd/fuzz && ./fuzz ./config.yaml` — build and run the official fuzz startup/orchestration entry.
- `./scripts/run_ethereum_network.sh -c <ethereum-package.yaml>` — bootstrap the local multi-client Ethereum network used by integration workflows.
- `cd stress_test && ./run_stress_test.sh` — execute the stress-test harness.

## Coding Style & Naming Conventions
Follow standard Go formatting with `gofmt` before committing; keep imports grouped by `gofmt` output. Use lowercase package names, `PascalCase` for exported identifiers, and `camelCase` for locals. Keep files focused on one area of responsibility and prefer extending existing packages over adding new top-level directories. YAML/config examples should mirror existing lowercase, underscore-separated keys.

## Testing Guidelines
Write tests in `*_test.go` files next to the package they cover. Use Go’s `testing` package with `github.com/stretchr/testify` for assertions, matching patterns like `utils/logger_test.go`. Add or update tests for every behavior change; for network-dependent cases, document prerequisites and keep deterministic unit coverage separate from environment-heavy flows in `testing/` or `poc/`.

## Commit & Pull Request Guidelines
Recent history uses short imperative subjects (for example, `update import`), but contributors should be more descriptive. Start each commit with the reason for the change, then include Lore trailers such as `Constraint:`, `Confidence:`, `Scope-risk:`, `Tested:`, and `Not-tested:`. PRs should summarize the affected module, list verification commands run, link related issues, and note required config, RPC endpoints, or testnet assumptions.

## Security & Configuration Tips
Do not commit live JWT secrets, private keys, or RPC credentials. Keep local overrides in untracked config files, use `templates/` for shareable examples, and sanitize logs or reports before attaching them to reviews.
