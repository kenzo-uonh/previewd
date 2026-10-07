# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## Architecture & Tech Stack

*   **Core Daemon:** Statically compiled Go 1.27+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
*   **Orchestration:** Docker API (`github.com/moby/moby/client`) for isolated bridge networks and container lifecycles.
*   **Ingress & Routing:** Traefik reverse proxy bound to the local Docker socket, configured dynamically via runtime container labels.
*   **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery.
*   **Security Context:** Secrets are injected strictly into memory from a local vault file and never written to disk.

## Codebase Structure

```text
.
├── cmd/
│   └── previewd/
│       └── main.go                # Single binary entry point initializing config, store, and HTTP server.
├── deployments/
│   ├── docker-compose.yml         # Standalone installation for agent and Traefik reverse proxy.
│   └── traefik.yml                # Base Traefik static configuration.
├── internal/
│   ├── api/
│   │   ├── handlers.go            # Webhook receivers for GitHub PR events.
│   │   └── middleware.go          # Request authentication and payload signature verification.
│   ├── config/
│   │   └── config.go              # Air-gapped environment configuration loading.
│   ├── orchestrator/
│   │   ├── docker.go              # Docker Driver implementation for the MVP.
│   │   ├── engine.go              # Interface defining the Driver (Docker/Kubernetes).
│   │   ├── environment.go         # EaaS lifecycle logic (Clone, Start, Stop, Destroy).
│   │   └── queue.go               # Bounded worker pool for deployment concurrency.
│   ├── proxy/
│   │   └── labels.go              # Dynamic routing configuration and Docker label assignment.
│   ├── secrets/
│   │   └── injector.go            # In-memory secret mapping and container injection.
│   ├── store/
│   │   ├── db.go                  # modernc.org/sqlite connection pool (No CGO).
│   │   └── queries.go             # Agent persistence for active environment states.
│   └── vcs/
│       ├── clone.go               # Secure repository cloning execution.
│       └── github.go              # GitHub webhook payload schemas.
├── scripts/
│   ├── build.sh                   # Static binary compilation script.
│   └── verify-e2e.sh              # Local, air-gapped end-to-end integration validation.
├── Makefile                       # Build, test, and infrastructure automation targets.
├── go.mod                         # Go module dependencies.
└── go.sum                         # Go module checksums.

```

## Development & Execution

The project uses a strict `Makefile` for all build and verification pipelines to enforce simplicity and consistency.

### Core Commands

* **Initialize Infrastructure:** Start the local Traefik proxy on port 8081 and create the `previewd-proxy` bridge network.


```bash
make docker-up
```


* **Build the Agent:** Compile the static, CGO-free binary with version metadata injected via ldflags into the `bin/` directory.


```bash
make build
```


* **Run Locally:** Execute the `previewd` daemon.


```bash
make run
```


* **Execute End-to-End Tests:** Run the air-gapped validation suite using a locally generated bare Git repository to verify the complete environment lifecycle.


```bash
make e2e
```


* **Deterministic Gate:** Module tidiness and hashes, formatting, vet, golangci-lint, gosec, govulncheck (fails on reachable findings), `airgap-check`, unit tests. Packages whose tests import rapid run with a fixed seed (`RAPID_SEED`, default 1; 0 is refused because rapid treats it as random), so every run generates the same inputs. Air-gapped: `DEPS_GATE=vendor-check` checks `vendor/` instead of the module cache, and `GOVULNDB=file:///path/to/vulndb` points govulncheck at an offline database mirror.


```bash
make check
make check DEPS_GATE=vendor-check GOVULNDB=file:///opt/vulndb
make check RAPID_SEED=<seed printed by a failing make verify>
```


* **Dependency Denylist:** Fails if `./cmd/previewd` links an OpenTelemetry SDK or exporter, OTLP protobufs, gRPC, an AWS/GCP/Azure SDK, or the deprecated `github.com/docker/docker` module. The Docker client is `github.com/moby/moby/client`, which links the OpenTelemetry *API* packages and `otelhttp`. With no SDK in the binary these are no-ops: no span, metric or log record leaves the process. The previous `docker/docker` dependency listed `otlptracehttp` in `go.mod` without linking it; after the migration it is gone from the module graph. No exception to the no-telemetry rule is needed.


```bash
make airgap-check
```


* **Deep Verification:** Property-based tests (`pgregory.net/rapid`, `-rapid.checks=$(RAPID_CHECKS)`, default 10000) in every package whose tests import rapid, with a random seed on each run, then every native fuzz target (`go test -fuzz`, `FUZZTIME` per target, default 60s). Fails if it finds no rapid package or no fuzz target.


```bash
make verify
make verify RAPID_CHECKS=100000 FUZZTIME=10m
```


* **Air-Gapped Execution:** `scripts/airgap-exec.sh <cmd>` runs a command in fresh unprivileged user, network and mount namespaces. Only loopback exists, and `/run` is hidden behind an empty tmpfs, because a network namespace does not isolate `/run/docker.sock` and a test could ask the host daemon to reach the network. Before running the command, the script checks that no interface, route, outbound connection or daemon socket is reachable, and refuses to run otherwise.


### CI (`.github/workflows/ci.yml`)

| Stage | Job         | What it enforces                                                                                                                                                                                                                                                                                                                                                                                     |
|-------|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1     | `semgrep`   | Project rules in `.semgrep/previewd-rules.yaml`: no `container.Config.Env`, secret mounts memory-backed and read-only, no `context.Background()`/`TODO()` in orchestrator/store. The rule self-test (`semgrep --test`) runs first, so a rule that stops matching fails CI. Runs from a digest-pinned image with `--network none --metrics=off`.                                                      |
| 1     | `codeql`    | Go taint analysis with the `security-extended` and `security-and-quality` suites.                                                                                                                                                                                                                                                                                                                    |
| 2     | `airgapped` | **Networked phase:** `make deps-check`, `go mod vendor`, pinned tool install (golangci-lint, gosec, govulncheck), offline copy of `vuln.go.dev/vulndb.zip`. **Air-gapped phase:** `make check` and `make verify` under `scripts/airgap-exec.sh` with `GOFLAGS=-mod=vendor`, `GOPROXY=off`, `GOTOOLCHAIN=local` and an empty read-only `GOMODCACHE`, so every dependency must resolve from `vendor/`. |
| 3     | `build`     | Runs only after stages 1 and 2 pass. Builds the static binary air-gapped from `vendor/` and uploads it with its SHA-256.                                                                                                                                                                                                                                                                             |

Every job starts with StepSecurity Harden-Runner in `block` mode and an explicit endpoint allowlist. On Ubuntu 24.04, `scripts/ci-apparmor-userns.sh` installs an AppArmor profile that grants the `userns` permission to `unshare` only. The global `kernel.apparmor_restrict_unprivileged_userns` stays on. The script then checks that an unprivileged network namespace can be created, and fails otherwise.

Harden-Runner, CodeQL and the Semgrep image are CI-only SaaS, authorized for the pipeline. None of them is a runtime dependency of `previewd`.

Actions are pinned by commit SHA, and checkout does not persist the job token to disk.



## Configuration

Operational parameters enforce hardware boundaries and are managed exclusively via environment variables:

* `PREVIEWD_API_PORT`: Agent HTTP listener port (default: 8080).


* `PREVIEWD_TRAEFIK_DOMAIN`: Base routing domain for PR environments (default: local.previewd).


* `PREVIEWD_MAX_BUILDS`: Strict concurrency limit for active deployment workers to prevent host CPU/RAM exhaustion (default: 2).


* `PREVIEWD_SECRETS_PATH`: Path to the local air-gapped secrets file (default: secrets.env).


* `PREVIEWD_DB_PATH`: SQLite database path (default: previewd.sqlite).
