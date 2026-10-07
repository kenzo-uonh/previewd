# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## Architecture & Tech Stack

*   **Core Daemon:** Statically compiled Go 1.27+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
*   **Orchestration:** Docker API (`github.com/moby/moby/client`) for isolated bridge networks and container lifecycles.
*   **Ingress & Routing:** Traefik reverse proxy bound to the local Docker socket, configured dynamically via runtime container labels.
*   **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery.
*   **Security Context:** Secrets are loaded into memory from a local secrets file. For each environment they are staged on a host ramfs directory (`/run/previewd/secrets/<env-id>/`, one file per key) and bind-mounted read-only into the container at `/run/secrets`. They never pass through container environment variables, the Docker API, `docker inspect`, image layers or disk.

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
│   │   ├── handlers.go            # Webhook receivers for GitHub PR events (validate + envid).
│   │   └── middleware.go          # Bounded body read, HMAC-SHA256 verification (validate).
│   ├── config/
│   │   └── config.go              # Air-gapped environment configuration loading.
│   ├── envid/                     # Environment ID: pr-<n>-<hash(repo, branch)>, a DNS label (leaf).
│   ├── hardening/                 # mlockall with RLIMIT_MEMLOCK and VmLck checks (leaf, _linux/_other).
│   ├── orchestrator/
│   │   ├── docker.go              # Docker Driver implementation for the MVP.
│   │   ├── engine.go              # Interface defining the Driver (Docker/Kubernetes).
│   │   ├── environment.go         # EaaS lifecycle logic (Clone, Start, Stop, Destroy).
│   │   └── queue.go               # Bounded worker pool for deployment concurrency.
│   ├── proxy/
│   │   ├── labels.go              # Docker label routing (current runtime path).
│   │   ├── route.go               # Traefik file-provider route documents (validated, JSON-as-YAML).
│   │   └── publish.go             # Atomic publish: temp file, fsync, rename, fsync dir.
│   ├── secrets/
│   │   ├── injector.go            # Loads the secrets file into memory.
│   │   └── stager*.go             # ramfs staging: fs-type, owner and mode checks, one file per key.
│   ├── store/
│   │   ├── db.go                  # modernc.org/sqlite connection pool (No CGO).
│   │   ├── queries.go             # Agent persistence for active environment states.
│   │   └── schema.go              # Startup schema check: pinned columns, no BLOB affinity.
│   ├── textutil/                  # Sanitize: map untrusted text onto [a-zA-Z0-9-] (leaf).
│   ├── validate/                  # Identifier validators, webhook HMAC and payload schema, layering test (leaf).
│   └── vcs/
│       ├── clone.go               # Secure repository cloning execution.
│       └── github.go              # GitHub webhook event names.
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


* `PREVIEWD_WEBHOOK_SECRET`: HMAC secret of the GitHub webhook. **Required.** The daemon refuses to start without it, and an empty secret accepts nothing. Every webhook must carry the exact `X-Hub-Signature-256` for its body (at most 1 MiB).


* `PREVIEWD_ALLOW_UNLOCKED_MEMORY`: Set exactly `1` to start when `mlockall` cannot be applied. By default the daemon locks all current and future memory before reading any secret, and refuses to start unless `RLIMIT_MEMLOCK` is unlimited (systemd `LimitMEMLOCK=infinity`). The opt-in is logged as an error at every start.


* `PREVIEWD_SECRETS_PATH`: Path to the local air-gapped secrets file (default: secrets.env).


* `PREVIEWD_SECRETS_STAGING_DIR`: Host directory where each environment's secrets are staged (default: `/run/previewd/secrets`). Must be on **ramfs**, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job.


* `PREVIEWD_ALLOW_TMPFS_SECRETS`: Set exactly `1` to accept a tmpfs staging directory. tmpfs pages can be swapped to disk, so use it only on hosts without swap. The opt-in is logged as an error at every start, and any other value is a configuration error.


* `PREVIEWD_DB_PATH`: SQLite database path (default: previewd.sqlite).

## Secret Staging

Secrets reach a preview container only as read-only files:

1. At deploy, previewd writes each key to `$PREVIEWD_SECRETS_STAGING_DIR/<env-id>/<KEY>`. Directories are `0555` and files `0444`. Keys must match `[A-Za-z_][A-Za-z0-9_]*`, and a bad key refuses the job before anything is written.
2. The container gets that directory at `/run/secrets` as a `bind` mount with `ReadOnly`, `rprivate` propagation and no recursion. Its config holds no secret, so `docker inspect` and the daemon's on-disk container state show only the host path.
3. Teardown (PR closed) removes the container, then the staged directory, even when Docker teardown fails. A failed deploy removes its staging too.

The staging root lives in memory. Mount it before starting previewd:

```bash
sudo mkdir -p /run/previewd/secrets
sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs /run/previewd/secrets
sudo chown previewd:previewd /run/previewd/secrets
```

ramfs is never swapped. A reboot discards it, together with every staged secret.

## Webhook Ingestion

1. **Signature:** the body is read up to 1 MiB (larger bodies get 413, never truncated). It must carry `X-Hub-Signature-256: sha256=<64 lowercase hex>`, equal to HMAC-SHA256 of the raw body under `PREVIEWD_WEBHOOK_SECRET`. Anything else gets 401.
2. **Schema:** `pull_request` bodies need `action`, `number` (1 to 2^32-1), `pull_request.head.ref` (git ref rules), `pull_request.head.sha` (40 or 64 lowercase hex), `repository.full_name` (`owner/repo`) and `repository.clone_url` (absolute, no credentials), for every action, `closed` included. `opened`, `reopened`, `synchronize` and `closed` are acted on; other well-formed actions get 202 and are ignored.
3. **Environment ID:** `pr-<number>-<10 hex of SHA-256(repo, head branch)>`. The same PR number in two repositories, or on two branches, never shares an environment.

## Formal Verification (Phase 1)

| Invariant | Where | How |
|---|---|---|
| Environment ID is an RFC 1123 label (at most 63 chars), recovers its PR number, is deterministic, separates repositories | `internal/envid` | rapid properties over arbitrary strings and bytes |
| `Sanitize` is idempotent and outputs only `[a-zA-Z0-9-]` | `internal/textutil` | rapid properties |
| Route documents decode with `gopkg.in/yaml.v3` (Traefik's parser) and as strict JSON; merged routes send each host only to its own backend | `internal/proxy` | rapid properties |
| Signature check and payload parser never panic; only the exact HMAC is accepted; schema violations are rejected | `internal/validate` | native fuzzing (`FuzzVerifySignature`, `FuzzParsePullRequest`) |
| Route swap is atomic (no torn read) and durable (fsync file, rename, fsync dir) | `internal/proxy` | concurrent reader test, call-order test |
| Schema holds no BLOB column and no unreviewed column | `internal/store` | startup check plus drift tests on modernc |
| Staging root is really ramfs | `internal/secrets` | real ramfs and tmpfs mounts inside an unprivileged user and mount namespace |
| `mlockall` locks current and future pages, and is refused under a finite limit | `internal/hardening` | subprocess tests (the success path needs `RLIMIT_MEMLOCK` unlimited; CI raises it with `prlimit`) |
| Leaves import no internal package; layering edges are explicit | `internal/validate` | `TestPackageLayering` |

`make check` runs all of these deterministically (fixed rapid seed, fuzz seed corpora). `make verify` runs rapid at 10,000 checks with random seeds, plus each fuzz target for `FUZZTIME`. Namespace tests skip where unprivileged user namespaces are unavailable. `PREVIEWD_REQUIRE_NS_TESTS=1` and `PREVIEWD_REQUIRE_MLOCK_TEST=1` turn those skips into failures, and CI sets both.

Phase 2 is a TLA+ model of the target queue design (webhook API, SQLite job queue, reconciler workers, startup sweep, daemon crash and host reboot) in `docs/formal/previewd.tla`. TLC checks zero secret leakage, no orphaned resources, monotonic ordering, eventual completion and eventual consistency. The shipped code still queues in memory; `docs/formal/README.md` has the results, the mutation table and how to run TLC offline.
