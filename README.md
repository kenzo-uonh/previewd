# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## Architecture & Tech Stack

*   **Core Daemon:** Statically compiled Go 1.27+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
*   **Orchestration:** Docker API (`github.com/moby/moby/client`). Each environment runs on its own internal bridge network (no default route, no egress), shared only with the Traefik container. PR containers run with every capability dropped, `no-new-privileges`, a read-only root file system with no writable mount (no tmpfs), a memory limit without swap and a task limit. An application that must write at run time is not supported yet.
*   **Ingress & Routing:** Traefik with the file provider only. previewd writes one route document per environment into `PREVIEWD_ROUTES_DIR` and removes it at teardown. Traefik has no Docker socket and reads no container label, so nothing in a PR image can add or change a route. Its entry point listens only on its fixed `previewd-proxy` address, never on the environment networks it joins, so a PR container cannot reach other environments through it. previewd refuses to start if the Traefik container mounts a socket, enables the Docker provider, is privileged or is not running.
*   **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery.
*   **Security Context:** Secrets are loaded into memory from a local secrets file. For each environment they are staged on a host ramfs directory (`/run/previewd/secrets/<env-id>/`, one file per key) and bind-mounted read-only into the container at `/run/secrets`. They never pass through container environment variables, the Docker API, `docker inspect`, image layers or disk.

## Codebase Structure

```text
.
├── cmd/
│   └── previewd/
│       └── main.go                # Single binary entry point initializing config, store, and HTTP server.
├── deployments/
│   ├── docker-compose.yml         # Traefik: digest-pinned, read-only, no socket, routes dir mounted read-only.
│   └── traefik.yml                # Traefik static configuration: file provider only, no API, no telemetry.
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
│   │   └── reconciler.go          # Startup sweep (inventory, destroy, route GC) and the deployment workers on the durable queue.
│   ├── proxy/
│   │   ├── route.go               # Traefik file-provider route documents (validated, JSON-as-YAML), the only routing path.
│   │   └── publish.go             # Atomic publish: temp file, fsync, rename, fsync dir.
│   ├── secrets/
│   │   ├── injector.go            # Loads the secrets file into memory.
│   │   └── stager*.go             # ramfs staging: fs-type, owner and mode checks, one file per key.
│   ├── store/
│   │   ├── db.go                  # modernc.org/sqlite pool (No CGO): WAL, busy_timeout, IMMEDIATE transactions, forward-only migrations (schema 3), incremental auto_vacuum.
│   │   ├── jobs.go                # Durable job queue: replay protection, stale deliveries, leases, startup sweep (TLA+ model).
│   │   ├── approvals.go           # Approval grants and revocations (order-independent), classification, park, internal teardowns.
│   │   ├── audit.go               # Append-only, hash-chained audit trail.
│   │   ├── maintenance.go         # Pruning behind the watermark, TTL expiry.
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

* **Initialize Infrastructure:** Start Traefik on port 80 and create the `previewd-proxy` bridge network (`172.30.255.0/24`; change it in both `deployments/docker-compose.yml` and `deployments/traefik.yml` if it overlaps a site network). `PREVIEWD_ROUTES_DIR` must exist first and be the directory the daemon writes to. The image is pinned by digest: on an air-gapped host, `docker load` it from a tar first.


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


* **Execute End-to-End Tests:** Run the air-gapped validation suite using a locally generated bare Git repository to verify the complete environment lifecycle: signature check, secrets only through the read-only mount, routing through the route document (no label, no socket), the internal network shared only with Traefik, Traefik unreachable from the PR container, and teardown of container, network, route and staged secrets. It mounts a ramfs with sudo; `E2E_STAGING=tmpfs make e2e` uses `/dev/shm` with `PREVIEWD_ALLOW_TMPFS_SECRETS=1` instead. Needs `busybox:latest` loaded locally.


```bash
make e2e
```


* **Deterministic Gate:** Module tidiness and hashes, formatting, vet, golangci-lint, gosec, govulncheck (fails on reachable findings), `airgap-check` (linked packages), `airgap-scan` (source, deployment files and specs; `scripts/airgap_scan.py`, Python 3 standard library, offline, after its own regression tests; fails on LOW and above), unit tests. Packages whose tests import rapid run with a fixed seed (`RAPID_SEED`, default 1; 0 is refused because rapid treats it as random), so every run generates the same inputs. Air-gapped: `DEPS_GATE=vendor-check` checks `vendor/` instead of the module cache, and `GOVULNDB=file:///path/to/vulndb` points govulncheck at an offline database mirror.


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


* `PREVIEWD_MAX_BUILDS`: Number of reconciler workers, i.e. jobs (deploys and teardowns) run at once; one job per environment at a time regardless (default: 2).


* `PREVIEWD_WEBHOOK_SECRET`: HMAC secret of the GitHub webhook. **Required.** The daemon refuses to start without it, and an empty secret accepts nothing. Every webhook must carry the exact `X-Hub-Signature-256` for its body (at most 1 MiB).


* `PREVIEWD_ALLOW_UNLOCKED_MEMORY`: Set exactly `1` to start when `mlockall` cannot be applied. By default the daemon locks all current and future memory before reading any secret, and refuses to start unless `RLIMIT_MEMLOCK` is unlimited (systemd `LimitMEMLOCK=infinity`). The opt-in is logged as an error at every start.


* `PREVIEWD_SECRETS_PATH`: Path to the local air-gapped secrets file (default: secrets.env).


* `PREVIEWD_SECRETS_STAGING_DIR`: Host directory where each environment's secrets are staged (default: `/run/previewd/secrets`). Must be on **ramfs**, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job.


* `PREVIEWD_ALLOW_TMPFS_SECRETS`: Set exactly `1` to accept a tmpfs staging directory. tmpfs pages can be swapped to disk, so use it only on hosts without swap. The opt-in is logged as an error at every start, and any other value is a configuration error.


* `PREVIEWD_DB_PATH`: SQLite database path (default: previewd.sqlite).


* `PREVIEWD_CONTAINER_MEMORY_MIB`: Memory limit of each PR container, swap disabled (default: 512). Must be an integer in 1..2^40; anything else is a configuration error.


* `PREVIEWD_CONTAINER_PIDS`: Task limit of each PR container (default: 256). Same validation.


* `PREVIEWD_ROUTES_DIR`: Directory of the route documents, watched by Traefik's file provider (default: `/var/lib/previewd/routes`). Must exist (absolute path, not a symlink); the daemon refuses to start otherwise. Mounted read-only into Traefik.


* `PREVIEWD_TRAEFIK_CONTAINER`: Name of the Traefik container, joined to each environment network (default: `traefik-proxy`). Checked at startup.

## Secret Staging

Secrets reach a preview container only as read-only files:

1. At deploy, previewd writes each key to `$PREVIEWD_SECRETS_STAGING_DIR/<env-id>/<KEY>`. Directories are `0555` and files `0444`. Keys must match `[A-Za-z_][A-Za-z0-9_]*`, and a bad key refuses the job before anything is written.
2. The container gets that directory at `/run/secrets` as a `bind` mount with `ReadOnly`, `rprivate` propagation and no recursion. Its config holds no secret, so `docker inspect` and the daemon's on-disk container state show only the host path.
3. Teardown (PR closed) removes the route document, then the container, then the staged directory; each step runs even when an earlier one fails. A failed deploy removes its staging too, and the startup sweep removes staging no kept environment owns.

The staging root lives in memory. Mount it before starting previewd:

```bash
sudo mkdir -p /run/previewd/secrets
sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs /run/previewd/secrets
sudo chown previewd:previewd /run/previewd/secrets
```

ramfs is never swapped. A reboot discards it, together with every staged secret.

## Webhook Ingestion

1. **Signature:** the body is read up to 1 MiB (larger bodies get 413, never truncated). It must carry `X-Hub-Signature-256: sha256=<64 lowercase hex>`, equal to HMAC-SHA256 of the raw body under `PREVIEWD_WEBHOOK_SECRET`. Anything else gets 401.
2. **Schema:** `pull_request` bodies need `action`, `number` (1 to 2^32-1), `pull_request.head.ref` (git ref rules), `pull_request.head.sha` (40 or 64 lowercase hex), `pull_request.head.repo` (`null` for a deleted fork, otherwise with `full_name`), `pull_request.user.login` and `pull_request.user.id` (the opener), `repository.full_name` (`owner/repo`) and `repository.clone_url` (absolute, no credentials), for every action, `closed` included. The head repository and the opener are recorded with the job; trust is never decided from them. `opened`, `reopened`, `synchronize` and `closed` are acted on; other well-formed actions get 202 and are ignored.
3. **Environment ID:** `pr-<number>-<10 hex of SHA-256(repo, head branch)>`. The same PR number in two repositories, or on two branches, never shares an environment.
4. **Ordering:** `X-GitHub-Delivery` must be a canonical UUID version 1 (RFC 4122 variant). Its embedded timestamp, in 100-nanosecond intervals, orders the intents of one environment. Anything else gets 400, and so does a timestamp more than 5 minutes ahead of the host's clock. GitHub does not sign that header, and one forged far-future ID would otherwise make every later event of the environment stale. Ordering relies on the clock of the GitHub Enterprise Server that minted the IDs; keep it and the previewd host on NTP.
5. **Queue:** one SQLite transaction records the delivery (`internal/store/jobs.go`). A delivery whose GUID or whose body (SHA-256) was already recorded is a duplicate (200). The body check matters because the header is unsigned, so a captured body resent under a new GUID is still refused. A delivery not newer than every job of its environment, whatever that job's status, and than its watermark (the highest seq of pruned jobs), is stale (202, nothing queued). Otherwise a job is queued (202) and a worker woken. `opened`, `reopened` and `synchronize` queue a deploy, `closed` a teardown. An accepted deploy also revokes, in the same transaction, the approvals of every other commit of the pull request (V1 approval gating, `docs/specs/V1-previewd.md`).

The database is at schema version 3. The first start of this version migrates a version-2 file in one transaction, then converts it once to incremental `auto_vacuum` with a `VACUUM` (temporary disk space up to the database size); the daemon refuses to start if either fails.

## Reconciliation

Workers (`PREVIEWD_MAX_BUILDS`) take the newest queued job of an environment with no job in progress; older queued jobs of that environment are skipped.

- **Deploy:** remove the previous version, fetch the commit, create the internal network, build, stage secrets, start the container, publish the route document, commit SUCCESS. Any failure removes everything and records FAILED.
- **Teardown:** remove route, container, network, image and staging. A failure requeues it with backoff (1 s doubling to 5 min); a teardown never ends FAILED.

At every start, before the API listens, the startup sweep runs:

1. Inventory the host: containers and networks previewd owns (`previewd.env` label, or the environment name for resources created before labels), staging directories, route documents.
2. Garbage-collect the routes directory. Crash debris from an interrupted write and any `.yml`, `.yaml` or `.toml` file that is not the route document of a valid environment ID are deleted. A directory or symlink there refuses the start.
3. Sweep the queue against that inventory. An environment is kept only if it is complete (container running, network, staged secrets, route document) and built by the newest executed job, a SUCCESS deploy. An interrupted deploy becomes FAILED and an interrupted teardown is queued again. A latest SUCCESS deploy whose environment is gone (a reboot wiped its secrets, its route was lost) is queued again.
4. Destroy everything else.
5. Check that every remaining route document belongs to a kept environment.

Any error refuses the start. A route document therefore exists only while the database records the environment as deployed.

## Formal Verification (Phase 1)

| Invariant                                                                                                                                                                                                                                                                                       | Where                | How                                                                                                             |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------|-----------------------------------------------------------------------------------------------------------------|
| Environment ID is an RFC 1123 label (at most 63 chars), recovers its PR number, is deterministic, separates repositories                                                                                                                                                                        | `internal/envid`     | rapid properties over arbitrary strings and bytes                                                               |
| `Sanitize` is idempotent and outputs only `[a-zA-Z0-9-]`                                                                                                                                                                                                                                        | `internal/textutil`  | rapid properties                                                                                                |
| Route documents decode with `gopkg.in/yaml.v3` (Traefik's parser) and as strict JSON; merged routes send each host only to its own backend                                                                                                                                                      | `internal/proxy`     | rapid properties                                                                                                |
| Signature check and payload parser never panic; only the exact HMAC is accepted; schema violations are rejected                                                                                                                                                                                 | `internal/validate`  | native fuzzing (`FuzzVerifySignature`, `FuzzParsePullRequest`)                                                  |
| Route swap is atomic (no torn read) and durable (fsync file, rename, fsync dir)                                                                                                                                                                                                                 | `internal/proxy`     | concurrent reader test, call-order test                                                                         |
| Schema holds no BLOB column and no unreviewed column                                                                                                                                                                                                                                            | `internal/store`     | startup check plus drift tests on modernc                                                                       |
| Staging root is really ramfs                                                                                                                                                                                                                                                                    | `internal/secrets`   | real ramfs and tmpfs mounts inside an unprivileged user and mount namespace                                     |
| `mlockall` locks current and future pages, and is refused under a finite limit                                                                                                                                                                                                                  | `internal/hardening` | subprocess tests (the success path needs `RLIMIT_MEMLOCK` unlimited; CI raises it with `prlimit`)               |
| Leaves import no internal package; layering edges are explicit                                                                                                                                                                                                                                  | `internal/validate`  | `TestPackageLayering`                                                                                           |
| Job queue equals the TLA+ model after every command (enqueue, replay, out-of-order delivery, acquire, deploy and teardown steps with Docker failures, daemon crash, host reboot, stale leases); lock integrity, monotonicity, no orphaned resources; every job completes and the host converges | `internal/store`     | `rapid.StateMachine` (`TestJobStore_StateMachine`), scenario tests per deviation D1 to D3                       |
| V1 store (schema 3) equals the V1 reference model after every command: approvals and revocations in any order, park, classification, revocation, re-validation and TTL teardowns, pruning, crashes; every V1 safety and liveness property of `docs/formal/V1-model.md` holds | `internal/store` | `rapid.StateMachine` (`TestV1Store_StateMachine`, at most 500 runs under `make verify`), V1 mutants on the reference model (`TestV1Model_Mutants`) |
| The audit trail is append-only and any changed, deleted, relinked or forged row breaks the hash chain | `internal/store` | append-only triggers, tamper tests with the triggers dropped |
| Overlapping read/write transactions never surface `SQLITE_BUSY`                                                                                                                                                                                                                                 | `internal/store`     | 16 writers and 4 long readers on two pools; controls prove the detector fires without the connection parameters |

`make check` runs all of these deterministically (fixed rapid seed, fuzz seed corpora). `make verify` runs rapid at 10,000 checks with random seeds, plus each fuzz target for `FUZZTIME`. Namespace tests skip where unprivileged user namespaces are unavailable. `PREVIEWD_REQUIRE_NS_TESTS=1` and `PREVIEWD_REQUIRE_MLOCK_TEST=1` turn those skips into failures, and CI sets both.

Phase 2 is a TLA+ model of the queue design (webhook API, SQLite job queue, reconciler workers, route documents, startup sweep, daemon crash and host reboot) in `docs/formal/previewd.tla`. TLC checks zero secret leakage, no orphaned resources (route documents included), routes only to running containers, monotonic ordering, eventual completion and eventual consistency. The daemon runs this design: `internal/store/jobs.go` and `internal/orchestrator/reconciler.go`. `docs/formal/README.md` has the results, the mutation table and how to run TLC offline.
