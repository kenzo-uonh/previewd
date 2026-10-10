# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## What it does, in plain words

When a developer opens a pull request, reviewers usually read the code change but cannot try it. previewd fixes that: for every pull request it builds that exact version of the application, runs it in its own sealed box on your server, and gives it its own web address. When the pull request is updated, the preview is rebuilt; when it is closed, the preview and everything it used are deleted.

Think of it as a hotel that hands each pull request a private room: the room is set up when the guest arrives, nobody can walk from one room into another, the keys are never written down, and the room is emptied the moment the guest checks out.

## Quick Start Installation

previewd ships as a `.deb` and an `.rpm` (`make release` builds both into `dist/`). Install from the file, no repository needed:

```bash
sudo apt install ./previewd_1.0.0_amd64.deb      # or: sudo dnf install --disablerepo='*' ./previewd-1.0.0-1.x86_64.rpm
sudo editor /etc/previewd/previewd.conf          # PREVIEWD_* settings: paths and identifiers, never a secret
sudo systemctl enable --now previewd
```

The package installs the binary (`/usr/bin/previewd`), the systemd unit, the build slice and the Docker drop-in, and creates the `previewd` system user. Before the first start, seal the credentials, mount the ramfs staging root, start Traefik and allow your GHES address: previewd checks each of them and refuses to start while one is missing. Every step: [Deployment](docs/deployment.md).

## The Workflow (How it Works)

1. **A developer opens a pull request** on the organization's GitHub Enterprise Server. GHES sends a signed webhook to previewd; nothing else is contacted.
2. **previewd decides whether the code may run.** A branch of the same repository pushed by someone with write access deploys at once. A fork or an outside contributor waits until an approver listed in `PREVIEWD_APPROVERS` approves that exact commit; every decision goes to the audit trail.
3. **previewd builds and runs it.** It fetches the commit's tarball from GHES with a repository-scoped GitHub App token revoked after use, builds the image without network inside the bounded `previewd-builds.slice` cgroup, and starts the environment on its own private network with its secrets as read-only in-memory files.
4. **The preview gets its own address.** Traefik serves it at `http://pr-<number>-<hash>.<PREVIEWD_TRAEFIK_DOMAIN>`; the route file of the same name in `PREVIEWD_ROUTES_DIR` shows it. previewd posts nothing back to the pull request: PR status feedback is an Enterprise edition feature. Each new push rebuilds the preview (from a fork, once the new commit is approved).
5. **The preview is destroyed** when the pull request is closed, when its approval is withdrawn (dismissed review, requested changes, label removed), or when its running version reaches the TTL with no newer push (`PREVIEWD_ENV_TTL`, default 7 days). Teardown removes the container, network, image, route and staged secrets.

## Why it exists

Hosted preview services send source code, and often the secrets an application needs, to someone else's cloud. Banks, hospitals and defense organizations cannot do that: their code and credentials must stay inside their own network, often on machines with no internet access at all. previewd is built for them:

- **Runs entirely on your premises.** One static binary next to Docker and Traefik on a single Linux host, talking to your own GitHub Enterprise Server. It needs no cloud account, calls no service outside your network and installs offline.
- **Treats pull-request code as hostile.** Builds run without network access, containers run locked down on private networks, and code from forks or outside contributors runs only after a named approver has reviewed that exact commit.
- **Never writes a secret to disk.** previewd's own keys are systemd credentials; application secrets are held in locked memory and handed to a preview only as read-only files in memory.
- **Leaves a verifiable record.** Every authorization decision is written to a tamper-evident, hash-chained audit trail.

## Documentation

| Document | Contents |
|----------|----------|
| [Architecture](docs/architecture.md) | Tech stack, build isolation, secret staging, webhook ingestion, reconciliation, audit trail, formal verification |
| [Configuration](docs/configuration.md) | Every `PREVIEWD_*` environment variable, systemd credentials, opt-ins |
| [Deployment](docs/deployment.md) | Host setup: offline images, Traefik, ramfs secrets staging, build cgroup and egress filter, GHES |
| [V1 specification](docs/specs/V1-previewd.md) | V1 design, decisions and invariants |
| [Formal models](docs/formal/README.md) | TLA+ models, TLC results, how to run TLC offline |

On this page: [Codebase Structure](#codebase-structure) · [Development & Execution](#development--execution) · [CI](#ci-githubworkflowsciyml)

## Codebase Structure

```text
.
├── .semgrep/                      # Semgrep rules and fixtures: previewd-rules (env, secret mounts, root contexts), previewd-no-container-output (H1).
├── cmd/
│   └── previewd/
│       ├── main.go                # Single binary entry point initializing config, store, and HTTP server.
│       ├── audit.go               # `previewd audit verify|export`: read-only check and JSON Lines export of the audit trail.
│       └── buildprobe.go          # `previewd build-probe`: the network check run inside the startup probe's BuildKit RUN step.
├── deployments/
│   ├── docker-compose.yml         # Traefik: digest-pinned, read-only, no socket, routes dir mounted read-only, cgroup parent system.slice.
│   ├── docker.service.d/
│   │   └── previewd-builds.conf   # dockerd drop-in: default cgroup parent previewd-builds.slice (BuildKit RUN steps), egress filter (IPAddressDeny).
│   ├── previewd.service           # Daemon unit (packages): User previewd, Group docker, LimitMEMLOCK, credentials, IPAddressDeny.
│   ├── previewd-builds.slice      # Bounded subtree of every build: MemoryMax 4G, MemorySwapMax 0, CPUQuota 200%, TasksMax 2048 (D-V1-4).
│   └── traefik.yml                # Traefik static configuration: file provider only, no API, no telemetry.
├── docs/
│   ├── architecture.md            # Tech stack, ingestion, staging, reconciliation, audit trail, verification.
│   ├── configuration.md           # Environment variables and credentials.
│   ├── deployment.md              # Host setup.
│   ├── formal/                    # TLA+ models and TLC results.
│   └── specs/                     # MVP and V1 specifications.
├── internal/
│   ├── api/
│   │   ├── handlers.go            # Webhook receivers for GitHub PR events (validate + envid).
│   │   └── middleware.go          # Bounded body read, HMAC-SHA256 verification (validate).
│   ├── config/
│   │   └── config.go              # Air-gapped environment configuration loading.
│   ├── envid/                     # Environment ID: pr-<n>-<hash(repo, branch)>, a DNS label (leaf).
│   ├── hardening/                 # mlockall checks; build probe network checks; build cgroup limits and processes; free disk (statfs) (leaf, _linux/_other).
│   ├── orchestrator/
│   │   ├── buildprobe.go          # Startup build probe: probe image, isolation verification, bridge gateway.
│   │   ├── authorizer.go          # D4 deploy gate: trusted/untrusted from GHES, approvals re-read (review, approver ID and write access).
│   │   ├── builddir_*.go          # Owner check of stale build directories (_linux/_other).
│   │   ├── docker.go              # Docker engine: locked-down BuildKit /build request, build stream parsing, base-image check, containers, networks, image and build cache prune, free disk.
│   │   ├── engine.go              # Interface defining the Driver (Docker/Kubernetes).
│   │   ├── environment.go         # EaaS lifecycle logic (Clone, Start, Stop, Destroy).
│   │   ├── preflight.go           # Build preflight (V1 F2): validated context tar, Dockerfile checks on the pinned BuildKit parser.
│   │   └── reconciler.go          # Startup sweep (stale build dirs, inventory, destroy, route GC), deployment workers (build slots, build timeout, free-disk floor, build cache prune), maintenance loop (TTL, prune, images).
│   ├── proxy/
│   │   ├── route.go               # Traefik file-provider route documents (validated, JSON-as-YAML), the only routing path.
│   │   └── publish.go             # Atomic publish: temp file, fsync, rename, fsync dir.
│   ├── secrets/
│   │   ├── credential.go          # systemd credentials by name from $CREDENTIALS_DIRECTORY (App key, listener key, webhook secret).
│   │   ├── injector.go            # Loads the secrets file into memory.
│   │   └── stager*.go             # ramfs staging: fs-type, owner and mode checks, one file per key.
│   ├── store/
│   │   ├── db.go                  # modernc.org/sqlite pool (No CGO): WAL, busy_timeout, IMMEDIATE transactions, forward-only migrations (schema 3), incremental auto_vacuum.
│   │   ├── jobs.go                # Durable job queue: replay protection, stale deliveries, leases, startup sweep (TLA+ model).
│   │   ├── approvals.go           # Approval grants and revocations (order-independent), classification, park, internal teardowns.
│   │   ├── audit.go               # Append-only, hash-chained audit trail.
│   │   ├── maintenance.go         # Batched pruning behind the watermark, incremental_vacuum, TTL expiry.
│   │   └── schema.go              # Startup schema check: pinned columns, no BLOB affinity.
│   ├── textutil/                  # Sanitize: map untrusted text onto [a-zA-Z0-9-] (leaf).
│   ├── validate/                  # Identifier validators (base images: name:tag@sha256), webhook HMAC and payload schema, layering test (leaf).
│   └── vcs/
│       ├── clone.go               # git fallback (no GitHub App): exactly the commit, --depth=1, its argument vectors in one function.
│       ├── ghes.go                # GHES client as a GitHub App: scoped tokens revoked after use, bounded replies.
│       ├── tarball.go             # Source fetch (H2): the commit tarball from GHES, extracted under bounds through os.Root.
│       └── github.go              # GitHub webhook event names.
├── test/e2e/                      # E2E tools, e2e build tag: fakegithub (fake GHES, tarballs), exfil (E3 listener), dockerapi (G1 on the real engine).
├── scripts/
│   ├── build.sh                   # Static binary compilation script.
│   ├── check-package-install.sh   # `make test-packages`: user, group and installed files after a package install.
│   ├── postinstall.sh             # Package post-install: previewd system user (no shell, no home) in group docker.
│   ├── verify-buildkit.sh         # E0 engine probe: BuildKit network isolation, stream errors, cache, pulls, cgroup placement and bounds, cancellation.
│   └── verify-e2e.sh              # Local, air-gapped end-to-end integration validation.
├── Makefile                       # Build, test, and infrastructure automation targets.
├── nfpm.yaml                      # deb and rpm package definition (`make release`).
├── go.mod                         # Go module dependencies.
└── go.sum                         # Go module checksums.

```

## Development & Execution

The project uses a strict `Makefile` for all build and verification pipelines to enforce simplicity and consistency.

### Core Commands

| Command | Purpose |
|---------|---------|
| `make docker-up` | Start Traefik and the `previewd-proxy` network |
| `make build` | Compile the static, CGO-free binary into `bin/` |
| `make run` | Run the daemon locally |
| `make verify-buildkit` | Probe the engine's BuildKit behavior (E0) |
| `make e2e` | Air-gapped end-to-end suite against a fake GHES |
| `make check` | Deterministic gate (deps, format, vet, lint, gosec, govulncheck, air-gap checks, unit tests) |
| `make airgap-check` | Dependency denylist on the linked binary |
| `make verify` | Deep verification: property-based tests at volume, then every fuzz target |
| `make release` | Build the binary, then the deb and rpm packages into `dist/` (nfpm, digest-pinned image, no network) |
| `make test-packages` | Install, then reinstall, the packages in Ubuntu 24.04 and Fedora 42 containers without network and check the user and files |

#### Initialize Infrastructure

```bash
make docker-up
```

Start Traefik on port 80 and create the `previewd-proxy` bridge network. `PREVIEWD_ROUTES_DIR` must exist first. Subnet, image loading and Traefik checks: [Deployment, step 3](docs/deployment.md#3-start-traefik).

#### Build the Agent

```bash
make build
```

Compile the static, CGO-free binary with version metadata injected via ldflags into the `bin/` directory.

#### Run Locally

```bash
make run
```

Execute the `previewd` daemon. The settings it reads are in [configuration.md](docs/configuration.md).

#### Probe the engine (E0)

```bash
make verify-buildkit
```

`scripts/verify-buildkit.sh` sends the exact `/build` request previewd sends and checks the engine's BuildKit behavior:

- the four network cases (`networkmode=none`, a control build that must reach a listener on the host bridge, `RUN --network=host`, `RUN --network=default`);
- the session-less tar context;
- errors in a 200 stream;
- `nocache`;
- registry access for present, missing and swapped base images (against "registries" that are host-bridge ports: nothing leaves the host);
- per-build limits ignored;
- the host cgroup of a `RUN`;
- the drop-in bounds under `PREVIEWD_BUILDKIT_CGROUP` (cgroup v2);
- the end of the `RUN` when the request is closed.

Evidence goes to `build/reports/<version>/buildkit/<engine>/`; it exits 0 only if every case passes. It needs `busybox` loaded locally (or `PROBE_BASE=name@sha256:<digest>`).

The daemon's own startup build probe (`previewd build-probe`) is described in [architecture.md](docs/architecture.md#startup-build-probe).

#### Execute End-to-End Tests

```bash
make e2e
```

Run the air-gapped validation suite using a locally generated bare Git repository to verify the complete environment lifecycle against a fake GHES (`test/e2e/fakegithub`, build tag `e2e`, its own test PKI, never part of the daemon), which also serves that repository's commit tarballs through a one-time archive URL. The suite covers:

- the TLS listener;
- sources fetched only as GHES tarballs with `contents:read` tokens, each archive URL used once and never sent a token;
- approvals judged from GHES with every token scoped and revoked;
- signature check;
- secrets only through the read-only mount;
- routing through the route document (no label, no socket);
- the internal network shared only with Traefik, Traefik unreachable from the PR container;
- teardown of container, network, route and staged secrets;
- the startup build probe (at both starts, its image removed);
- the exfiltration probe: a PR whose `RUN` tries a TCP connection and a DNS query to a listener on the host bridge reaches nothing, while a control build on the default network by the test fixture `test/e2e/exfil` (`e2e` tag) must reach it;
- a `RUN --network=host` PR refused by the preflight;
- the approval gating flow on a fork PR: parked without a build, still parked on an approval of another commit, deployed with the `:untrusted` secret section only on an approval of its head, torn down by a push, by a dismissal, and by GHES down past the re-validation grace;
- `previewd audit verify|export` on the live database;
- the auto-cleanup calls against the real engine (`test/e2e/dockerapi`, `e2e` tag: `PruneImages` keeps an image an operator tagged or a container uses, `PruneBuildCache` leaves nothing, `FreeDisk` equals statfs of the data root) and the daemon's build cache and image prunes;
- a short TTL: an `e2e` build of the daemon (TTL and prune-interval floors of 1 s, logged as an error at every start, absent from `bin/previewd`) with `PREVIEWD_ENV_TTL=20s` tears down a running environment and a parked fork through the queue, each audited `ttl_expired`.

Run notes:

- Re-validation runs at its minimum interval and grace (1m each), so the suite takes a few minutes.
- It mounts a ramfs with sudo; `E2E_STAGING=tmpfs make e2e` uses `/dev/shm` with `PREVIEWD_ALLOW_TMPFS_SECRETS=1` instead.
- `E2E_BUILDKIT_CGROUP=<subtree>` runs the daemon with `PREVIEWD_BUILDKIT_CGROUP`; unset, it runs with `PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1` (the network probe still runs).
- Needs `busybox:latest` loaded locally: the PR Dockerfiles use it pinned to its local digest (`busybox:latest@sha256:…`), the only allowlisted base.

#### Deterministic Gate

```bash
make check
make check DEPS_GATE=vendor-check GOVULNDB=file:///opt/vulndb
make check RAPID_SEED=<seed printed by a failing make verify>
```

Runs, in order:

- module tidiness and hashes;
- formatting, vet, golangci-lint, gosec;
- govulncheck (fails on reachable findings);
- `airgap-check` (linked packages);
- `airgap-scan` (source, deployment files and specs; `scripts/airgap_scan.py`, Python 3 standard library, offline, after its own regression tests; fails on LOW and above);
- unit tests.

Packages whose tests import rapid run with a fixed seed (`RAPID_SEED`, default 1; 0 is refused because rapid treats it as random), so every run generates the same inputs. Air-gapped: `DEPS_GATE=vendor-check` checks `vendor/` instead of the module cache, and `GOVULNDB=file:///path/to/vulndb` points govulncheck at an offline database mirror.

#### Dependency Denylist

```bash
make airgap-check
```

Fails if `./cmd/previewd` links an OpenTelemetry SDK or exporter, OTLP protobufs, gRPC, an AWS/GCP/Azure SDK, or the deprecated `github.com/docker/docker` module.

The Docker client is `github.com/moby/moby/client`, which links the OpenTelemetry *API* packages and `otelhttp`. With no SDK in the binary these are no-ops: no span, metric or log record leaves the process. The previous `docker/docker` dependency listed `otlptracehttp` in `go.mod` without linking it; after the migration it is gone from the module graph. No exception to the no-telemetry rule is needed.

#### Deep Verification

```bash
make verify
make verify RAPID_CHECKS=100000 FUZZTIME=10m
```

Property-based tests (`pgregory.net/rapid`, `-rapid.checks=$(RAPID_CHECKS)`, default 10000) in every package whose tests import rapid, with a random seed on each run, then every native fuzz target (`go test -fuzz`, `FUZZTIME` per target, default 60s). Fails if it finds no rapid package or no fuzz target. What these tests prove: [Formal Verification](docs/architecture.md#formal-verification-phase-1).

#### Air-Gapped Execution

`scripts/airgap-exec.sh <cmd>` runs a command in fresh unprivileged user, network and mount namespaces. Only loopback exists, and `/run` is hidden behind an empty tmpfs, because a network namespace does not isolate `/run/docker.sock` and a test could ask the host daemon to reach the network. Before running the command, the script checks that no interface, route, outbound connection or daemon socket is reachable, and refuses to run otherwise.

### CI (`.github/workflows/ci.yml`)

| Stage | Job | What it enforces |
|-------|-----|------------------|
| 1 | `semgrep` | Project rules in `.semgrep/previewd-rules.yaml`: no `container.Config.Env`, secret mounts memory-backed and read-only, no `context.Background()`/`TODO()` in orchestrator/store; and `.semgrep/previewd-no-container-output.yaml` (H1, V1-I10): no `ContainerLogs`, `ContainerAttach` or `ContainerExecAttach` outside tests. Each rule file's self-test (`semgrep --test` on its fixture) runs first, so a rule that stops matching fails CI. The scan runs with `--strict --timeout 0`: a rule that timed out on a file would otherwise report no finding there. Digest-pinned image, `--network none --metrics=off`; `make semgrep` runs the same locally (image loaded, never pulled). |
| 1 | `codeql` | Go taint analysis with the `security-extended` and `security-and-quality` suites. |
| 2 | `airgapped` | **Networked phase:** `make deps-check`, `go mod vendor`, pinned tool install (golangci-lint, gosec, govulncheck), offline copy of `vuln.go.dev/vulndb.zip`. **Air-gapped phase:** `make check` and `make verify` (on a pull request or push at `RAPID_CHECKS=100` and `FUZZTIME=10s`; on a manual run at the full 10000 and 60s) under `scripts/airgap-exec.sh` with `GOFLAGS=-mod=vendor`, `GOPROXY=off`, `GOTOOLCHAIN=local` and an empty read-only `GOMODCACHE`, so every dependency must resolve from `vendor/`. |
| 3 | `build` | Runs only after stages 1 and 2 pass. Builds the static binary air-gapped from `vendor/` and uploads it with its SHA-256. |

- Every job starts with StepSecurity Harden-Runner in `block` mode and an explicit endpoint allowlist.
- On Ubuntu 24.04, `scripts/ci-apparmor-userns.sh` installs an AppArmor profile that grants the `userns` permission to `unshare` only. The global `kernel.apparmor_restrict_unprivileged_userns` stays on. The script then checks that an unprivileged network namespace can be created, and fails otherwise.
- Harden-Runner, CodeQL and the Semgrep image are CI-only SaaS, authorized for the pipeline. None of them is a runtime dependency of `previewd`.
- Actions are pinned by commit SHA, and checkout does not persist the job token to disk.

### Release (`.github/workflows/release.yml`)

On a pushed `v*` tag, job `build-and-release`:

1. Refuses a tag that is not `vMAJOR.MINOR.PATCH[-PRERELEASE]` or does not point at the checked-out commit (the Makefile would otherwise package it as `1.0.0`).
2. `make test-packages` with the tag's version: `make release` builds the deb and rpm into `dist/`, then both are installed and reinstalled in Ubuntu 24.04 and Fedora 42 containers.
3. Generates a CycloneDX SBOM of the tree (`dist/previewd-sbom.json`) with a digest-pinned syft image run with `--network none`.
4. Writes `dist/SHA256SUMS` and publishes the GitHub release (`gh release create --generate-notes`) with the packages, the SBOM and the checksums.

Same rules as `ci.yml`: Harden-Runner in `block` mode, actions pinned by SHA, images by digest, no persisted token. The workflow needs `contents: write` to create the release. The release is not signed and is not gated on `ci.yml`: tag a commit whose CI passed.
