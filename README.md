# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## Architecture & Tech Stack

*   **Core Daemon:** Statically compiled Go 1.27.2+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
*   **Orchestration:** Docker API (`github.com/moby/moby/client`). Each environment runs on its own internal bridge network (no default route, no egress), shared only with the Traefik container. PR containers run with every capability dropped, `no-new-privileges`, a read-only root file system with no writable mount (no tmpfs), a memory limit without swap and a task limit. An application that must write at run time is not supported yet.
*   **Ingress & Routing:** Traefik with the file provider only. previewd writes one route document per environment into `PREVIEWD_ROUTES_DIR` and removes it at teardown. Traefik has no Docker socket and reads no container label, so nothing in a PR image can add or change a route. Its entry point listens only on its fixed `previewd-proxy` address, never on the environment networks it joins, so a PR container cannot reach other environments through it. previewd refuses to start if the Traefik container mounts a socket, enables the Docker provider, is privileged or is not running.
*   **Build isolation (V1 F2):** before any request reaches the engine, previewd packs the checkout into a tar (at most `PREVIEWD_MAX_BUILD_CONTEXT_MIB`; files, directories and symlinks that resolve inside the context only) and runs a Dockerfile preflight on the daemon's own parser (BuildKit v0.33.1, the version Docker 29.8.2 embeds). It refuses a `FROM` not in `PREVIEWD_ALLOWED_BASE_IMAGES` after `ARG` substitution, `FROM --platform`, `ADD` of a URL, git source or variable, `# syntax=`, every `RUN` flag (`--network`, `--mount`, `--security`, `--device`), `COPY --from` an image, `ONBUILD`, and anything it does not recognize. The build itself is BuildKit with `networkmode=none` (forced on every `RUN`), no cache, intermediate containers removed even on failure, no build argument, session or per-build limit, and its outcome is read from the response stream (an HTTP 200 carrying an error is a failed build). Secrets are never part of a build: they are staged after it. At every start, before the startup sweep, a probe build proves the isolation (see `previewd build-probe` below) and the daemon refuses to start if it fails.
*   **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery.
*   **Security Context:** Secrets are loaded into memory from a local secrets file, split per repository and per trust level (`[owner/repo]`, `[owner/repo:untrusted]`). For each environment, the section of its trust is staged on a host ramfs directory (`/run/previewd/secrets/<env-id>/`, one file per key) and bind-mounted read-only into the container at `/run/secrets`. They never pass through container environment variables, the Docker API, `docker inspect`, image layers or disk.

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
│   ├── previewd-builds.slice      # Bounded subtree of every build: MemoryMax 4G, MemorySwapMax 0, CPUQuota 200%, TasksMax 2048 (D-V1-4).
│   └── traefik.yml                # Traefik static configuration: file provider only, no API, no telemetry.
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
│   ├── verify-buildkit.sh         # E0 engine probe: BuildKit network isolation, stream errors, cache, pulls, cgroup placement and bounds, cancellation.
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


* **Startup build probe:** `previewd build-probe -addr IP:PORT` runs inside the probe build's only `RUN` step (`FROM scratch`, the previewd binary itself, the request PR builds get). It exits 0 only if every interface is loopback, no IPv4 route and no IPv6 route off `lo` exists, and the TCP connection fails as unreachable; then it stays alive 3 s so the daemon sees it in `PREVIEWD_BUILDKIT_CGROUP`. Exit 3: an interface; 4: a route; 5: the address answered, refused or timed out.


* **Probe the engine (E0):** `scripts/verify-buildkit.sh` sends the exact `/build` request previewd sends and checks the engine's BuildKit behavior: the four network cases (`networkmode=none`, a control build that must reach a listener on the host bridge, `RUN --network=host`, `RUN --network=default`), the session-less tar context, errors in a 200 stream, `nocache`, registry access for present, missing and swapped base images (against "registries" that are host-bridge ports: nothing leaves the host), per-build limits ignored, the host cgroup of a `RUN`, the drop-in bounds under `PREVIEWD_BUILDKIT_CGROUP` (cgroup v2), and the end of the `RUN` when the request is closed. Evidence goes to `build/reports/<version>/buildkit/<engine>/`; it exits 0 only if every case passes. It needs `busybox` loaded locally (or `PROBE_BASE=name@sha256:<digest>`).


```bash
make verify-buildkit
```


* **Execute End-to-End Tests:** Run the air-gapped validation suite using a locally generated bare Git repository to verify the complete environment lifecycle against a fake GHES (`test/e2e/fakegithub`, build tag `e2e`, its own test PKI, never part of the daemon), which also serves that repository's commit tarballs through a one-time archive URL: the TLS listener, sources fetched only as GHES tarballs with `contents:read` tokens, each archive URL used once and never sent a token, approvals judged from GHES with every token scoped and revoked, signature check, secrets only through the read-only mount, routing through the route document (no label, no socket), the internal network shared only with Traefik, Traefik unreachable from the PR container, teardown of container, network, route and staged secrets, the startup build probe (at both starts, its image removed), the exfiltration probe (a PR whose `RUN` tries a TCP connection and a DNS query to a listener on the host bridge reaches nothing, while a control build on the default network by the test fixture `test/e2e/exfil`, `e2e` tag, must reach it), a `RUN --network=host` PR refused by the preflight, the approval gating flow on a fork PR (parked without a build, still parked on an approval of another commit, deployed with the `:untrusted` secret section only on an approval of its head, torn down by a push, by a dismissal, and by GHES down past the re-validation grace), `previewd audit verify|export` on the live database, the auto-cleanup calls against the real engine (`test/e2e/dockerapi`, `e2e` tag: `PruneImages` keeps an image an operator tagged or a container uses, `PruneBuildCache` leaves nothing, `FreeDisk` equals statfs of the data root) and the daemon's build cache and image prunes, and a short TTL: an `e2e` build of the daemon (TTL and prune-interval floors of 1 s, logged as an error at every start, absent from `bin/previewd`) with `PREVIEWD_ENV_TTL=20s` tears down a running environment and a parked fork through the queue, each audited `ttl_expired`. Re-validation runs at its minimum interval and grace (1m each), so the suite takes a few minutes. It mounts a ramfs with sudo; `E2E_STAGING=tmpfs make e2e` uses `/dev/shm` with `PREVIEWD_ALLOW_TMPFS_SECRETS=1` instead. `E2E_BUILDKIT_CGROUP=<subtree>` runs the daemon with `PREVIEWD_BUILDKIT_CGROUP`; unset, it runs with `PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1` (the network probe still runs). Needs `busybox:latest` loaded locally: the PR Dockerfiles use it pinned to its local digest (`busybox:latest@sha256:…`), the only allowlisted base.


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
| 1     | `semgrep`   | Project rules in `.semgrep/previewd-rules.yaml`: no `container.Config.Env`, secret mounts memory-backed and read-only, no `context.Background()`/`TODO()` in orchestrator/store; and `.semgrep/previewd-no-container-output.yaml` (H1, V1-I10): no `ContainerLogs`, `ContainerAttach` or `ContainerExecAttach` outside tests. Each rule file's self-test (`semgrep --test` on its fixture) runs first, so a rule that stops matching fails CI. The scan runs with `--strict --timeout 0`: a rule that timed out on a file would otherwise report no finding there. Digest-pinned image, `--network none --metrics=off`; `make semgrep` runs the same locally (image loaded, never pulled). |
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


* `PREVIEWD_MAX_BUILDS`: Number of reconciler workers, i.e. jobs (deploys and teardowns) run at once, 1..64; one job per environment at a time regardless (default: 2). A value outside the range, or not an integer, refuses to start. How many of those jobs build at once is `PREVIEWD_MAX_CONCURRENT_BUILDS`.


* `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL` (default `webhook_secret`): Name of the systemd credential holding the HMAC secret of the GitHub webhook. **Required credential.** The secret is never read from the environment or from a configured path: the daemon refuses to start while `PREVIEWD_WEBHOOK_SECRET` is set (whatever its value, which is never read), and when the credential is missing, empty, or only line breaks. Trailing CR/LF bytes are dropped; every other byte is the key. Every webhook must carry the exact `X-Hub-Signature-256` for its body (at most 1 MiB). Changing the secret takes a restart.


* `PREVIEWD_ALLOW_UNLOCKED_MEMORY`: Set exactly `1` to start when `mlockall` cannot be applied. By default the daemon locks all current and future memory before reading any secret, and refuses to start unless `RLIMIT_MEMLOCK` is unlimited (systemd `LimitMEMLOCK=infinity`). The opt-in is logged as an error at every start.


* `PREVIEWD_SECRETS_PATH`: Path to the local air-gapped secrets file (default: secrets.env), at most 1 MiB. Every key lives in a section:

  ```ini
  [acme/app]
  DB_PASSWORD=...        # trusted deploys: same-repository PRs opened by a writer
  [acme/app:untrusted]
  DB_PASSWORD=...        # approved fork or external PRs
  ```

  A key outside any section, a line without `=`, an invalid key, a header that is not `[owner/repo]` or `[owner/repo:untrusted]`, or a section or key declared twice refuses to start; errors name the line, never its content. An untrusted deploy receives its `:untrusted` section only, an empty set when there is none, never the trusted one. A missing file is an empty set.


* `PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS`: Comma-separated `owner/repo` list (D-V1-1 escape hatch): approved untrusted deploys of these repositories receive the trusted section. Logged as an error at every start and every such deploy, and audited (`full_secrets_opt_in`).


* `PREVIEWD_APPROVAL_REVALIDATE_INTERVAL` (default `10m`, 1m..1h) and `PREVIEWD_APPROVAL_REVALIDATE_GRACE` (default `1h`, at least the interval, at most 24h): every interval, each running environment is re-checked against GHES; see Reconciliation.


* `PREVIEWD_SECRETS_STAGING_DIR`: Host directory where each environment's secrets are staged (default: `/run/previewd/secrets`). Must be on **ramfs**, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job.


* `PREVIEWD_ALLOW_TMPFS_SECRETS`: Set exactly `1` to accept a tmpfs staging directory. tmpfs pages can be swapped to disk, so use it only on hosts without swap. The opt-in is logged as an error at every start, and any other value is a configuration error.


* `PREVIEWD_DB_PATH`: SQLite database path (default: previewd.sqlite).


* `PREVIEWD_CONTAINER_MEMORY_MIB`: Memory limit of each PR container, swap disabled (default: 512). Must be an integer in 1..2^40; anything else is a configuration error.


* `PREVIEWD_CONTAINER_PIDS`: Task limit of each PR container (default: 256). Same validation.


* `PREVIEWD_APPROVERS`: Accounts whose review approves untrusted code, as comma-separated `owner/repo:login#id` entries (repository spelled as GitHub spells it). The numeric account ID is mandatory and is the identity; the login is for logs and the audit trail. Any malformed entry, or an account listed twice for a repository, refuses to start. Unset: no approver.


* `PREVIEWD_LABEL_APPROVAL`: Set exactly `1` to let an approver approve by labeling the pull request. Logged as an error at every start.


* `PREVIEWD_APPROVAL_LABEL`: The approving label (default: `previewd-approved`), 1 to 50 bytes, no control character.


* `PREVIEWD_DELIVERY_MAX_AGE`: How long after its signed time a delivery is still accepted (default: `15m`, a Go duration in 1m..2h; see V1-I7 below).


* `PREVIEWD_GHES_URL` (required): The GitHub Enterprise Server, `https://host[:port]`, no path (the API is under `/api/v3`). previewd reads it as a GitHub App, through no proxy, following no redirect.


* `PREVIEWD_GHES_CA_FILE`: PEM bundle of the site CA that signs the GHES certificate. When set, it is the only trust (never added to the system roots); every block must be a certificate.


* `PREVIEWD_GITHUB_APP_ID` (required) and `PREVIEWD_GITHUB_APP_KEY_CREDENTIAL` (default `github-app-key`): The GitHub App and the name of the systemd credential holding its private key (RSA, 2048 bits or more). The App needs **Pull requests: read**, **Contents: read** (source tarballs, H2) and the default **Metadata: read**, installed on the repositories previewd serves. Each read mints a token scoped to one repository, read only, with the one permission it needs, and revokes it before returning.


* `PREVIEWD_TLS_CERT_FILE` and `PREVIEWD_TLS_KEY_CREDENTIAL` (required unless the plaintext opt-in): The webhook listener's certificate chain (a file) and the systemd credential holding its key. TLS 1.2 or later, AEAD suites only. `systemctl reload`/SIGHUP re-reads both; a pair that fails to load keeps the one in use. An expired, not yet valid or mismatched pair refuses to start.


* `PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS`: Set exactly `1` to receive webhooks in plaintext (delivery IDs and bodies readable on the network). Logged as an error at every start; contradicts the TLS keys.


* `PREVIEWD_WEBHOOK_ALLOWED_CIDRS`: Comma-separated prefixes (`10.0.0.0/8,fd00::/8`, no host bits) of the GHES addresses that may deliver webhooks. A peer outside them gets 403 before its body is read. Unset: any source (logged as a warning).

Credentials are read by name from `$CREDENTIALS_DIRECTORY`, never from a configured path: pass them with `LoadCredentialEncrypted=github-app-key:/etc/credstore.encrypted/github-app-key` and `LoadCredentialEncrypted=webhook_secret:/etc/credstore.encrypted/webhook_secret` (or `LoadCredential=`) in the unit; `systemd-creds encrypt --name=webhook_secret - /etc/credstore.encrypted/webhook_secret` seals the secret from standard input. In GHES, enable SSL verification on the webhook and make the listener certificate chain to a CA GHES trusts.


* `PREVIEWD_ALLOWED_BASE_IMAGES` (required): Comma-separated base images a PR may build `FROM`, each `name:tag@sha256:<64 hex>` (tag **and** digest; `docker.io/library` defaults apply). Load each on the host under that `name:tag` (`docker load`): previewd never pulls, and refuses to start unless every entry's local `name:tag` is the pinned digest and carries no `ONBUILD` trigger. A `FROM` must spell the same image, tag included: the engine contacts the image's registry before every build whatever the pull flag, and falls back to the local image only by its `name:tag`, refusing it unless it is the pinned digest; a digest-only `FROM` cannot build offline (`scripts/verify-buildkit.sh`, cases `egress-filter`, `offline-base`, `digest-enforced`). The host egress filter is the control that keeps the engine off the registries (D-V1-2): install it. Any malformed entry, or an image listed twice, refuses to start.


* `PREVIEWD_MAX_BUILD_CONTEXT_MIB`: Size cap of the build context tar, 1..16384 (default: 512). A larger checkout fails the deploy before any build request.


* `PREVIEWD_BUILDKIT_CGROUP` (required unless the opt-in below): The cgroup v2 subtree, under `/sys/fs/cgroup`, where the engine runs BuildKit `RUN` steps, bounded by systemd (D-V1-4). At every start previewd requires its `memory.max`, `pids.max` and `cpu.max` quota finite and `memory.swap.max` 0, the subtree idle, a process of the probe build in it while the probe runs, and none left after. Any failure refuses to start. With the systemd cgroup driver, install `deployments/previewd-builds.slice` in `/etc/systemd/system/` and `deployments/docker.service.d/previewd-builds.conf` in `/etc/systemd/system/docker.service.d/`, then `systemctl daemon-reload && systemctl restart docker`, and set `/sys/fs/cgroup/previewd.slice/previewd-builds.slice`. The drop-in makes that slice dockerd's default cgroup parent, where BuildKit runs every `RUN` (`docker-<id>.scope`), and filters dockerd's own egress (D-V1-2): environment containers and Traefik name `system.slice` instead, and any other container on the host must too, or the subtree is busy and previewd refuses to start. Not yet verified on a cgroup v2 host (E0 `bound-*` cases pending).


* `PREVIEWD_ALLOW_UNBOUNDED_BUILDS`: Set exactly `1` to skip the cgroup checks of the startup probe (dev hosts, cgroup v1); the network check still runs. Contradicts `PREVIEWD_BUILDKIT_CGROUP`. Logged as an error at every start.


* `PREVIEWD_MAX_CONCURRENT_BUILDS`: Builds in flight at once across every worker, 1..16 (default: 1). Every build shares the BuildKit cgroup's limits (D-V1-4), so a value above 1 needs `previewd-builds.slice` scaled; it is logged at every start. A worker waits for a free slot before it builds.


* `PREVIEWD_BUILD_TIMEOUT`: A build still running after this duration, 1m..2h, is cancelled (default: `20m`): previewd closes the build request, which stops the BuildKit solve and its `RUN` processes (`scripts/verify-buildkit.sh`, case `cancel`), and the deploy fails with `failure = 'build'`. A build the engine reports successful after its deadline fails too.


* `PREVIEWD_BUILD_PROBE_ADDR`: The startup probe's TCP target, `IP:PORT` (default: the default bridge's IPv4 gateway, port 9). Only "network unreachable" or "host unreachable" passes; a connection, a refusal or a timeout refuses to start.


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

0. **Transport:** TLS 1.2+ from an allowed source (`PREVIEWD_WEBHOOK_ALLOWED_CIDRS`, checked before the body is read).
1. **Signature:** the body is read up to 1 MiB (larger bodies get 413, never truncated). It must carry `X-Hub-Signature-256: sha256=<64 lowercase hex>`, equal to HMAC-SHA256 of the raw body under the webhook secret (the `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL` credential). Anything else gets 401.
2. **Schema:** `pull_request` bodies need `action`, `number` (1 to 2^32-1), `pull_request.head.ref` (git ref rules), `pull_request.head.sha` (40 or 64 lowercase hex), `pull_request.head.repo` (`null` for a deleted fork, otherwise with `full_name`), `pull_request.user` and `sender` (login and numeric ID), `pull_request.updated_at` (RFC 3339), `repository.full_name` (`owner/repo`) and `repository.clone_url` (absolute, no credentials), for every action, `closed` included; `labeled` and `unlabeled` also need `label.name`. `pull_request_review` bodies need the same pull request fields (`pull_request.number`) and the review's `id`, `user`, `commit_id`, `state`, and `submitted_at` when submitted. The head repository and the opener are recorded with the job; trust is never decided from them. Acted on: `opened`, `reopened`, `synchronize`, `closed`, the approval label (below), and an approver's review that approves, requests changes or is dismissed. Other well-formed events and actions get 202 and are ignored.
3. **Environment ID:** `pr-<number>-<10 hex of SHA-256(repo, head branch)>`. The same PR number in two repositories, or on two branches, never shares an environment.
4. **Ordering:** `X-GitHub-Delivery` must be a canonical UUID version 1 (RFC 4122 variant). Its embedded timestamp, in 100-nanosecond intervals, orders the intents of one environment. Anything else gets 400, and so does a timestamp more than 5 minutes ahead of the host's clock. GitHub does not sign that header, and one forged far-future ID would otherwise make every later event of the environment stale. Ordering relies on the clock of the GitHub Enterprise Server that minted the IDs; keep it and the previewd host on NTP.
5. **Signed time (V1-I7):** the GUID's time must lie within 5 minutes before and `PREVIEWD_DELIVERY_MAX_AGE` after the time the signed body carries (`pull_request.updated_at`; `review.submitted_at` for a submitted review). A body captured and resent later under a fresh GUID falls outside it. A delivery that would deploy or approve is refused there (400); one that only restricts (`closed`, a change request, a dismissal, a label removal) is processed and logged, since it can only remove.
6. **Approvals:** an approver (`PREVIEWD_APPROVERS`, matched on the account ID) approves the exact head commit with a review, or, with `PREVIEWD_LABEL_APPROVAL=1`, by adding `PREVIEWD_APPROVAL_LABEL`. A change request by an approver, the dismissal of an approver's review, or the removal of the label (by anyone) revokes the approvals of that commit. Approvals and revocations are recorded with their delivery (replay-checked like any other) and an audit row, in any arrival order. Each is judged against GHES read in the same request: the environment is trusted when its head lives in the repository and its opener has write access (a trusted environment is not torn down by a revocation: it needed no approval), and an approval queues a deploy only when its commit is the open head now. When GHES cannot be read, an approval queues no deploy and a revocation is judged as for an untrusted environment.
7. **Queue:** one SQLite transaction records the delivery (`internal/store/jobs.go`). A delivery whose GUID or whose body (SHA-256) was already recorded is a duplicate (200). The body check matters because the header is unsigned, so a captured body resent under a new GUID is still refused. A delivery not newer than every job of its environment, whatever that job's status, and than its watermark (the highest seq of pruned jobs), is stale (202, nothing queued). Otherwise a job is queued (202) and a worker woken. `opened`, `reopened` and `synchronize` queue a deploy, `closed` a teardown. An accepted deploy also revokes, in the same transaction, the approvals of every other commit of the pull request (V1 approval gating, `docs/specs/V1-previewd.md`).

* `PREVIEWD_RETENTION`: Age past which finished jobs, approval grants no longer live and deliveries are pruned, at least `24h` (default: `720h`). Deliveries are kept at least `PREVIEWD_DELIVERY_MAX_AGE` + 5 minutes, so a captured body outside V1-I7's window is refused by the handler, never accepted for want of its row.

* `PREVIEWD_ENV_TTL`: Age, at least `1h` (default: `168h`), after which an environment whose running version has not been replaced is torn down, and a deploy parked for an approval since its creation is dropped: each maintenance pass queues an internal teardown (`origin = 'ttl'`, audited `ttl_expired`) pinned to that job's commit, which supersedes a parked job. A later push, or an approval of the open head, deploys it again. `0`, exactly, disables the TTL and is logged as an error at every start.
* `PREVIEWD_MIN_FREE_DISK_MIB`: Free space, at least `1024` (default: `10240`), that the file system of the Docker data root must have for a build to start. Below it, or when the free space cannot be read, the deploy is refused: FAILED with `failure = 'disk_floor'` and a `deploy_refused` audit row, nothing built. The daemon refuses to start only if the free space cannot be read; below the floor it starts and logs an error, so teardowns and the prune loop can free space.
* `PREVIEWD_DOCKER_DATA_ROOT`: The path whose file system is measured (default: the daemon's `DockerRootDir`, read at each check). Clean and absolute. With `userns-remap` the daemon's root is `/var/lib/docker/<uid>.<gid>`, which the daemon's user may not be allowed to reach: set `/var/lib/docker`, on the same file system.


* `PREVIEWD_PRUNE_INTERVAL`, `PREVIEWD_PRUNE_BATCH`: The maintenance loop runs a pass at start, then every interval, 1m..24h (default: `1h`), deleting at most a batch of rows per transaction, 10..10000 (default: 500), with a 150 ms pause between transactions so that webhooks waiting for the database lock get it, then returns up to 1,000 free pages to the file system (`PRAGMA incremental_vacuum`). A pass reads the host's environments first and never prunes the job that built one, nor any job newer than it; if the engine cannot be read the pass prunes nothing. Never pruned: a job not finished, the latest job of an environment, watermarks, revocations and new-head records, the newest 100 boot epochs, and the audit trail. Each pass first queues the TTL teardowns (`PREVIEWD_ENV_TTL`) and ends with an image prune (below).

**Disk (V1 F5, V1-I9).** Images previewd built (both ownership labels, tagged at most `<env>:latest`) whose environment is neither on the host nor deploying are removed after every teardown and at the end of every maintenance pass, never forced: an image a container uses stays. The daemon's whole unused build cache is pruned after every build, successful or not, before the next build can take the slot; a prune that fails is retried before the next build, which does not run while it fails. Build directories (`previewd-build-*` in the temporary directory) that a crash left behind and that the daemon's user owns are removed by the startup sweep.

The database is at schema version 3. The first start of this version migrates a version-2 file in one transaction, then converts it once to incremental `auto_vacuum` with a `VACUUM` (temporary disk space up to the database size); the daemon refuses to start if either fails.

## Audit Trail

Every authorization decision (approval granted or revoked, trusted or untrusted deploy and its approver, refusal, re-validation teardown, full-secrets opt-in) is an `audit_events` row, written in the transaction of the job transition it causes. Rows are append-only (SQLite triggers) and hash-chained: `hash = SHA-256(prev_hash || "previewd-audit-v1\n" || <len>:<column>, … from id to detail)`, 64 zeros before the first row. The table is never pruned.

```bash
previewd audit verify [-db PATH] [-head HASH]   # exit 0: "audit chain intact: N rows, head H"; exit 1: BROKEN
previewd audit export [-db PATH] > audit.jsonl   # verified first; a broken chain writes nothing and exits 1
```

Both open the database read-only (never migrated, this binary's schema version only) and need none of the daemon's keys or credentials; `PATH` defaults to `PREVIEWD_DB_PATH`. They run beside the daemon or on a copy. A chain truncated from the end is still a valid chain: record the head hash outside the host (with each export, in a ticket) and pass it to `-head`, which fails when the chain no longer contains it. Exit 2 is a usage or read error.

## Reconciliation

Workers (`PREVIEWD_MAX_BUILDS`) take the newest queued job of an environment with no job in progress; older queued jobs of that environment are skipped.

- **Authorize (before anything is fetched or built):** the pull request is read from GHES. Trusted (head in the repository, opener with admin, maintain or write) or untrusted with a live approval confirmed on GHES (the approver, by account ID, still listed, their latest review still `APPROVED` on the exact commit, still with write access). The verdict is recorded with the approval it confirmed; if a newer approval was recorded meanwhile, the deploy is requeued and authorized again. Not approved: the previous version is removed and the job waits in `PENDING_APPROVAL` until an approval of its exact commit or a newer push. GHES unavailable: requeued unclassified (30 s doubling to 10 min), after removing a running version whose approval was revoked; after 10 attempts the deploy is parked instead.
- **Deploy:** remove the previous version, fetch the commit (the GHES tarball of exactly that commit, below), pack the build context and run the preflight (a refusal fails the deploy before any engine request), create the internal network, build (in one of `PREVIEWD_MAX_CONCURRENT_BUILDS` slots, only above `PREVIEWD_MIN_FREE_DISK_MIB`, cancelled at `PREVIEWD_BUILD_TIMEOUT`, the build cache pruned after it), stage the secret section of its trust, start the container, publish the route document, commit SUCCESS. Any failure removes everything and records FAILED with the step that failed (`failure`: `fetch`, `preflight`, `build`, `disk_floor`, `stage`, `start`, `route`, `commit`; empty when the previous version, the build directory or the network could not be handled).
- **Re-validation:** every `PREVIEWD_APPROVAL_REVALIDATE_INTERVAL`, each environment whose latest job is a successful deploy is re-checked. A version built trusted needs its PR still trusted (an offboarded opener tears it down, whatever approval exists); one built on an approval needs that approval confirmed again. One no longer authorized gets a teardown at once, its approval revoked in the same transaction; one GHES cannot verify for `PREVIEWD_APPROVAL_REVALIDATE_GRACE` is torn down (fail closed). The grace count is kept in memory: a restart starts a new one.
- **Source fetch (H2, V1-I11):** with the GitHub App (always, in this daemon), `GET /repos/{owner}/{repo}/tarball/{sha}` with a token scoped to the repository, `contents:read` only, revoked after the download. The redirect to the archive is followed only to the GHES host or `codeload.<GHES host>` over https, without the token (the archive URL carries its own short-lived credential, never logged). The archive is streamed through a cap (`PREVIEWD_MAX_BUILD_CONTEXT_MIB`, compressed and extracted alike, 100,000 entries) and extracted under the build directory through `os.Root`: its pax header must name the commit; only directories, regular files (0644, or 0755 when executable, never setuid) and symlinks whose relative target stays inside the tree are written; an absolute or non-clean name, `..`, an entry outside the archive's top directory, a hard link, a device, a FIFO or a duplicate refuses the whole fetch (`failure = 'fetch'`). The directory is then packed into the build context, which checks every symlink again, and preflighted. Without an App, `git fetch --depth=1 origin <sha>` and `git checkout FETCH_HEAD`: never a branch, a tag or the history.
- **Teardown:** remove route, container, network, image and staging, then prune the images of every environment gone. A failure requeues it with backoff (1 s doubling to 5 min); a teardown never ends FAILED.
- **TTL:** every maintenance pass, an environment whose running version finished deploying `PREVIEWD_ENV_TTL` ago, or whose latest intent has been parked for an approval since it was created that long ago, with nothing newer recorded, gets an internal teardown.

At every start, before the API listens, the startup sweep runs:

0. Remove the build directories a crash left behind (the daemon's own `previewd-build-*` directories; files, links and other users' entries are left).
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
| Signature check and payload parser never panic; only the exact HMAC is accepted; schema violations are rejected                                                                                                                                                                                 | `internal/validate`  | native fuzzing (`FuzzVerifySignature`, `FuzzParsePullRequest`, `FuzzParseReview`, `FuzzParseApprovers`)                                                  |
| Route swap is atomic (no torn read) and durable (fsync file, rename, fsync dir)                                                                                                                                                                                                                 | `internal/proxy`     | concurrent reader test, call-order test                                                                         |
| Schema holds no BLOB column and no unreviewed column                                                                                                                                                                                                                                            | `internal/store`     | startup check plus drift tests on modernc                                                                       |
| Staging root is really ramfs                                                                                                                                                                                                                                                                    | `internal/secrets`   | real ramfs and tmpfs mounts inside an unprivileged user and mount namespace                                     |
| `mlockall` locks current and future pages, and is refused under a finite limit                                                                                                                                                                                                                  | `internal/hardening` | subprocess tests (the success path needs `RLIMIT_MEMLOCK` unlimited; CI raises it with `prlimit`)               |
| The build preflight never panics; an accepted Dockerfile has only allowed instructions, no syntax directive, no `RUN` flag, no `FROM --platform`, no remote `ADD` source; every refusal of the table tests (one per control) fails closed before any engine request | `internal/orchestrator` | native fuzzing (`FuzzPreflight`), table tests, rig test with a fake engine |
| The startup build probe fails closed: a non-loopback interface, a route, a reply from the probe address; a build cgroup with an unbounded limit or swap, busy before the probe, never holding the probe, or holding a process after it | `internal/hardening`, `internal/orchestrator`, `cmd/previewd` | table tests on fake cgroupfs and route tables, rig with a fake prober and cgroup, wire test of the probe request |
| Leaves import no internal package; layering edges are explicit                                                                                                                                                                                                                                  | `internal/validate`  | `TestPackageLayering`                                                                                           |
| Job queue equals the TLA+ model after every command (enqueue, replay, out-of-order delivery, acquire, deploy and teardown steps with Docker failures, daemon crash, host reboot, stale leases); lock integrity, monotonicity, no orphaned resources; every job completes and the host converges | `internal/store`     | `rapid.StateMachine` (`TestJobStore_StateMachine`), scenario tests per deviation D1 to D3                       |
| V1 store (schema 3) equals the V1 reference model after every command: approvals and revocations in any order, park, classification, revocation, re-validation and TTL teardowns, pruning, crashes; every V1 safety and liveness property of `docs/formal/V1-model.md` holds | `internal/store` | `rapid.StateMachine` (`TestV1Store_StateMachine`, at most 500 runs under `make verify`), V1 mutants on the reference model (`TestV1Model_Mutants`) |
| The audit trail is append-only and any changed, deleted, relinked or forged row breaks the hash chain | `internal/store` | append-only triggers, tamper tests with the triggers dropped |
| Overlapping read/write transactions never surface `SQLITE_BUSY`, with `Prune` and its `incremental_vacuum` running in parallel                                                                                                                                                                                                                                 | `internal/store`     | 16 writers, 4 long readers on two pools and a pruner; controls prove the detector fires without the connection parameters |
| Pruning keeps every verdict (V1-I6): a twin store that is never pruned gives every possible next delivery the same verdict, and every mirrored operation the same result; the latest job, unfinished jobs, host builders and the jobs newer than them survive; no transaction deletes more than the batch; freed pages go back to the file system | `internal/store` | `TestJobStore_StateMachine` with a pruned twin, scenario tests (`maintenance_test.go`), page count on a real file |
| Builds are bounded: at most `PREVIEWD_MAX_CONCURRENT_BUILDS` in flight, a build past `PREVIEWD_BUILD_TIMEOUT` is cancelled and fails its deploy even if the engine then reports success; the prune loop prunes nothing without the host's view | `internal/orchestrator` | rig tests with a fake engine (overlap control, hanging and deadline-ignoring builds, observe failure) |
| Sources (H2, V1-I11): a GHES tarball of the exact commit (pax header), contents:read token revoked after use, redirect only to GHES or codeload over https without the token, never quoted; extraction refuses absolute paths, `..`, foreign top directories, escaping or absolute symlinks, hard links, devices, FIFOs, duplicates and oversize (compressed, extracted, entries); the git fallback runs exactly `fetch --depth=1 origin <sha>` and `checkout FETCH_HEAD` | `internal/vcs` | extraction table (21 refusals), fetch against a fake GHES (13 refusals, each after the API call), recorded git argument vectors via a fake `git` on `PATH`, 12 mutants killed |
| No container output (H1, V1-I10): `Engine.Logs` removed; no `ContainerLogs`, `ContainerAttach` or `ContainerExecAttach` outside tests | `.semgrep/` | Semgrep self-test fixture; the rule finds the removed `DockerEngine.Logs` |
| Disk (V1-I9): no build below the free-disk floor or with the free space unknown (FAILED `disk_floor`, audited); the build cache is pruned after every build and, after a failed prune, before the next one or no build; images of environments neither on the host nor deploying are pruned after teardowns and maintenance passes, never without the host's view; stale build directories go at startup; expired environments and parked deploys get a TTL teardown | `internal/orchestrator`, `internal/store`, `internal/hardening` | rig tests with a fake engine and the fake clock, wire tests of the Docker requests, statfs on a real file system, mutants on each control |

`make check` runs all of these deterministically (fixed rapid seed, fuzz seed corpora). `make verify` runs rapid at 10,000 checks with random seeds, plus each fuzz target for `FUZZTIME`. Namespace tests skip where unprivileged user namespaces are unavailable. `PREVIEWD_REQUIRE_NS_TESTS=1` and `PREVIEWD_REQUIRE_MLOCK_TEST=1` turn those skips into failures, and CI sets both.

Phase 2 is a TLA+ model of the queue design (webhook API, SQLite job queue, reconciler workers, route documents, startup sweep, daemon crash and host reboot) in `docs/formal/previewd.tla`. TLC checks zero secret leakage, no orphaned resources (route documents included), routes only to running containers, monotonic ordering, eventual completion and eventual consistency. The daemon runs this design: `internal/store/jobs.go` and `internal/orchestrator/reconciler.go`. `docs/formal/README.md` has the results, the mutation table and how to run TLC offline.
