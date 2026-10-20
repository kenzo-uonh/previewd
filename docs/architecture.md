# Architecture

How previewd turns a signed pull-request webhook into an isolated, routed preview environment, and how it keeps that state consistent, audited and verified. Configuration keys are described in [configuration.md](configuration.md); host setup is in [deployment.md](deployment.md).

## Contents

- [Request lifecycle](#request-lifecycle)
- [Architecture & Tech Stack](#architecture--tech-stack)
  - [Build isolation (V1 F2)](#build-isolation-v1-f2)
  - [Startup build probe](#startup-build-probe)
  - [Persistence](#persistence)
- [Secret Staging](#secret-staging)
- [Forges](#forges)
- [Webhook Ingestion](#webhook-ingestion)
- [Reconciliation](#reconciliation)
  - [Disk (V1 F5, V1-I9)](#disk-v1-f5-v1-i9)
  - [Startup sweep](#startup-sweep)
- [Compose sidecars](#compose-sidecars-v11-spec-33)
- [Audit Trail](#audit-trail)
- [Formal Verification (Phase 1)](#formal-verification-phase-1)

## Request lifecycle

```text
GitHub Enterprise Server
   │ signed webhook (TLS, allowed source)
   ▼
API handler ─── HMAC signature · payload schema · ordering · replay check
   │
   ▼
SQLite job queue ─── authorization decisions audited in the job's transaction
   │
   ▼
Reconciler worker (deploy)
   ├─ authorize against GHES (trusted, or approved on the exact commit)
   ├─ remove the previous version
   ├─ fetch the commit tarball (scoped token, revoked after use)
   ├─ pack the build context · Dockerfile preflight · compose file validation (when enabled)
   ├─ create the internal network (no default route)
   ├─ build (BuildKit, networkmode=none, bounded cgroup)
   ├─ stage secrets on ramfs · bind-mount read-only
   ├─ start the sidecars (compose), then the application container
   └─ publish the route document ──▶ Traefik (file provider)

PR closed ──▶ teardown: route, containers, network, volumes, image, staging
```

Each step is detailed in [Webhook Ingestion](#webhook-ingestion) and [Reconciliation](#reconciliation).

## Architecture & Tech Stack

- **Core Daemon:** Statically compiled Go 1.27.2+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
- **Orchestration:** Docker API (`github.com/moby/moby/client`).
  - Each environment runs on its own internal bridge network (no default route, no egress), shared only with the Traefik container.
  - PR containers run with every capability dropped, `no-new-privileges`, a read-only root file system with no writable mount (no tmpfs), a memory limit without swap and a task limit.
  - An application that must write at run time is not supported yet. Compose sidecars are the one exception, see [Compose sidecars](#compose-sidecars-v11-spec-33).
- **Ingress & Routing:** Traefik with the file provider only.
  - previewd writes one route document per environment into `PREVIEWD_ROUTES_DIR` and removes it at teardown.
  - Traefik has no Docker socket and reads no container label, so nothing in a PR image can add or change a route.
  - Its entry point listens only on its fixed `previewd-proxy` address, never on the environment networks it joins, so a PR container cannot reach other environments through it.
  - previewd refuses to start if the Traefik container mounts a socket, enables the Docker provider, is privileged or is not running.
- **Build isolation (V1 F2):** see [below](#build-isolation-v1-f2).
- **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery (see [Persistence](#persistence)).
- **Security Context:**
  - Secrets are loaded into memory from a local secrets file, split per repository and per trust level (`[owner/repo]`, `[owner/repo:untrusted]`).
  - For each environment, the section of its trust is staged on a host ramfs directory (`/run/previewd/secrets/<env-id>/`, one file per key) and bind-mounted read-only into the container at `/run/secrets`.
  - They never pass through container environment variables, the Docker API, `docker inspect`, image layers or disk.

### Build isolation (V1 F2)

Before any request reaches the engine, previewd:

1. Packs the checkout into a tar (at most `PREVIEWD_MAX_BUILD_CONTEXT_MIB`; files, directories and symlinks that resolve inside the context only).
2. Runs a Dockerfile preflight on the daemon's own parser (BuildKit v0.33.1, the version Docker 29.8.2 embeds). It refuses:
   - a `FROM` not in `PREVIEWD_ALLOWED_BASE_IMAGES` after `ARG` substitution;
   - `FROM --platform`;
   - `ADD` of a URL, git source or variable;
   - `# syntax=`;
   - every `RUN` flag (`--network`, `--mount`, `--security`, `--device`);
   - `COPY --from` an image;
   - `ONBUILD`;
   - and anything it does not recognize.

The build itself is BuildKit with:

- `networkmode=none` (forced on every `RUN`);
- no cache;
- intermediate containers removed even on failure;
- no build argument, session or per-build limit;
- its outcome read from the response stream (an HTTP 200 carrying an error is a failed build).

Secrets are never part of a build: they are staged after it. At every start, before the startup sweep, a probe build proves the isolation (see [Startup build probe](#startup-build-probe)) and the daemon refuses to start if it fails.

### Startup build probe

`previewd build-probe -addr IP:PORT` runs inside the probe build's only `RUN` step (`FROM scratch`, the previewd binary itself, the request PR builds get).

- It exits 0 only if every interface is loopback, no IPv4 route and no IPv6 route off `lo` exists, and the TCP connection fails as unreachable; then it stays alive 3 s so the daemon sees it in `PREVIEWD_BUILDKIT_CGROUP`.
- Exit codes:

  | Exit | Cause |
  |------|-------|
  | 3 | an interface |
  | 4 | a route |
  | 5 | the address answered, refused or timed out |

The target address is [`PREVIEWD_BUILD_PROBE_ADDR`](configuration.md#previewd_build_probe_addr).

### Persistence

The database is at schema version 4. The first start of this version migrates an older file one version at a time, each in its own transaction; from version 2 it then converts the file once to incremental `auto_vacuum` with a `VACUUM` (temporary disk space up to the database size); the daemon refuses to start if either fails. Version 4 (GitLab approvals) rebuilds `approvals` and `audit_events` to admit the `approval` path: every row of the hash-chained trail keeps its bytes and hash, and the append-only triggers are created again.

## Secret Staging

Secrets reach a preview container only as read-only files:

1. At deploy, previewd writes each key to `$PREVIEWD_SECRETS_STAGING_DIR/<env-id>/<KEY>`. Directories are `0555` and files `0444`. Keys must match `[A-Za-z_][A-Za-z0-9_]*`, and a bad key refuses the job before anything is written.
2. The container gets that directory at `/run/secrets` as a `bind` mount with `ReadOnly`, `rprivate` propagation and no recursion. Its config holds no secret, so `docker inspect` and the daemon's on-disk container state show only the host path.
3. Teardown (PR closed) removes the route document, then the container, then the staged directory; each step runs even when an earlier one fails. A failed deploy removes its staging too, and the startup sweep removes staging no kept environment owns.

The staging root lives in memory and must be mounted before starting previewd ([deployment step 4](deployment.md#4-mount-the-secrets-staging-root-ramfs)). ramfs is never swapped. A reboot discards it, together with every staged secret.

## Forges

A forge is a `vcs.Provider` (`internal/vcs/vcs.go`): `Name`, `VerifyWebhook` (authenticates a request against the secret and returns its body, at most 1 MiB), `ParseEvent`, `FetchTarball`, `GetMRState` (open, head commit, trusted) and `GetApprovals`. The daemon serves one (`PREVIEWD_VCS_PROVIDER`). `vcs.Client` (the GitHub App) and `vcs.GitLab` implement it; `vcs.Authorized` matches approvals to `PREVIEWD_APPROVERS` by account ID.

| | GitHub (GHES, github.com) | GitLab (Self-Managed, gitlab.com) |
|---|---|---|
| Route | `POST /webhooks/github` | `POST /webhooks/gitlab` |
| Authentication | `X-Hub-Signature-256`, HMAC-SHA256 of the body | `X-Gitlab-Token`, the shared secret, compared in constant time (digests, `subtle.ConstantTimeCompare`) |
| Event | `X-GitHub-Event: pull_request`, `pull_request_review` | `X-Gitlab-Event: Merge Request Hook` |
| Replay key | `X-GitHub-Delivery` (UUIDv1) and the body's digest | `X-Gitlab-Event-UUID` (body digest when absent) and the body's digest |
| Order of intents | the delivery UUID's time | the instant the hook is received |
| API credential | installation token per read, scoped, revoked | access token in `PRIVATE-TOKEN`, read only |
| Trusted | head in the repository, opener can write | head in the project, author an active member with Developer or more |
| Approval | a review (or label), bound to its `commit_id` | `approved` / `unapproved` hooks; bound to the head the hook named, confirmed on GitLab at each use (`Approval.CommitSHA` is empty) |

GitLab ingestion shares the pull request path of GitHub from the decoded event on (signed window, environment ID, enqueue). `cmd/previewd/forge.go` wires the forge the daemon serves: `orchestrator.GitLabAuthorizer` is its deploy gate and `vcs.GitLabFetcher` its source fetch (the store keeps a project by path, GitLab is addressed by ID, so the path is resolved at each use). Approvals are recorded and confirmed as described in [Configuration: GitLab](configuration.md#gitlab).

## Webhook Ingestion

0. **Transport:** TLS 1.2+ from an allowed source (`PREVIEWD_WEBHOOK_ALLOWED_CIDRS`, checked before the body is read).
1. **Signature:** the body is read up to 1 MiB (larger bodies get 413, never truncated). It must carry `X-Hub-Signature-256: sha256=<64 lowercase hex>`, equal to HMAC-SHA256 of the raw body under the webhook secret (the `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL` credential). Anything else gets 401.
2. **Schema:**
   - `pull_request` bodies need, for every action, `closed` included:
     - `action`;
     - `number` (1 to 2^32-1);
     - `pull_request.head.ref` (git ref rules);
     - `pull_request.head.sha` (40 or 64 lowercase hex);
     - `pull_request.head.repo` (`null` for a deleted fork, otherwise with `full_name`);
     - `pull_request.user` and `sender` (login and numeric ID);
     - `pull_request.updated_at` (RFC 3339);
     - `repository.full_name` (`owner/repo`);
     - `repository.clone_url` (absolute, no credentials).

     `labeled` and `unlabeled` also need `label.name`.
   - `pull_request_review` bodies need the same pull request fields (`pull_request.number`) and the review's `id`, `user`, `commit_id`, `state`, and `submitted_at` when submitted.
   - The head repository and the opener are recorded with the job; trust is never decided from them.
   - Acted on: `opened`, `reopened`, `synchronize`, `closed`, the approval label (below), and an approver's review that approves, requests changes or is dismissed. Other well-formed events and actions get 202 and are ignored.
3. **Environment ID:** `pr-<number>-<10 hex of SHA-256(repo, head branch)>`. The same PR number in two repositories, or on two branches, never shares an environment.
4. **Ordering:** `X-GitHub-Delivery` must be a canonical UUID version 1 (RFC 4122 variant). Its embedded timestamp, in 100-nanosecond intervals, orders the intents of one environment.
   - Anything else gets 400, and so does a timestamp more than 5 minutes ahead of the host's clock. GitHub does not sign that header, and one forged far-future ID would otherwise make every later event of the environment stale.
   - Ordering relies on the clock of the GitHub Enterprise Server that minted the IDs; keep it and the previewd host on NTP.
5. **Signed time (V1-I7):** the GUID's time must lie within 5 minutes before and `PREVIEWD_DELIVERY_MAX_AGE` after the time the signed body carries (`pull_request.updated_at`; `review.submitted_at` for a submitted review). A body captured and resent later under a fresh GUID falls outside it.
   - A delivery that would deploy or approve is refused there (400).
   - One that only restricts (`closed`, a change request, a dismissal, a label removal) is processed and logged, since it can only remove.
6. **Approvals:**
   - An approver (`PREVIEWD_APPROVERS`, matched on the account ID) approves the exact head commit with a review, or, with `PREVIEWD_LABEL_APPROVAL=1`, by adding `PREVIEWD_APPROVAL_LABEL`.
   - A change request by an approver, the dismissal of an approver's review, or the removal of the label (by anyone) revokes the approvals of that commit.
   - Approvals and revocations are recorded with their delivery (replay-checked like any other) and an audit row, in any arrival order.
   - Each is judged against GHES read in the same request: the environment is trusted when its head lives in the repository and its opener has write access (a trusted environment is not torn down by a revocation: it needed no approval), and an approval queues a deploy only when its commit is the open head now.
   - When GHES cannot be read, an approval queues no deploy and a revocation is judged as for an untrusted environment.
7. **Queue:** one SQLite transaction records the delivery (`internal/store/jobs.go`).
   - A delivery whose GUID or whose body (SHA-256) was already recorded is a duplicate (200). The body check matters because the header is unsigned, so a captured body resent under a new GUID is still refused.
   - A delivery not newer than every job of its environment, whatever that job's status, and than its watermark (the highest seq of pruned jobs), is stale (202, nothing queued).
   - Otherwise a job is queued (202) and a worker woken. `opened`, `reopened` and `synchronize` queue a deploy, `closed` a teardown.
   - An accepted deploy also revokes, in the same transaction, the approvals of every other commit of the pull request (V1 approval gating, `docs/specs/V1-previewd.md`).

Retention of deliveries and jobs is set by [`PREVIEWD_RETENTION`](configuration.md#previewd_retention); environment expiry by [`PREVIEWD_ENV_TTL`](configuration.md#previewd_env_ttl).

## Reconciliation

Workers (`PREVIEWD_MAX_BUILDS`) take the newest queued job of an environment with no job in progress; older queued jobs of that environment are skipped.

### Authorize (before anything is fetched or built)

The pull request is read from GHES.

- **Allowed:** trusted (head in the repository, opener with admin, maintain or write) or untrusted with a live approval confirmed on GHES (the approver, by account ID, still listed, their latest review still `APPROVED` on the exact commit, still with write access).
- The verdict is recorded with the approval it confirmed; if a newer approval was recorded meanwhile, the deploy is requeued and authorized again.
- **Not approved:** the previous version is removed and the job waits in `PENDING_APPROVAL` until an approval of its exact commit or a newer push.
- **GHES unavailable:** requeued unclassified (30 s doubling to 10 min), after removing a running version whose approval was revoked; after 10 attempts the deploy is parked instead.

### Deploy

1. Remove the previous version.
2. Fetch the commit (the GHES tarball of exactly that commit, see [Source fetch](#source-fetch-h2-v1-i11)).
3. Pack the build context and run the preflight, then validate the compose file when [compose sidecars](#compose-sidecars-v11-spec-33) are enabled (a refusal fails the deploy, `failure = 'preflight'`, before any engine request).
4. Create the internal network.
5. Build (the deploy holds one of `PREVIEWD_MAX_CONCURRENT_BUILDS` slots from its lease, taken without waiting: with none free it is requeued unclassified and teardowns run; only above `PREVIEWD_MIN_FREE_DISK_MIB`, cancelled at `PREVIEWD_BUILD_TIMEOUT`, the build cache pruned after it).
6. Stage the secret section of its trust.
7. Start the containers: with a compose file, the sidecars first (images verified on the host, volumes created), then the application.
8. Publish the route document.
9. Commit SUCCESS.

Any failure removes everything and records FAILED with the step that failed (`failure`: `fetch`, `preflight`, `build`, `disk_floor`, `stage`, `start`, `route`, `commit`; empty when the previous version, the build directory or the network could not be handled).

### Re-validation

Every `PREVIEWD_APPROVAL_REVALIDATE_INTERVAL`, each environment whose latest job is a successful deploy is re-checked.

- A version built trusted needs its PR still trusted (an offboarded opener tears it down, whatever approval exists); one built on an approval needs that approval confirmed again.
- One no longer authorized gets a teardown at once, its approval revoked in the same transaction.
- One GHES cannot verify for `PREVIEWD_APPROVAL_REVALIDATE_GRACE` is torn down (fail closed). The grace count is kept in memory: a restart starts a new one.

### Source fetch (H2, V1-I11)

With the GitHub App (always, in this daemon):

- `GET /repos/{owner}/{repo}/tarball/{sha}` with a token scoped to the repository, `contents:read` only, revoked after the download.
- The redirect to the archive is followed only to the GHES host or `codeload.<GHES host>` over https, without the token (the archive URL carries its own short-lived credential, never logged).
- The archive is streamed through a cap (`PREVIEWD_MAX_BUILD_CONTEXT_MIB`, compressed and extracted alike, 100,000 entries) and extracted under the build directory through `os.Root`:
  - its pax header must name the commit;
  - only directories, regular files (0644, or 0755 when executable, never setuid) and symlinks whose relative target stays inside the tree are written;
  - an absolute or non-clean name, `..`, an entry outside the archive's top directory, a hard link, a device, a FIFO or a duplicate refuses the whole fetch (`failure = 'fetch'`).
- The directory is then packed into the build context, which checks every symlink again, and preflighted.

Without an App, `git fetch --depth=1 origin <sha>` and `git checkout FETCH_HEAD`: never a branch, a tag or the history.

With GitLab (`vcs.GitLab.FetchTarball`): `GET /api/v4/projects/{id}/repository/archive.tar.gz?sha={sha}` by the numeric project ID, authenticated by the access token in `PRIVATE-TOKEN`. GitLab serves the archive itself: a redirect is refused, so the token cannot reach another host. The same cap and the same extraction apply (`git archive` writes the same pax header naming the commit).

### Teardown

Remove route, every container of the environment (application and sidecars, by ownership label), network, named volumes, image and staging, then prune the images of every environment gone. A failure requeues it with backoff (1 s doubling to 5 min); a teardown never ends FAILED.

### TTL

Every maintenance pass, an environment whose running version finished deploying `PREVIEWD_ENV_TTL` ago, or whose latest intent has been parked for an approval since it was created that long ago, with nothing newer recorded, gets an internal teardown.

### Disk (V1 F5, V1-I9)

- Images previewd built (both ownership labels, tagged at most `<env>:latest`) whose environment is neither on the host nor deploying are removed after every teardown and at the end of every maintenance pass, never forced: an image a container uses stays.
- The daemon's whole unused build cache is pruned after every build, successful or not, before the next build can take the slot; a prune that fails is retried before the next build, which does not run while it fails.
- Build directories (`previewd-build-*` in the temporary directory) that a crash left behind and that the daemon's user owns are removed by the startup sweep.

The free-disk floor, the data root and the maintenance loop are configured in [Storage, retention and cleanup](configuration.md#storage-retention-and-cleanup).

### Startup sweep

At every start, before the API listens, the startup sweep runs:

0. Remove the build directories a crash left behind (the daemon's own `previewd-build-*` directories; files, links and other users' entries are left).
1. Inventory the host: containers (sidecars included), networks and named volumes previewd owns (`previewd.env` label, or the environment name for resources created before labels), staging directories, route documents.
2. Garbage-collect the routes directory. Crash debris from an interrupted write and any `.yml`, `.yaml` or `.toml` file that is not the route document of a valid environment ID are deleted. A directory or symlink there refuses the start.
3. Sweep the queue against that inventory.
   - An environment is kept only if it is complete (application container running, network, staged secrets, route document) and built by the newest executed job, a SUCCESS deploy.
   - An interrupted deploy becomes FAILED and an interrupted teardown is queued again.
   - A latest SUCCESS deploy whose environment is gone (a reboot wiped its secrets, its route was lost) is queued again.
4. Destroy everything else.
5. Check that every remaining route document belongs to a kept environment.

Any error refuses the start. A route document therefore exists only while the database records the environment as deployed.

## Audit Trail

Every authorization decision (approval granted or revoked, trusted or untrusted deploy and its approver, refusal, re-validation teardown, full-secrets opt-in) is an `audit_events` row, written in the transaction of the job transition it causes.

- Rows are append-only (SQLite triggers) and hash-chained: `hash = SHA-256(prev_hash || "previewd-audit-v1\n" || <len>:<column>, … from id to detail)`, 64 zeros before the first row.
- The table is never pruned.

```bash
previewd audit verify [-db PATH] [-head HASH]   # exit 0: "audit chain intact: N rows, head H"; exit 1: BROKEN
previewd audit export [-db PATH] > audit.jsonl   # verified first; a broken chain writes nothing and exits 1
```

- Both open the database read-only (never migrated, this binary's schema version only) and need none of the daemon's keys or credentials; `PATH` defaults to `PREVIEWD_DB_PATH`.
- They run beside the daemon or on a copy.
- A chain truncated from the end is still a valid chain: record the head hash outside the host (with each export, in a ticket) and pass it to `-head`, which fails when the chain no longer contains it.
- Exit 2 is a usage or read error.

## Formal Verification (Phase 1)

| Invariant | Where | How |
|-----------|-------|-----|
| Environment ID is an RFC 1123 label (at most 63 chars), recovers its PR number, is deterministic, separates repositories | `internal/envid` | rapid properties over arbitrary strings and bytes |
| `Sanitize` is idempotent and outputs only `[a-zA-Z0-9-]` | `internal/textutil` | rapid properties |
| Route documents decode with `gopkg.in/yaml.v3` (Traefik's parser) and as strict JSON; merged routes send each host only to its own backend | `internal/proxy` | rapid properties |
| Signature check and payload parser never panic; only the exact HMAC is accepted; schema violations are rejected | `internal/validate` | native fuzzing (`FuzzVerifySignature`, `FuzzParsePullRequest`, `FuzzParseReview`, `FuzzParseApprovers`) |
| Route swap is atomic (no torn read) and durable (fsync file, rename, fsync dir) | `internal/proxy` | concurrent reader test, call-order test |
| Schema holds no BLOB column and no unreviewed column | `internal/store` | startup check plus drift tests on modernc |
| Staging root is really ramfs | `internal/secrets` | real ramfs and tmpfs mounts inside an unprivileged user and mount namespace |
| `mlockall` locks current and future pages, and is refused under a finite limit | `internal/hardening` | subprocess tests (the success path needs `RLIMIT_MEMLOCK` unlimited; CI raises it with `prlimit`) |
| The build preflight never panics; an accepted Dockerfile has only allowed instructions, no syntax directive, no `RUN` flag, no `FROM --platform`, no remote `ADD` source; every refusal of the table tests (one per control) fails closed before any engine request | `internal/orchestrator` | native fuzzing (`FuzzPreflight`), table tests, rig test with a fake engine |
| The startup build probe fails closed: a non-loopback interface, a route, a reply from the probe address; a build cgroup with an unbounded limit or swap, busy before the probe, never holding the probe, or holding a process after it | `internal/hardening`, `internal/orchestrator`, `cmd/previewd` | table tests on fake cgroupfs and route tables, rig with a fake prober and cgroup, wire test of the probe request |
| Leaves import no internal package; layering edges are explicit | `internal/validate` | `TestPackageLayering` |
| Job queue equals the TLA+ model after every command (enqueue, replay, out-of-order delivery, acquire, deploy and teardown steps with Docker failures, daemon crash, host reboot, stale leases); lock integrity, monotonicity, no orphaned resources; every job completes and the host converges | `internal/store` | `rapid.StateMachine` (`TestJobStore_StateMachine`), scenario tests per deviation D1 to D3 |
| V1 store (the schema 3 model; schema 4 adds one approval path, covered by `TestMergeRequestApprovalGrantsTheCommitItNamed` and `TestMigrateSchema3ToGitLabApprovals`) equals the V1 reference model after every command: approvals and revocations in any order, park, classification, revocation, re-validation and TTL teardowns, pruning, crashes; every V1 safety and liveness property of `docs/formal/V1-model.md` holds | `internal/store` | `rapid.StateMachine` (`TestV1Store_StateMachine`, at most 500 runs under `make verify`), V1 mutants on the reference model (`TestV1Model_Mutants`) |
| The audit trail is append-only and any changed, deleted, relinked or forged row breaks the hash chain | `internal/store` | append-only triggers, tamper tests with the triggers dropped |
| Overlapping read/write transactions never surface `SQLITE_BUSY`, with `Prune` and its `incremental_vacuum` running in parallel | `internal/store` | 16 writers, 4 long readers on two pools and a pruner; controls prove the detector fires without the connection parameters |
| Pruning keeps every verdict (V1-I6): a twin store that is never pruned gives every possible next delivery the same verdict, and every mirrored operation the same result; the latest job, unfinished jobs, host builders and the jobs newer than them survive; no transaction deletes more than the batch; freed pages go back to the file system | `internal/store` | `TestJobStore_StateMachine` with a pruned twin, scenario tests (`maintenance_test.go`), page count on a real file |
| Builds are bounded: at most `PREVIEWD_MAX_CONCURRENT_BUILDS` in flight, a build past `PREVIEWD_BUILD_TIMEOUT` is cancelled and fails its deploy even if the engine then reports success; the prune loop prunes nothing without the host's view | `internal/orchestrator` | rig tests with a fake engine (overlap control, hanging and deadline-ignoring builds, observe failure, teardown not blocked by saturated slots) |
| Sources (H2, V1-I11): a GHES tarball of the exact commit (pax header), contents:read token revoked after use, redirect only to GHES or codeload over https without the token, never quoted; extraction refuses absolute paths, `..`, foreign top directories, escaping or absolute symlinks, hard links, devices, FIFOs, duplicates and oversize (compressed, extracted, entries); the git fallback runs exactly `fetch --depth=1 origin <sha>` and `checkout FETCH_HEAD` | `internal/vcs` | extraction table (21 refusals), fetch against a fake GHES (13 refusals, each after the API call), recorded git argument vectors via a fake `git` on `PATH`, 12 mutants killed |
| No container output (H1, V1-I10): `Engine.Logs` removed; no `ContainerLogs`, `ContainerAttach` or `ContainerExecAttach` outside tests | `.semgrep/` | Semgrep self-test fixture; the rule finds the removed `DockerEngine.Logs` |
| Disk (V1-I9): no build below the free-disk floor or with the free space unknown (FAILED `disk_floor`, audited); the build cache is pruned after every build and, after a failed prune, before the next one or no build; images of environments neither on the host nor deploying are pruned after teardowns and maintenance passes, never without the host's view; stale build directories go at startup; expired environments and parked deploys get a TTL teardown | `internal/orchestrator`, `internal/store`, `internal/hardening` | rig tests with a fake engine and the fake clock, wire tests of the Docker requests, statfs on a real file system, mutants on each control |

`make check` runs all of these deterministically (fixed rapid seed, fuzz seed corpora). `make verify` runs rapid at 10,000 checks with random seeds, plus each fuzz target for `FUZZTIME`. Namespace tests skip where unprivileged user namespaces are unavailable. `PREVIEWD_REQUIRE_NS_TESTS=1` and `PREVIEWD_REQUIRE_MLOCK_TEST=1` turn those skips into failures, and CI sets both.

Phase 2 is a TLA+ model of the queue design (webhook API, SQLite job queue, reconciler workers, route documents, startup sweep, daemon crash and host reboot) in `docs/formal/previewd.tla`. TLC checks zero secret leakage, no orphaned resources (route documents included), routes only to running containers, monotonic ordering, eventual completion and eventual consistency. The daemon runs this design: `internal/store/jobs.go` and `internal/orchestrator/reconciler.go`. `docs/formal/README.md` has the results, the mutation table and how to run TLC offline.

## Compose sidecars (V1.1 spec 3.3)

Opt-in (`PREVIEWD_COMPOSE_ENABLED=1`, see [Configuration](configuration.md#compose-sidecars-previewd_compose_enabled-and-previewd_compose_max_services)). The compose file is read from the extracted checkout (`os.Root`, a regular file of at most 256 KiB, never a link), parsed with `gopkg.in/yaml.v3` and validated by `orchestrator.ParseCompose` after the Dockerfile preflight and before the first request that changes the host. It accepts a small subset and refuses everything else: a key not listed below is a refusal, not an ignored setting.

**Services.** At most `PREVIEWD_COMPOSE_MAX_SERVICES`, named as DNS labels. Exactly one builds (`build: .` or `build: {context: .}`): that is the application, built from the root Dockerfile with the locked request every PR build gets; its `image`, if any, is not used. Every other service is a sidecar with an `image` from `PREVIEWD_ALLOWED_BASE_IMAGES`, no `build`.

**Accepted keys.** `image`, `build`, `environment` (map or `KEY=value` list; literal values, no inheritance from the host, no `${…}`; at most 64 variables of 4 KiB), `command` (list form), `volumes`, `depends_on` (names must exist; start order is fixed, sidecars first, and conditions are not read), `ports`, `expose`, `restart` (the last three are dropped, see below). At the top level: `services`, `volumes`, and the ignored `version` and `name`. Anything else (`privileged`, `network_mode`, `pid`, `ipc`, `cap_add`, `devices`, `security_opt`, `env_file`, `volumes_from`, `user`, `entrypoint`, `healthcheck`, top-level `networks`, `secrets`, `configs`) refuses the file. Duplicate keys, aliases that expand excessively and more than one YAML document are refused.

**Storage.** Named volumes only, each declared at the top level without any option (a driver, a driver option or `external` could turn it into a host bind mount) and named as a DNS label. A host path (`/…`, `./…`, `../…`, `~…`, anything with a slash), a `bind` or `tmpfs` mount, an anonymous volume, a mode other than `ro`/`rw` and a target that is not a clean absolute path, or is under `/run/secrets`, `/proc`, `/sys` or `/dev`, are refused. The daemon-wide volume name is `previewd-<env-id>-<name>`; it is created on the plain `local` driver with the ownership labels. A volume of that name that already exists is reused only if it carries this environment's label, uses `local` and has no option.

**Network and ingress.** Every container of the environment attaches to the environment's internal bridge network only (`<env-id>-net`, the existing name) and answers to its service name there, so `postgres` resolves from the application. `ports` and `expose` are counted and dropped (the count is logged): nothing is published, and the network has no route out. The route document points to the application container only; the proxy joins the network as before.

**Sidecar containers.** Same as the application's (all capabilities dropped, `no-new-privileges`, read-only root file system, memory limit without swap, task limit, `system.slice` cgroup parent, ownership labels `previewd.env` and `previewd.job`) with three differences:

- they get **no secrets mount**; only the application receives the read-only ramfs directory;
- they get `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID` and `SETUID` back: the official database and cache images start as root to own their data directory and drop to their own user. Nothing else;
- they get two bounded tmpfs (`/tmp`, `/run`, 64 MiB each, `nosuid`, `nodev`), and their named volumes, as their only writable state.

**Images.** Before any volume or container is created, each sidecar image is inspected on the host: the local `name:tag` must be the pinned digest and carry no `ONBUILD` trigger (the checks of the base images at start). The container then runs the verified image ID, so a tag moved afterwards changes nothing. A missing image fails the deploy (`failure = 'start'`); there is no pull.

**Lifecycle.** `Engine.Deploy` verifies the images, creates the volumes, creates and starts the sidecars, then creates and starts the application, joins the proxy and returns the application's address. `Engine.Destroy` removes every container labelled `previewd.env=<env-id>` (and the container named `<env-id>`, for resources that predate labels), the network, every volume labelled `previewd.env=<env-id>`, then the image, in that order: a network or a volume in use cannot be removed. `Engine.Observe` counts all the containers and volumes of an environment, but reports it `Running` only when its application container runs: a sidecar alone does not keep an environment alive. A volume with no container (a crash after it was created) is an environment the startup sweep destroys.

**What it does not do.** No readiness wait (the application must retry its connection to a sidecar that is still starting), no seeding, no per-service resource limits, no sidecar reachable from outside the environment.

## Developer feedback (V1.1 spec 3.3)

The reconciler reports each deploy through `orchestrator.Feedback` (`*vcs.Notifier` in the daemon; nil when `PREVIEWD_FEEDBACK=0`): `Begin` after the deploy is authorized and before anything is built, `Succeed` after the database records SUCCESS, `Fail` after the rollback, with the step that failed. Each call runs on a context detached from the job and bounded to 10 s; its error is logged at warn in one place (`Reconciler.notify`) and dropped, so feedback cannot fail, delay or roll back a deploy.

`Provider.SetCommitStatus` and `Provider.PostComment` implement it per forge. The comment is the one sticky object: the driver lists the thread, takes the comment that starts with `<!-- previewd-status -->` **and was written by its own credential** (GitHub: `performed_via_github_app.id`; GitLab: the author of `GET /user`, user notes only), skips the write when the body is unchanged, updates it in place otherwise, and creates it when none exists. GitHub writes mint a token scoped to one repository and one permission at write level (`statuses`, `pull_requests`), revoked after use; `checkGrant` still refuses any grant other than the level requested.
