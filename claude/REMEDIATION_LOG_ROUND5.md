# Remediation log, round 5 (V1 phases E to H)

Date: 2026-10-10. Branch: `v1`. Sources: the `eaas-security-review` passes and engine probes recorded in `docs/specs/V1-previewd.md` (section 1.4, phase statuses of section 4, section 5). Rounds 1 to 4 belong to another branch lineage and are not in this tree.

Commits: c1d0496 (E0 to E2), 0d4f6f0 (E2b probe, E3, D-V1-2 decision), e0b2c26 (E2b bounds, F1 to F3), a494c1d (G1 to G3), fe08d2b (G leftovers, H1, H2).

| # | Severity | Source | Finding | Status |
|---|---|---|---|---|
| R5-1 | LOW | Review of G2 | Image and cache prunes had no deadline: a hung daemon blocked every deploy | Fixed |
| R5-2 | MEDIUM | E0 probe | `pull=0` does not keep the engine off the registry | Decided (D-V1-2); verification open |
| R5-3 | MEDIUM | H1, CI run | Container output reachable; Semgrep timeouts reported as 0 findings | Fixed |
| R5-4 | LOW | Review of H2 | Archive host check compared ports literally (`:443` vs none) | Fixed |
| R5-5 | MEDIUM | G3 (second commit) | `PENDING_APPROVAL` deploys never expired | Fixed |
| R5-6 | MEDIUM | F3 test under `-race` | Back-to-back prune batches starved writers (`SQLITE_BUSY`) | Fixed |
| R5-7 | LOW | F2 SPBT | Pruning a skipped job changed the startup sweep's verdict | Fixed |
| R5-8 | MEDIUM | E2b | Builds unbounded in number and duration | Fixed |
| R5-9 | MEDIUM | E2b review | A worker waiting for a build slot keeps its lease | Open |
| R5-10 | MEDIUM | E2b review | The egress filter is not verified at start | Open |

## R5-1: Docker API prune timeout

- **Finding:** the image prune holds the in-flight mutex (`deployMu`) across `Engine.Observe` and `Engine.PruneImages`, and the pre-build cache prune holds `cacheMu` and a build slot. With no deadline, a Docker daemon that stops answering would hold them forever: every deploy waits on `deployMu` to start, so the queue deadlocks.
- **Changed:** `pruneTimeout = 5 * time.Minute` (`internal/orchestrator/reconciler.go`) bounds `pruneImages` and `cleanBuildCache`. The post-build cache prune runs on `cleanupContext` (detached from the job, 2-minute `cleanupTimeout`); the startup free-disk read runs under 10 s.
- **Tests:** none for the bound itself (a constant). The prune paths are covered by the G2 rig tests (observe failure prunes nothing, failed prune refuses the next build).
- **Ops:** none.
- **Still open:** no test proves the timeout fires; a hung prune now fails after 5 minutes instead of never.

## R5-2: egress filter as the registry control (D-V1-2)

- **Finding:** E0 (`scripts/verify-buildkit.sh`, Docker 29.8.2) counted connections at a fake registry on the host bridge. With `pull=0`, a build of a base present locally made 20 connections before falling back to the local image, a missing base 10, and `docker events` showed no `pull`. The engine contacts the base image's registry at every build, from the host network namespace, where neither the build's network mode nor `DOCKER-USER` applies.
- **Changed:**
  - Owner decision (2026-10-09): the host egress filter is the authoritative control for the engine's registry connections.
  - `deployments/docker.service.d/previewd-builds.conf`: `IPAddressDeny=any`, allowing loopback and the proxy subnet `172.30.255.0/24` (and, commented, an internal mirror).
  - `PREVIEWD_ALLOWED_BASE_IMAGES` takes `name:tag@sha256:<64 hex>`; a `FROM` must spell the same tag and digest; at start each entry's local `name:tag` must be the pinned digest without `ONBUILD`.
  - E0's `no-pull` case became `egress-filter`.
- **Deviation:** the first E0 version passed `no-pull` on a missing base because the error said `not found` and `docker events` showed no pull; counting connections showed the access. `docker events` is not evidence of registry access.
- **Tests:** E0 cases `offline-base`, `digest-enforced` (pass on 29.8.2), `egress-filter` (fails without a filter, as it must); config tables for the image format; startup base-image check.
- **Breaking:** `PREVIEWD_ALLOWED_BASE_IMAGES` in `name@sha256` form is refused. **Ops:** install the drop-in and load each base under its `name:tag`; behind the filter, environments resolve no DNS name.
- **Still open:** R5-10; the `egress-filter` case has not run on a host with the filter (cgroup v2, systemd driver).

## R5-3: no container output (H1) and strict Semgrep

- **Finding:** `Engine.Logs` / `DockerEngine.Logs` let the core read PR container output, which is PR-controlled and can carry whatever the PR's code prints, staged secrets included (V1-I10). Separately, under load Semgrep timed out on five files and still reported "0 findings" with exit 0, so a timed-out rule passed silently.
- **Changed:** `Engine.Logs` and `DockerEngine.Logs` removed (no caller). `.semgrep/previewd-no-container-output.yaml` bans `ContainerLogs`, `ContainerAttach` and `ContainerExecAttach` (call or method value) outside tests and the rule's fixture. CI and `make semgrep` run both rule files with `--strict --timeout 0`, so a timeout fails the scan.
- **Deviation:** `ContainerExecAttach` added to the draft's two selectors.
- **Tests:** fixture `.semgrep/previewd-no-container-output.go` (four `ruleid`, two `ok`); the self-test runs before the scan; the rule finds the removed `DockerEngine.Logs` in the previous `docker.go`.
- **Ops:** none.

## R5-4: port 443 normalization on the archive redirect (H2)

- **Finding:** `allowedArchiveURL` compared ports literally. A GHES URL without a port and a redirect naming `:443` (or the reverse) was refused. Fail closed, but on such a site every deploy failed at `fetch`.
- **Changed:** `httpsPort` (`internal/vcs/tarball.go`) treats an `https` URL without a port as port 443 on both sides; host must still be the GHES host or `codeload.<GHES host>`, https, no user info.
- **Tests:** a table of 12 archive hosts and one of the default port (443 named or not); 13 fetch refusals against a fake GHES, including redirect to another port.

## R5-5: parked deploys never expired (G3)

- **Finding:** `Store.Expired` returned only running environments, so a fork deploy parked in `PENDING_APPROVAL` stayed forever.
- **Changed:** `Store.Expired` also returns an environment whose latest job is a `PENDING_APPROVAL` deploy created at least `PREVIEWD_ENV_TTL` ago; its TTL teardown supersedes the parked job. TLA+ model: `parkedAt`, `ExpirableParked`.
- **Tests:** `TestExpired`, rig `TestTTLExpiresParkedDeploys`, property `LivenessParkedExpired` in the V1 state machine; mutant V1-M23 and a store mutant killed; E2E section 6 (`PREVIEWD_ENV_TTL=20s`, parked fork audited `ttl_expired`).

## R5-6: prune passes starved writers (F3)

- **Finding:** batches run back to back took the SQLite lock again at once; waiting writers slept in the busy handler and lost every race. `Enqueue` and `Acquire` failed with `SQLITE_BUSY` after the 5 s `busy_timeout`. In production a long pass could fail a webhook's `Enqueue` with a 500 that GitHub does not redeliver.
- **Changed:** `PruneRequest.Yield`, a 150 ms pause before every transaction of a pass but the first.
- **Tests:** concurrency test (16 writers, 4 long readers, a pruner): fails 3 of 3 under `-race` with `Yield = 0`, passes 3 of 3 with 150 ms.
- **Still open:** only a `-race` run catches a regression; `make check` passes either way.

## R5-7: pruning changed the sweep's verdict (F2)

- **Finding:** pruning a `SKIPPED` job newer than a host builder turned the startup sweep's decision from destroy to keep. Not a safety violation (the queued teardown removes the environment), but pruning changed queue behavior.
- **Changed:** `Prune` keeps every job at or above a host builder's seq; the V1 state machine and TLA+ `PrunableJobs` follow.
- **Tests:** `TestPruneKeepsWhatTheSweepReads`; the twin-store SPBT (`TestJobStore_StateMachine`).

## R5-8: bounded builds (E2b)

- **Finding:** BuildKit ignores per-build limits (D-V1-4), concurrent builds were bounded only by the worker count, and a build had no deadline: one PR could hold the engine and the shared build quota.
- **Changed:** `PREVIEWD_MAX_CONCURRENT_BUILDS` (slot shared by every worker, default 1), `PREVIEWD_BUILD_TIMEOUT` (default 20m, request closed, `failure = 'build'`, success after the deadline fails), `previewd-builds.slice` bounds verified at start by the build probe; `PREVIEWD_MAX_BUILDS` malformed values now refused.
- **Tests:** two workers never overlap with one slot (control with two); hanging build cancelled at the timeout; deadline-ignoring success fails; mutants (no semaphore, no timeout, late success accepted) killed; 15 cgroup limit refusals on a fake cgroupfs.
- **Ops:** scale the slice before raising the slot count.

## R5-9 (open): worker lease held while waiting for a build slot

With more workers than slots, one long build can hold every worker, and a revocation or re-validation teardown waits up to `PREVIEWD_BUILD_TIMEOUT` beyond V1-I4's interval. Fix direction: job-type-aware acquisition (a worker kept for teardowns, or teardowns first).

## R5-10 (open): egress filter not verified at start

previewd does not check that dockerd's egress filter is installed and enforced (cgroup v2); the startup probe checks the `RUN` network only. Until it does, the filter is an operator-verified control.

## Not run for this round

- E0 on the production shape (cgroup v2, systemd driver, filter installed): `host`, `egress-filter`, `bound-*`, `cgroupns-hidden`.
- The E2E with ramfs staging (all runs used `E2E_STAGING=tmpfs`).
- `make ghes-conformance` (C4, not written).
- `make e2e` was not re-run for this documentation commit.

## Verification for this round (2026-10-10)

- `make check`: pass. Skipped: the `mlockall` success path (`RLIMIT_MEMLOCK` 64 MiB on this host). govulncheck read the online database.
- `make verify`: pass with `VERIFY_TIMEOUT=240m` (5 rapid packages at 10,000 checks, 6 fuzz targets at 60 s). With the default 60-minute timeout it fails: `internal/store` takes 3,616 s. No property failed; the first run was killed while shrinking a mutant's expected counterexample. Open (LOW): raise the default.
