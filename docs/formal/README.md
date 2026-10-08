# previewd formal model

`previewd.tla` is a PlusCal algorithm, with its TLA+ translation, of previewd's orchestration. Since task A1 it is the V1 model designed in [`V1-model.md`](V1-model.md) (task A0): commit identity, trust from GitHub truth, approval gating, revocation, continuous re-validation of every environment (D-V1-5), expiry and pruning, on top of the MVP queue.

```text
GitHub (truth: head, open, approvals, opener write access) ──signed deliveries, reordered──▶ Api ──1 tx──▶ db_jobs, approvals (SQLite)
                                                                                                │
Workers: AcquireJob ▶ AuthorizeDeploy (trusted | approved | park | GHES fault) ▶ deploy steps ▶ environments
Supervisor: StartupSweep at every start      Revalidator, Expirer: fair previewd loops
Pruner, Chaos (daemon crash, host reboot), GitHub: unfair, bounded
```

The daemon implements the MVP part: `internal/store/jobs.go` (queue transitions) and `internal/orchestrator/reconciler.go` (workers and startup sweep). `TestJobStore_StateMachine` checks the queue against the model after every command (`docs/specs/phase3_spbt_architecture.md`). The V1 part is specified in `docs/specs/V1-previewd.md`. Task A2 extended the state-machine test to it (`internal/store/jobs_spbt_v1*_test.go`, V1-model.md section 8): the Go reference model follows this model rule for rule, and found two design bugs beyond the TLC bounds (V1-model.md section 11), fixed here and pinned by `previewd_a2.tla`.

## Files

| File | Purpose |
|---|---|
| `previewd.tla` | Model, invariants, temporal properties. The block between `BEGIN TRANSLATION` and `END TRANSLATION` is generated: edit the PlusCal, then translate again. |
| `V1-model.md` | Design of the V1 model (A0), the deviations found while implementing it (section 10, A1) and testing it (section 11, A2). |
| `previewd_a2.tla`, `previewd_a2.cfg`, `previewd_a2-trust.cfg` | A2 regression: `RegressionA21` (action) and `RegressionA22` (invariant) name the step and the state that doomed an approved head in the A1 model. Safety only, 2 commits: 5 GitHub actions on a fork PR; the `-trust` variant, a same-repo PR whose opener loses write access, at 4 (at 5 it passed 33 M states without finishing). |
| `previewd.cfg`, `previewd-workers.cfg` | MVP regression: every V1 feature off (trusted environments only, one commit, no permission loss, no GHES fault, no pruning, no expiry). |
| `previewd-approval.cfg` | Approval gate, revocation, new head, GHES faults, approver loses write access. |
| `previewd-reapproval.cfg` | Dismissal then re-approval; approval of the current head with no job waiting. |
| `previewd-approval-reboot.cfg` | Untrusted environment across a reboot: rebuilt only after a fresh authorization. |
| `previewd-mixed.cfg` | Trusted and untrusted environments, 2 workers, opener loses write access (D-V1-5). |
| `previewd-prune.cfg` | Pruning behind the watermark, pruned deliveries. |
| `previewd-ttl.cfg` | Expiry through the queue. |
| `previewd-grace.cfg` | GHES unavailable below the grace limit (`Grace = 2`): recovery resets the count, two consecutive failures tear down. |

## Running TLC offline

TLC needs a JRE (17 or later) and `tla2tools.jar`. Neither is a runtime dependency of previewd. Fetch the jar once on a connected machine, check its digest, and copy it next to the model. `tla2tools.jar` is git-ignored.

Checked with `TLC2 Version 2026.10.06.014338 (rev: 94d0c50)`, `tla2tools.jar` SHA-256 `7beec0f04818732a62fa193731711a99aa4f11279499b2360a7d156c519ea78d` (asset of the `v1.8.0` release of `tlaplus/tlaplus`, which is rebuilt in place: record the digest of the jar you use).

```bash
cd docs/formal
# After editing the PlusCal: regenerate the translation. -nocfg keeps the .cfg files.
# pcal.trans leaves previewd.old (git-ignored).
java -cp tla2tools.jar pcal.trans -nocfg previewd.tla
# Model check every configuration. -lncheck final checks liveness once, on the
# complete state graph: same verdict, several times faster. TLC writes states/
# and, on a violation, *_TTrace_* files: all git-ignored.
for c in previewd previewd-workers previewd-approval previewd-reapproval \
         previewd-approval-reboot previewd-mixed previewd-prune previewd-ttl previewd-grace; do
  java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -lncheck final -config "$c.cfg" previewd.tla
done
# A2 regression (safety only; the module extends previewd).
for c in previewd_a2 previewd_a2-trust; do
  java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config "$c.cfg" previewd_a2.tla
done
```

One TLC at a time on a host with less than 16 GB: on a 7 GB host, four parallel runs with 5 GB heaps were killed (exit 137).

## Checked properties

Every configuration checks every property. The initial state lets each environment hold a stray (container, network, staged secrets, route document) that no job tracks, so the sweep's convergence is checked too. Properties use their own copies of the operators they judge with (`LiveApprovalSpec`, `HasGrant`, `AllowedTruth`, `Running`), so a mutant of the algorithm cannot weaken its own judge.

| Property | Kind | Meaning |
|---|---|---|
| `TypeOK` | invariant | Types and bounds, including the clock and job-ID bounds the properties quantify over |
| `SafetyZeroSecretLeakage` | invariant | No environment's secret bytes ever reach a block device |
| `SafetyNoOrphanedResources` | invariant | After the sweep, every container, network, staged secret or route document belongs to an `IN_PROGRESS`/`SUCCESS` deploy that no newer teardown has undone |
| `SafetyMonotonicity` | invariant | No older intent pending or running once a newer one has executed; a running environment is never older than a completed intent |
| `SafetyUniqueDelivery` | invariant | One job per seq and environment, as `UNIQUE (preview_id, seq)` (A2-3) |
| `SafetyOneJobPerEnv` | invariant | At most one `IN_PROGRESS` job per environment, trusted or not |
| `SafetyLeases` | invariant | A current-epoch lease points at an `IN_PROGRESS` job and is never shared |
| `SafetyRouteImpliesRunning` | invariant | A route document never points at a container that is not running |
| `SafetyNoUnapprovedUntrusted` | invariant | An untrusted environment runs only from a job authorized as `approved`, against a recorded grant of that exact commit |
| `SafetyParkRemovesPrevious` | invariant | A parked latest intent means nothing of the environment remains |
| `SafetyRevocationPending` | invariant | Once the DB holds no live grant for what runs, a teardown or replacement is already queued |
| `SafetyFailClosedOnUnavailable` | invariant | GHES is never unavailable for `Grace` consecutive re-validations without the fail-closed teardown |
| `SafetyPruneKeepsVerdicts` | invariant | Pruning never changes a stale or replay verdict |
| `SafetyPrunedDeliveriesStale` | invariant | Every pruned delivery would still be refused as stale |
| `SafetyPruneKeepsLatest` | invariant | The latest job of an environment is never pruned |
| `SafetyAuthorizedThisBoot` | invariant | A deploy past `AuthorizeDeploy` was authorized in the current boot |
| `SafetyMonotonicStep` | action | A job becomes `IN_PROGRESS` only if newer than every executed job of its environment |
| `SafetyAuthorizeChecksBoth` | action | An `approved` authorization reads the DB grant and GitHub truth in the same step; a `trusted` one reads GitHub truth |
| `SafetyApprovalBindsCommit` | action | Only a live grant of the exact commit unparks a job |
| `SafetyInternalJobsAreNewest` | action | An internal job (approval, revocation, re-validation, expiry) is above every seq of its environment |
| `SafetyUnavailableRemovesRevoked` | action | A GHES-unavailable `AuthorizeDeploy` never leaves running a version authorized by approval whose grant the DB no longer holds live (A2-6) |
| `RegressionA21` | action (`previewd_a2` only) | A revocation teardown is created only above a latest intent that deploys the revoked commit (A2-1) |
| `RegressionA22` | invariant (`previewd_a2` only) | A deploy in flight, newer than every delivery of its environment ever recorded, is never already stale (A2-2) |
| `LivenessEventualCompletion` | liveness | Every `QUEUED` job reaches a terminal state or waits for an approval |
| `LivenessEventualConsistency` | liveness | `<>[]`: each environment runs the latest job's commit iff that job is a `SUCCESS` deploy GitHub still allows, absent otherwise |
| `LivenessRevokedTornDown` | liveness | Access lost in GitHub (revoked approval, approver or opener without write access) eventually removes the environment |
| `LivenessExpired` | liveness | An expired environment leaves through the queue |
| `LivenessHeadDeployed` | liveness | The open head GitHub allows eventually runs, unless it changed or previewd gave up by design (fail-closed or expiry teardown, failed deploy of that commit) |

## Results (V1 model)

Budget per configuration (V1-model.md section 6.1): 5 million distinct states and 15 minutes on 16 cores.

After A2-6 (V1-model.md section 11), all on one 16-thread, 7 GB host, one TLC at a time, 12 workers, with `SafetyUnavailableRemovesRevoked` in every configuration:

| Config | Distinct states | Depth | Time | Result |
|---|---|---|---|---|
| `previewd.cfg` | 686,226 | 37 | 14 min 35 s | no error |
| `previewd-workers.cfg` | 48,386 | 32 | 59 s | no error |
| `previewd-approval.cfg` | 212,752 | 37 | 2 min 52 s | no error |
| `previewd-reapproval.cfg` | 189,904 | 36 | 3 min 58 s | no error |
| `previewd-approval-reboot.cfg` | 194,928 | 40 | 2 min 54 s | no error |
| `previewd-mixed.cfg` | 481,280 | 33 | 19 min 05 s | no error |
| `previewd-prune.cfg` | 203,029 | 32 | 2 min 40 s | no error |
| `previewd-ttl.cfg` | 9,144 | 30 | 10 s | no error |
| `previewd-grace.cfg` | 125,796 | 38 | 1 min 46 s | no error |
| `previewd_a2.cfg` (safety) | 17,241,260 | 44 | 17 min 55 s | no error |
| `previewd_a2-trust.cfg` (safety) | 3,156,312 | 41 | 2 min 19 s | no error |

The host also ran the Go store tests during this sweep, so the times are inflated: on an idle host after A2, `previewd-mixed` took 11 min 26 s and `previewd` 7 min 42 s, within the 15-minute budget; the state counts, not the times, are the comparison. A2-6 adds states only where a GHES fault meets a running approved version: `previewd-approval` (211,448 → 212,752) and `previewd-grace` (125,236 → 125,796). Every other configuration, the two MVP regressions and the two A2 regressions (no GHES fault) have exactly their A2 counts.

After A2 (the rules of V1-model.md section 11, before A2-6), on an idle host: previewd 686,226 states (7 min 42 s), workers 48,386, approval 211,448, reapproval 189,904, approval-reboot 194,928, mixed 481,280 (11 min 26 s), prune 203,029, ttl 9,144, grace 125,236, previewd_a2 17,241,260 (11 min 32 s), previewd_a2-trust 3,156,312, all with no error.

A1 results, before A2: previewd 686,226 states (9 min 05 s), workers 48,386, approval 104,240, reapproval 110,752, approval-reboot 95,710, mixed 390,624, prune 203,029, ttl 8,896, grace 58,876, all with no error.

Times are wall clock; they are an upper bound.

Three configurations were over budget with the bounds first planned and were reduced or split without dropping a property (V1-model.md, A1-1). `previewd-grace.cfg` was added after coverage showed that `Grace = 1` leaves the recovery path unchecked (A1-12). TLC found one design bug in A0: a grant of the current head re-queued a parked job that was no longer the latest intent. The grant rule now judges the latest job (A1-3). The A2 state-machine test found two more beyond these bounds (V1-model.md section 11): a revocation judged against any active deploy rather than the latest intent (A2-1), and internal jobs ordered above in-flight deliveries (A2-2).

### Coverage

`-coverage` was run on every configuration except `previewd.cfg`, whose actions `previewd-workers.cfg` covers. In the union, every action produces new states, and none of the 1,028 sub-expressions of the translated actions is left unevaluated. Each feature action is covered by the configurations that target it: `Revalidate` by approval, reapproval, approval-reboot, mixed and grace; `Expire` by ttl; `Prune` by prune; the trusted-opener permission loss by mixed; the teardown fault by workers. The first pass, without `previewd-grace.cfg`, left the `Grace > 1` branches of `Revalidate` unevaluated (A1-12). Coverage was not re-run after A2; the changed branches (revoke rule, internal seq, re-validation revocation) are exercised by the Go mutants V1-M05, M13, M20 and M21.

## Mutation check (V1-model.md section 7)

The TLA+ mutants below were run on the A1 translation and not re-run after A2, except V1-M22 (A2-6). Since A2, `TestV1Model_Mutants` (`internal/store/jobs_spbt_v1_props_test.go`) applies every V1 mutant, plus V1-M06b (arrival order), V1-M20 (the A1 revoke rule), V1-M21 (the A1 internal seq) and V1-M22 (the removal of A2-6 skipped), to the Go reference model at every `make check`, with at least 1,000 runs each: all killed by the property named below or by `RegressionA21`/`RegressionA22`, and V1-M15 and V1-M16 survive. With random seeds, V1-M19 survives about one seed in ten at 1,000 runs (seed 9 on the A2 commit too); `make check` pins seed 1, which kills it. On the A1 model, TLC reproduces both A2 bugs with `previewd_a2.tla`: `RegressionA21` alone at depth 10 (44,748 states), `RegressionA22` alone at depth 7 (1,499 states), and in the trust variant at depth 8 (2,714 states).

Each mutant changes one rule of the translated model and must be rejected. TLC stops at the first violated property. Where that was not the property A0 named, the mutant was run again without the first property, and the named property caught it too (marked ✓²).

| Mutant | Config | Caught by |
|---|---|---|
| V1-M01 untrusted job authorized without a live approval | approval | `SafetyAuthorizeChecksBoth`; ✓² `SafetyNoUnapprovedUntrusted` |
| V1-M02 authorization reads the DB grant, not GitHub truth | approval | `SafetyAuthorizeChecksBoth` |
| V1-M03 a grant unparks a parked deploy of another commit | approval | `SafetyApprovalBindsCommit` |
| V1-M04 park leaves the previous version running | approval | `SafetyParkRemovesPrevious` |
| V1-M05 a revocation is recorded but queues no teardown | approval | `SafetyRevocationPending` |
| V1-M06 approvals and revocations applied in arrival order | reapproval | `LivenessHeadDeployed` |
| V1-M07 re-validation not fair | approval | `LivenessRevokedTornDown` (with `LivenessEventualConsistency`) |
| V1-M08 GHES unavailability during re-validation never escalates | approval | `SafetyFailClosedOnUnavailable` |
| V1-M09 GHES fault during authorization treated as allow | approval | `SafetyAuthorizeChecksBoth`; ✓² `SafetyNoUnapprovedUntrusted` |
| V1-M10 `synchronize` queues a teardown newer than its own deploy | previewd | `LivenessHeadDeployed` |
| V1-M11 a grant of the current head with no job waiting does nothing | reapproval | `LivenessHeadDeployed` |
| V1-M12 a re-armed deploy skips `AuthorizeDeploy` | approval-reboot | `SafetyAuthorizedThisBoot` |
| V1-M13 internal job seq not above the latest | approval | `SafetyUniqueDelivery` |
| V1-M14 prune deletes the latest job | prune | `SafetyPruneKeepsLatest` |
| V1-M15 prune does not raise the watermark | prune | survives, equivalent (A1-9): the latest job is never pruned, so `MaxSeq` never depends on the watermark |
| V1-M15b prune deletes the latest job and skips the watermark | prune | `SafetyPruneKeepsVerdicts` |
| V1-M16 prune deletes any delivery | prune | survives, equivalent (A1-9): every recorded delivery is at or below `MaxSeq` by construction |
| V1-M17 expiry not fair | ttl | `LivenessExpired` |
| V1-M18 untrusted environments not locked | mixed | `SafetyMonotonicity`; ✓² `SafetyOneJobPerEnv` |
| V1-M19 only untrusted environments re-validated (before D-V1-5) | mixed | `LivenessRevokedTornDown` (with `LivenessEventualConsistency`) |
| V1-M22 GHES unavailable in `AuthorizeDeploy` leaves a revoked version running (before A2-6) | approval | `SafetyUnavailableRemovesRevoked` (depth 16, 66,441 states, 56 s; run on the A2-6 translation) |

The watermark is defense in depth in the model: no reachable state needs it while the latest job is kept. The Go store keeps it, because a manual `DELETE` or a future pruning rule would otherwise reopen replays.

MVP mutants (Phase 2), re-run on the regression configurations:

| Mutant | Config | Caught by |
|---|---|---|
| D1 *plan*: stale check counts only newer `QUEUED`/`IN_PROGRESS`/`SUCCESS` jobs | previewd | `SafetyMonotonicity` |
| D2 *plan*: sweep marks an interrupted teardown `FAILED` | previewd | `SafetyMonotonicity` |
| Secrets passed as container Env (`SecretChannel = "container_env"`) | previewd | `SafetyZeroSecretLeakage` |
| Commit ignores the lease epoch after a crash | previewd | `LivenessEventualConsistency` and `LivenessHeadDeployed` |
| Sweep keeps an environment superseded by an interrupted deploy (D3) | previewd | `SafetyMonotonicity` |
| `AcquireJob` takes the oldest queued job | previewd | `LivenessHeadDeployed`; ✓² `LivenessEventualConsistency` |
| Sweep keeps intact strays no job tracks | previewd | `SafetyNoOrphanedResources` |
| Sweep does not re-arm a deploy whose secrets a reboot wiped (D3) | previewd | `LivenessEventualConsistency` and `LivenessHeadDeployed` |
| `AcquireJob` leaves older jobs `QUEUED` instead of `SKIPPED` | previewd | `SafetyMonotonicity` |
| No per-environment lock | workers | `SafetyMonotonicity`; ✓² `SafetyOneJobPerEnv` |
| No replay check | previewd | survives, equivalent (A1-9): the stale rule's `>=` already refuses a delivery whose seq exists. The Go store keeps both checks (a resent body under a new delivery ID is not modeled) |
| Destroy leaves the route document | previewd | `SafetyNoOrphanedResources` |
| Route document written before the container starts | previewd | `SafetyRouteImpliesRunning` |

Not repeated: the D5 *plan* formula (a property, not a model change; Safety 2 is the prose rule) and "sweep keeps an environment whose route document is missing" (equivalent in Phase 2; `TestSweepRouteMustMatchEnvironment` covers it).

## Not modeled

- Time: backoff, timeouts, the clock-skew window and the approval time binding (V1-I7). One global clock abstracts UUIDv1 ticks and `now`; GitHub stamps are `Stamp(clock) = clock × K`, and an internal job takes `MaxSeq(e) + 1`, between two stamps (A2-2).
- Docker errors inside the sweep, and rollback failures after a failed deploy step.
- Payload identity: a body resent under a new delivery ID is refused by the store's payload hash (Go tests). In the model a delivery is its seq.
- Secret sections, approver identity matching (`login#id`), TLS to GHES, the CIDR filter, the startup preflight and the BuildKit probe: Go unit, property and E2E tests (V1 spec, task list).
- Bounds beyond the configurations above.
