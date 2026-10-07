# previewd formal model (Phase 2)

`previewd.tla` is a PlusCal algorithm, with its TLA+ translation, for the target orchestration flow:

```text
GitHub ──signed delivery──▶ Api ──1 tx──▶ db_jobs (SQLite) ◀──lease── Worker(s) ──Docker──▶ environments
                                                ▲
                       Supervisor: StartupSweep at every start   Chaos: SimulateCrash (daemon crash / host reboot)
```

The daemon implements it: `internal/store/jobs.go` (queue transitions) and `internal/orchestrator/reconciler.go` (workers and startup sweep). `TestJobStore_StateMachine` checks the queue against the model after every command (`docs/specs/phase3_spbt_architecture.md`).

## Files

| File | Purpose |
|---|---|
| `previewd.tla` | Model, invariants, temporal properties. The block between `BEGIN TRANSLATION` and `END TRANSLATION` is generated: edit the PlusCal, then translate again. |
| `previewd.cfg` | Default gate: 1 worker, 3 deliveries, 2 environments, 1 crash, 1 transient teardown fault. |
| `previewd-workers.cfg` | Same with 2 workers, to check the per-environment lock and leases. |

## Running TLC offline

TLC needs a JRE (17 or later) and `tla2tools.jar`. Neither is a runtime dependency of previewd. Fetch the jar once on a connected machine, check its digest, and copy it next to the model. `tla2tools.jar` is git-ignored.

Checked with `TLC2 Version 2026.10.06.014338 (rev: 94d0c50)`, `tla2tools.jar` SHA-256 `7beec0f04818732a62fa193731711a99aa4f11279499b2360a7d156c519ea78d` (asset of the `v1.8.0` release of `tlaplus/tlaplus`, which is rebuilt in place: record the digest of the jar you use).

```bash
cd docs/formal
# After editing the PlusCal: regenerate the translation. -nocfg keeps the .cfg files.
# pcal.trans leaves previewd.old (git-ignored).
java -cp tla2tools.jar pcal.trans -nocfg previewd.tla
# Model check (TLC writes states/ and, on a violation, *_TTrace_* files: all git-ignored).
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config previewd.cfg previewd.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers auto -config previewd-workers.cfg previewd.tla
```

## Checked properties

| Property | Kind | Meaning |
|---|---|---|
| `SafetyZeroSecretLeakage` | invariant | No environment's secret bytes ever reach a block device |
| `SafetyNoOrphanedResources` | invariant | After the sweep, every container, network, staged secret or route document belongs to an `IN_PROGRESS`/`SUCCESS` deploy that no newer teardown has undone |
| `SafetyMonotonicity` | invariant | No older intent is pending or running once a newer one has executed; a running environment is never older than a completed intent |
| `SafetyMonotonicStep` | action | A job becomes `IN_PROGRESS` only if it is newer than every executed job of its environment |
| `SafetyUniqueDelivery` | invariant | One job per delivery (replay protection) |
| `SafetyOneJobPerEnv` | invariant | At most one `IN_PROGRESS` job per environment |
| `SafetyRouteImpliesRunning` | invariant | A route document never points at a container that is not running |
| `SafetyLeases` | invariant | A current-epoch lease points at an `IN_PROGRESS` job and is never shared |
| `TypeOK` | invariant | Types and bounds |
| `LivenessEventualCompletion` | liveness | Every `QUEUED` job reaches `SUCCESS`, `FAILED` or `SKIPPED` |
| `LivenessEventualConsistency` | liveness | `<>[]`: each environment ends intact at the latest job's `ts` iff that job is a `SUCCESS` deploy, absent otherwise |

The initial state lets each environment hold a stray (container, network, staged secrets) that no job tracks, so the sweep's convergence is checked too.

## Results

| Config | Distinct states | Depth | Result |
|---|---|---|---|
| `previewd.cfg` (1 worker) | 634,821 | 24 | no error (1 min 37 s) |
| `previewd-workers.cfg` (2 workers) | 2,779,645 | 26 | no error (10 min 44 s) |

Since the route documents were added (`route_published`, `PublishRoute`). Before: 548,975 / 2,253,617 states.

`-coverage` on `previewd.cfg`: every action (`ReceiveWebhook`, `AcquireJob`, `ExecuteDeploy`, `StartContainer`, `PublishRoute`, `CommitDeploy`, `ExecuteTeardown`, `CommitTeardown`, `StartupSweep`, `SimulateCrash`) produces new states, and no sub-expression is left unevaluated.

## Mutation check

Each mutant changes one rule in the translated model. TLC must reject it. Rows marked *plan* restore the first draft of `docs/specs/formal_verification_plan.md`. They are the counterexamples behind deviations D1 to D5 in the module header.

| Mutant | Caught by |
|---|---|
| D1 *plan*: stale check counts only newer `QUEUED`/`IN_PROGRESS`/`SUCCESS` jobs | `SafetyMonotonicity`: deploy ts 2 fails, the delayed ts 1 is accepted |
| D2 *plan*: sweep marks an interrupted teardown `FAILED` | `SafetyMonotonicity`: environment still running behind a completed teardown |
| D5 *plan*: Safety 2 requires the owner to be the latest job | that formula: deploy ts 1 running, redeploy ts 2 `QUEUED` |
| Secrets passed as container Env (`SecretChannel = "container_env"`) | `SafetyZeroSecretLeakage` |
| Commit ignores the lease epoch after a crash | `LivenessEventualConsistency` |
| Sweep keeps an environment superseded by an interrupted deploy (D3) | `SafetyMonotonicity` |
| Sweep does not re-arm a deploy whose secrets a reboot wiped (D3) | `LivenessEventualConsistency` |
| Sweep keeps intact strays no job tracks | `SafetyNoOrphanedResources` |
| `AcquireJob` takes the oldest queued job | `LivenessEventualConsistency` |
| `AcquireJob` leaves older jobs `QUEUED` instead of `SKIPPED` | `SafetyMonotonicity` |
| No per-environment lock (2 workers, 2 deliveries) | `SafetyMonotonicity` |
| No replay protection | `SafetyUniqueDelivery` |
| Destroy leaves the route document | `SafetyNoOrphanedResources` |
| Route document written before the container starts | `SafetyRouteImpliesRunning` |
| Sweep keeps an environment whose route document is missing | not killed: equivalent in the model, where only a full destroy removes a route. The case (route deleted by hand) is covered by `TestSweepRouteMustMatchEnvironment` and `TestStartupKeepsThenRebuildsDeployedEnvironment` |

## Not modeled

- Time: backoff, timeouts, the 90-day clock-skew window.
- Docker errors inside the sweep, and rollback failures after a failed deploy step.
- Authorization (approvers, fork policy), routes (`proxy`), image builds: covered by unit, property and E2E tests.
- Bounds beyond the gate configs (2 environments, 3 deliveries, 1 crash, 1 teardown fault). `MaxWebhooks = 4` passed 4.5 M distinct states without a violation but was not run to completion.
