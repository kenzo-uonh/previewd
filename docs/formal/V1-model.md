# V1 formal model design (task A0)

Status: accepted 2026-10-08; implemented by A1 (`previewd.tla`). Section 10 lists what modeling changed, written back as A0 requires. Section 11 lists the two design bugs the A2 state-machine test found beyond the TLC bounds, the rules that replaced them, and the A2-6 rule decided after the security review. Prerequisite of task A1 in `docs/specs/V1-previewd.md`: A1 implements exactly this design in `previewd.tla`. Any deviation found while modeling is written back here first.

The MVP model (`previewd.tla`, `docs/formal/README.md`) stays the base. V1 adds commit identity, trust, approvals, revocation, re-validation, pruning and expiry. Every MVP property keeps holding with the V1 features disabled (section 6.1).

## 1. Commit identity and trust

The MVP model identifies a delivery only by its order `ts`. It cannot say "the approval of the exact head commit" or "a push revokes the approval". V1 adds the minimum identity those rules need.

### 1.1 Constants

| Constant | Meaning | Typical value |
|---|---|---|
| `Commits` | commit identifiers (model values) | `{"c1", "c2"}` |
| `UntrustedEnvs` | environments whose PR comes from a fork or an external author, a subset of `EnvIDs` | `{"e1"}` |
| `MaxWebhooks` | GitHub actions that emit a delivery (PR, review and label events), redeliveries included | 3..4 |
| `MaxPermissionLoss` | silent GitHub-side changes, no webhook: an approver loses write access (untrusted environment), or the opener does (trusted environment, D-V1-5) | 0..1 |
| `MaxGhesFaults` | GHES unavailable during `AuthorizeDeploy` or `Revalidate` | 0..1 |
| `Grace` | consecutive unavailable re-validations before the fail-closed teardown | 1 |
| `MaxPrunes` | `Prune` steps | 0..2 |
| `TTL`, `MaxClock` | environment lifetime and clock bound, in clock ticks; `TTL = 0` disables expiry | 0 or 1, ≤ `MaxWebhooks + 3` |

A PR's head repository and opener do not change during its life, so `UntrustedEnvs` (forks and external authors) is a constant. The opener's write access can change (D-V1-5, decided), so trust is evaluated against GitHub truth, never cached: `Trusted(e) == e ∉ UntrustedEnvs ∧ openerOK[e]`. A same-repo PR whose opener lost write access is treated like a fork from then on.

### 1.2 GitHub-side truth

GitHub becomes an explicit process with its own state. The MVP model's "any ts, any content" delivery is replaced by deliveries emitted from consistent GitHub state.

| Variable | Domain | Meaning |
|---|---|---|
| `head[e]` | `Commits ∪ {None}` | current head commit of the PR |
| `open[e]` | `BOOLEAN` | PR open |
| `approvedGH[e]` | `SUBSET Commits` | commits with a currently valid approval by an approver who still has write access |
| `openerOK[e]` | `BOOLEAN` | the PR's opener still has write access (D-V1-5) |
| `clock` | `0..MaxClock` | one global clock. GitHub stamps deliveries with it (`Stamp(clock)`, A2-2), and a re-validation records its revocation at the current stamp; internal jobs take `MaxSeq(e) + 1` and do not move it. This abstracts UUIDv1 ticks and `now` with clocks synchronized within the skew bound (V1-I7 stays outside the model). |
| `inflight` | set of deliveries | emitted, not yet received; the network reorders freely |

A label approval is modeled as a review approval of the head commit at labeling time, and a label removal as a dismissal. Under D-V1-3 the two paths have the same semantics, so one modeled path covers both.

### 1.3 Deliveries and previewd state

- **Delivery:** `[ts, kind, env, commit]`, `kind ∈ {"deploy", "teardown", "grant", "revoke"}`:
  - `deploy` from `opened`, `reopened`, `synchronize` (the commit is the new head);
  - `teardown` from `closed`;
  - `grant` from an approval;
  - `revoke` from a dismissal, a change request or a label removal.
- **`db_jobs` records** gain:
  - `commit`;
  - `origin ∈ {"webhook", "approval", "revocation", "revalidation", "ttl"}`;
  - status `PENDING_APPROVAL`;
  - ghost field `authz ∈ {"none", "trusted", "approved"}`, set by `AuthorizeDeploy` and used only by properties.
- **`approvalsDB`:** set of `[env, commit, ts, kind ∈ {"grant", "revoke"}]`. `LiveApproval(e, c) == ∃ g ∈ grants(e, c): ∀ r ∈ revokes(e, c): r.ts < g.ts`.

  This makes approval state independent of delivery order. A dismissal delivered after a newer approval does not cancel it, and an approval delivered after a newer dismissal is not live.

  **Finding:** the spec's `approvals` table (`granted_at`, `revoked_at`) cannot express this. It must store the delivery `seq` of each grant and each revocation. This is spec change S-1, applied with this note.
- **`environments[e].commit`:** the built commit, read through the builder job.
- **`watermark[e]`:** the highest seq ever recorded.
- **`revalFails[e]`:** in `0..Grace`.
- **`deployedAt[e]`:** clock value at `CommitDeploy`.
- **Ghosts:** `maxTs[e]` (highest seq ever accepted) and `prunedDeliveries` (properties only).

## 2. Processes and fairness

Rule: a human or external actor is never fair, and a previewd loop that enforces a control is weakly fair. A liveness property may rely only on fair processes, and on unfair ones being bounded.

| Process | Fairness | Actions |
|---|---|---|
| `GitHub` | none; bounded by `MaxWebhooks`, `MaxPermissionLoss` | `Open(e, c)`, `Push(e, c)` (needs `c ≠ head[e]`), `Close(e)`, `Reopen(e)`, `Approve(e)` (approves `head[e]`), `Revoke(e, c)` (`c ∈ approvedGH[e]`), `PermissionLoss(e)` (untrusted: empties `approvedGH[e]`; trusted: `openerOK[e] := FALSE`; emits nothing), `Redeliver(d)` |
| `Clock` | none; bounded by `MaxClock` | `Tick` |
| `Api` | WF | `ReceiveWebhook` (any `d ∈ inflight`) |
| `Worker` (each) | WF | `AcquireJob`, `AuthorizeDeploy`, `ExecuteDeploy`, `StartContainer`, `PublishRoute`, `CommitDeploy`, `ExecuteTeardown`, `CommitTeardown` |
| `Revalidator` | WF | `Revalidate(e)` |
| `Expirer` | WF | `Expire(e)` |
| `Pruner` | none; bounded by `MaxPrunes` | `Prune` |
| `Supervisor` | WF | `StartupSweep` |
| `Chaos` | none; bounded | `SimulateCrash` (daemon crash or host reboot) |

Guards keep the fair loops from stuttering forever:
- `Revalidate(e)` is enabled only for an environment, trusted or not (D-V1-5), that exists, has a successful builder, and either is no longer allowed in GitHub truth or has `revalFails[e] > 0`, or while a GHES fault remains in the budget. Allowed: `Trusted(e)`, or a live approval of its commit in the DB and in GitHub truth.
- `Expire(e)` is enabled only when `clock − deployedAt[e] ≥ TTL > 0` and no newer job exists.

A fair action that is always enabled but changes nothing would satisfy weak fairness vacuously.

Transition rules beyond the MVP:
- **`ReceiveWebhook` `deploy`/`teardown`:** MVP rules, with the stale check against `max(MaxSeq(e), watermark[e])`. An accepted `synchronize` also records a `revoke` (ts of the delivery) for every other commit of `e`. No teardown job is queued.
- **`ReceiveWebhook` `grant`:** recorded, then acted on only for an environment that is not trusted and whose grant is live. Both cases judge the **latest** job (section 10, A1-3):
  - if the latest job is the parked deploy of `(e, commit)`, it becomes `QUEUED`;
  - otherwise a deploy with `origin = "approval"` and `seq = MaxSeq(e) + 1` (A2-2) is queued if `head[e] = commit` and `open[e]` (a GHES read, atomic in the model), unless the latest job already deploys that commit (`QUEUED`, `IN_PROGRESS`, `PENDING_APPROVAL` or `SUCCESS`).
- **`ReceiveWebhook` `revoke`:** recorded. If the environment is not trusted, no grant of that commit stays live, and the **latest** job deploys that commit (`QUEUED`, `IN_PROGRESS`, `PENDING_APPROVAL` or `SUCCESS`), a teardown is queued (`origin = "revocation"`, `seq = MaxSeq(e) + 1`). When the latest job deploys another commit, that intent already removes this one (A2-1).
- **`AuthorizeDeploy`:**
  - trusted environment: allow (`authz = "trusted"`);
  - untrusted environment with `LiveApproval(e, j.commit) ∧ j.commit ∈ approvedGH[e]`: allow (`authz = "approved"`);
  - untrusted without both: park. The previous version is destroyed and the job becomes `PENDING_APPROVAL`, in one step;
  - GHES fault: `QUEUED`, attempt counted. Before that, when the running version was authorized by approval and its approval is not live in the DB (`RevokedVersionRuns`, a DB read), it is destroyed, as the park does (A2-6). Nothing else changes on the host.
- **`Revalidate(e)`:**
  - if allowed (trusted, or approved in GitHub truth and live in the DB): reset `revalFails[e]`;
  - if not: record an internal `revoke` at the current stamp and queue a teardown (`origin = "revalidation"`, `seq = MaxSeq(e) + 1`);
  - GHES fault: `revalFails[e] + 1`, and at `Grace` the same teardown.
- **`Expire(e)`:** a teardown with `origin = "ttl"`, `seq = MaxSeq(e) + 1`.
- **`Prune`:** delete one terminal job that is not the highest-seq job of its environment and not the builder of what runs there (A1-6), after raising `watermark[e]` to at least its seq. Or delete one delivery record whose ts is at most `MaxSeq(env)`, added to `prunedDeliveries`. Which job or delivery is unconstrained: an over-approximation of "older than the retention".
- **`StartupSweep`:** MVP rules. `PENDING_APPROVAL` jobs are untouched. A re-armed deploy goes through `AuthorizeDeploy` again, so an untrusted environment comes back after a reboot only with a re-validated approval.

## 3. Checkable form of "pruning keeps verdicts"

"The verdict of every possible next delivery is the same as in a twin store never pruned" compares two behaviors. TLC cannot check that. The stale rule reads only `MaxSeq(e) = max({watermark[e]} ∪ {j.ts : j ∈ jobs of e})`, and the replay rule reads only the delivery set. A single-behavior invariant over ghost variables is therefore enough:

- `SafetyPruneKeepsVerdicts == ∀ e: MaxSeq(e) = maxTs[e]`, where `maxTs[e]` is raised on every accepted job and never lowered.
- `SafetyPrunedDeliveriesStale == ∀ d ∈ prunedDeliveries: d.ts ≤ MaxSeq(d.env)`: a replay of a pruned delivery is stale, never accepted.
- `SafetyPruneKeepsLatest == ∀ e: JobsOf(e) ≠ {} ⇒ the highest-ts job of e exists`.

Together they imply that every future `deploy`/`teardown` verdict is the same as without pruning.

## 4. Desired state (`Converged`) and liveness under gating

```tla
AllowedTruth(e, c) == Trusted(e) ∨ c ∈ approvedGH[e]          \* GitHub's view (A1-7)
Converged(e) ==
  IF JobsOf(e) ≠ {} ∧ db_jobs[Latest(e)].type = "deploy"
       ∧ db_jobs[Latest(e)].status = "SUCCESS" ∧ AllowedTruth(e, db_jobs[Latest(e)].commit)
  THEN Intact(e) ∧ environments[e].commit = db_jobs[Latest(e)].commit
  ELSE ¬Exists(e)
```

A latest job `PENDING_APPROVAL`, a revoked approval and a lost permission all lead to "absent". Liveness assumes the unfair processes are bounded, so every behavior ends with GitHub quiet and the clock stopped.

## 5. Properties

### 5.1 Safety (invariants or action properties)

| Name | Statement | Kind |
|---|---|---|
| `SafetyNoUnapprovedUntrusted` | Every job of an untrusted environment that reached `ExecuteDeploy` or `SUCCESS` has `authz = "approved"`. Every job of a trusted environment there has `authz ≠ "none"`. | invariant |
| `SafetyAuthorizeChecksBoth` | `AuthorizeDeploy` sets `authz = "approved"` only if `LiveApproval(e, j.commit)` and `j.commit ∈ approvedGH[e]` hold in that step | action |
| `SafetyApprovalBindsCommit` | A job leaves `PENDING_APPROVAL` for `QUEUED` only if a grant for its exact `(env, commit)` is live after the step | action |
| `SafetyParkRemovesPrevious` | daemon up ∧ latest job of `e` is `PENDING_APPROVAL` ⇒ `¬Exists(e)` | invariant |
| `SafetyRevocationPending` | daemon up ∧ `e ∈ UntrustedEnvs` ∧ `Exists(e)` ∧ builder `SUCCESS` ∧ `¬LiveApproval(e, environments[e].commit)` ⇒ a job of `e` newer than the builder is `QUEUED`, `IN_PROGRESS` or `PENDING_APPROVAL` | invariant |
| `SafetyInternalJobsAreNewest` | Every internal job (`origin ≠ "webhook"`) has `seq` above every job and watermark of its environment at creation | action |
| `SafetyUnavailableRemovesRevoked` | A GHES-unavailable `AuthorizeDeploy` never leaves running a version authorized by approval whose grant the DB no longer holds live (A2-6) | action |
| `SafetyPruneKeepsVerdicts`, `SafetyPrunedDeliveriesStale`, `SafetyPruneKeepsLatest` | section 3 | invariants |
| All MVP safety properties | unchanged statements over the extended state | invariants and action |

The statement "an untrusted environment runs only with a live approval" cannot be an invariant: a revocation is a GitHub event, and previewd acts on it after delivery. `SafetyRevocationPending` (the DB already knows, so a removal is queued) and `LivenessRevokedTornDown` (GitHub knows, so previewd eventually acts) together express it.

### 5.2 Liveness

| Name | Statement |
|---|---|
| `LivenessRevokedTornDown` | `∀ e ∈ EnvIDs: (Exists(e) ∧ ¬AllowedTruth(e, environments[e].commit)) ~> (¬Exists(e) ∨ AllowedTruth(e, environments[e].commit))`, with `AllowedTruth(e, c) == Trusted(e) ∨ c ∈ approvedGH[e]`. It covers a revoked fork approval and an offboarded opener alike (D-V1-5). Relies on WF of `Revalidator`, `Worker` and `Api`. |
| `LivenessExpired` | `∀ e: (TTL > 0 ∧ Exists(e) ∧ clock − deployedAt[e] ≥ TTL) ~> (¬Exists(e) ∨ a newer deploy SUCCESS)` |
| `LivenessEventualCompletion` (amended) | every `QUEUED` job reaches a terminal state or `PENDING_APPROVAL`; every `PENDING_APPROVAL` job whose grant is live leaves that status |
| `LivenessEventualConsistency` (amended) | `<>[] ∀ e: Converged(e)` with the section 4 definition |

## 6. Bounds and configurations

### 6.1 Regression and feature configurations

Each configuration enables only the features it targets. Budget per configuration: at most 5 million distinct states and 15 minutes on 16 cores, measured before A1 is accepted. Over budget, reduce `MaxWebhooks` first, then `Commits`. Never remove a property. No symmetry reduction, since it is unsound with liveness.

| Config | Purpose | EnvIDs (untrusted) | Commits | Workers | MaxWebhooks | Crashes | GHES faults | PermLoss | Prunes | TTL |
|---|---|---|---|---|---|---|---|---|---|---|
| `previewd.cfg` | MVP regression | e1, e2 (none) | c1 | 1 | 3 | 1 | 0 | 0 | 0 | 0 |
| `previewd-workers.cfg` | MVP regression, lock (A1-1: `MaxWebhooks` 3 → 2) | e1, e2 (none) | c1 | 2 | 2 | 1 | 0 | 0 | 0 | 0 |
| `previewd-approval.cfg` | gate, revocation, new head (A1-1: `MaxWebhooks` 4 → 3) | e1 (e1) | c1, c2 | 1 | 3 | 0 | 1 | 1 | 0 | 0 |
| `previewd-reapproval.cfg` | dismissal then re-approval, grant of the current head (A1-1) | e1 (e1) | c1 | 1 | 4 | 0 | 0 | 0 | 0 | 0 |
| `previewd-approval-reboot.cfg` | revalidated rebuild after reboot | e1 (e1) | c1 | 1 | 3 | 1 | 0 | 0 | 0 | 0 |
| `previewd-mixed.cfg` | trusted and untrusted together, lock across trust, opener offboarded (D-V1-5) | e1, e2 (e2) | c1 | 2 | 3 | 0 | 0 | 1 | 0 | 0 |
| `previewd-prune.cfg` | watermark, pruned deliveries (A1-1: `MaxWebhooks` 4 → 3) | e1 (none) | c1 | 1 | 3 | 1 | 0 | 0 | 2 | 0 |
| `previewd-ttl.cfg` | expiry through the queue | e1 (none) | c1 | 1 | 2 | 0 | 0 | 0 | 0 | 1 |
| `previewd-grace.cfg` | GHES unavailable below the grace limit, recovery resets the count (A1-12) | e1 (e1) | c1 | 1 | 3 | 0 | 2 | 1 | 0 | 0 |

The MVP regression configurations run the restructured model. Their state counts will differ from the MVP's (634,821 and 2,779,645) because GitHub is now an explicit process. Every MVP property must still hold, and every MVP mutant must still be killed.

### 6.2 Why these bounds are enough

Small-scope argument, stated so a reviewer can challenge it:
- **Two commits** are the least that express "approval of another commit", "a push revokes", and "an approval delivered after the PR moved on".
- **One untrusted environment** carries every approval rule, since approvals never cross environments (the store keys them by environment).
- **Interactions across environments** are trust-independent apart from the lock. `previewd-mixed.cfg` and the MVP configurations cover them.
- **`Grace = 1`** exercises the fail-closed path on the first fault. **`Grace = 2`** (`previewd-grace.cfg`) adds the only behavior a larger value has: a failure below the limit, then a success that resets the count (A1-12). Larger values only delay the teardown further.
- **Pruning** is over-approximated (any terminal non-latest job, at any time), so a bounded `MaxPrunes = 2` explores both "prune before the next delivery" and "prune between replays".

## 7. Acceptance criteria

A1 is accepted when every configuration of 6.1 passes within budget, coverage shows every new action producing states with no unevaluated sub-expression, and every mutant below (V1-M1 to V1-M19) is killed by the named property in the named configuration. The mutants are applied to the translated model, as in Phase 2. The MVP mutants (12, plus the route mutants) are re-run on the regression configurations.

| # | Mutant | Must be killed by | Config |
|---|---|---|---|
| V1-M1 | `AuthorizeDeploy` allows an untrusted job without a live approval | `SafetyNoUnapprovedUntrusted` | approval |
| V1-M2 | `AuthorizeDeploy` checks the DB approval but not GitHub truth | `SafetyAuthorizeChecksBoth` / `LivenessRevokedTornDown` | approval |
| V1-M3 | A grant unparks a job of another commit of the same environment | `SafetyApprovalBindsCommit` | approval |
| V1-M4 | Park leaves the previous version running | `SafetyParkRemovesPrevious` | approval |
| V1-M5 | A `revoke` delivery is recorded but queues no teardown | `SafetyRevocationPending` | approval |
| V1-M6 | `LiveApproval` ignores ordering (any revoke kills any grant) | `LivenessEventualConsistency` (a valid re-approval never deploys) | approval |
| V1-M7 | `Revalidator` not fair | `LivenessRevokedTornDown` (permission loss) | approval |
| V1-M8 | GHES faults during re-validation never escalate (no `Grace`) | `LivenessRevokedTornDown` | approval |
| V1-M9 | GHES fault in `AuthorizeDeploy` treated as allow | `SafetyNoUnapprovedUntrusted` | approval |
| V1-M10 | `synchronize` queues a teardown newer than its own deploy (the first draft's design) | `LivenessEventualConsistency` | approval |
| V1-M11 | A grant of the current head with no job waiting does nothing | `LivenessEventualConsistency` | approval |
| V1-M12 | The sweep re-arms an untrusted deploy and skips `AuthorizeDeploy` | `SafetyNoUnapprovedUntrusted` | approval-reboot |
| V1-M13 | Internal job `seq` = latest seq (not above it) | `SafetyInternalJobsAreNewest` / `SafetyUniqueDelivery` | approval |
| V1-M14 | `Prune` deletes the latest job of an environment | `SafetyPruneKeepsLatest` / `SafetyPruneKeepsVerdicts` | prune |
| V1-M15 | `Prune` does not raise the watermark | `SafetyPruneKeepsVerdicts` | prune |
| V1-M16 | `Prune` deletes a delivery newer than `MaxSeq` | `SafetyPrunedDeliveriesStale` | prune |
| V1-M17 | `Expirer` not fair | `LivenessExpired` | ttl |
| V1-M18 | Trusted and untrusted jobs of different environments share the lock | `SafetyOneJobPerEnv` / `LivenessEventualCompletion` | mixed |
| V1-M19 | `Revalidator` checks untrusted environments only (the pre-D-V1-5 design) | `LivenessRevokedTornDown` (offboarded opener) | mixed |
| V1-M22 | GHES unavailable in `AuthorizeDeploy` leaves a revoked version running (before A2-6) | `SafetyUnavailableRemovesRevoked` | approval |

Out of model, and checked by Go tests instead:
- an untrusted deploy receiving trusted secrets (`Injector.Section`);
- approver matched by login instead of ID;
- the V1-I7 time binding;
- TLS and the CIDR filter;
- the preflight and the build probe.

The task list names the test for each.

## 8. Mapping to the state-machine test (A2)

Implemented in `internal/store/jobs_spbt_v1_test.go` (reference model and commands), `jobs_spbt_v1_props_test.go` (properties, drain, mutants) and `jobs_spbt_v1_store_test.go` (the store backend; it pinned the store API behind the build tag `v1spbt` until B1 implemented it, and runs untagged since).

| Model action | Store method (V1 spec 3.4, as A2 pins it) | SPBT command |
|---|---|---|
| GitHub `opened`/`reopened`, `synchronize`, `closed` | none (test-side truth) | `Open`, `Push`, `Close` |
| GitHub approval, dismissal, redelivery | none | `Approve`, `Dismiss`, `Redeliver`, `ForgedRedelivery` (a body resent under a new ID) |
| GitHub `PermissionLoss`, `Tick` | none | `PermissionLoss`, `Tick` |
| `ReceiveWebhook` deploy/teardown | `Enqueue` (stale against the watermark too) | `ReceiveWebhook` |
| `ReceiveWebhook` grant | `Approve` | `ReceiveWebhook` |
| `ReceiveWebhook` revoke | `Revoke` | `ReceiveWebhook` |
| `AcquireJob` | `Acquire` | `AcquireJob` |
| `AuthorizeDeploy` allow / park / fault | `Classify`, `Park` (after `Classify` untrusted is refused without a live approval), `Requeue` | `Step` on a worker at `AuthorizeDeploy` |
| deploy and teardown steps | `Finish`, `Requeue` | `Step` |
| `Revalidate`, `Expire` | `ApprovalLive`, `Expired`, `EnqueueInternal` | `Revalidate`, `Expire` |
| `Prune` | `Prune` | `Prune` |
| `SimulateCrash`, `StartupSweep` | `Close`, `NewStore`, `StartupSweep` | `SimulateCrash` |

The reference model implements sections 1 to 4 independently of the store, as in Phase 3, with the TLA+ model's rules one for one. After every command `Check` compares every table with the model (when a store is driven) and judges the model with every property of section 5 and A1-4, plus the A2 regression properties; the action properties compare the states before and after the command. After the random rounds, the fair processes run with GitHub quiet and no fault, and the liveness properties are checked. Between rounds the run may settle (the fair processes reach quiescence) and may end with a quiet round (no new delivery, silent permission changes), so the commands reach running environments that GitHub then stops allowing.

Each mutant of section 7 is applied to the reference model's algorithm and must be killed by the property A1 named (`TestV1Model_Mutants`), with at least 1,000 runs per mutant. This proves that the commands reach every guarded path and that the Go properties are as strong as the TLA+ ones; at D3 the same commands and properties judge the store.

## 9. Spec changes from this design

- **S-1 (applied with this note):** `approvals` stores `granted_seq` and `revoked_seq` (delivery order) instead of relying on timestamps. Liveness of an approval is "a grant newer than every revocation of the same `(repo, pr, commit, approver)`".
- **S-2 (applied):** A0 inserted before A1 in the task list. A1 means "implement this note".
- **D-V1-5 (decided 2026-10-08):** every running environment is re-validated. For a trusted one that means its opener's write access, in the same loop with the same grace. Modeled by `openerOK`, `PermissionLoss` on trusted environments, `LivenessRevokedTornDown` over all environments, `previewd-mixed.cfg` with `MaxPermissionLoss = 1`, and mutant V1-M19.

## 10. Deviations found during A1

A1 (`previewd.tla`) follows sections 1 to 9 except for the points below. Each was forced by a TLC result or by a mutant that the properties as first written could not kill.

- **A1-1, configurations split or reduced to stay within budget (section 6.1).** Every property and mutant is kept.
  - `previewd-approval` with `MaxWebhooks = 4` was still growing at 518,000 states after 9 minutes. It is split into `previewd-approval` (`MaxWebhooks = 3`, both commits, GHES faults, permission loss) and `previewd-reapproval` (`MaxWebhooks = 4`, one commit, no faults), which carries the dismissal-then-re-approval paths (V1-M06, V1-M11).
  - `previewd-prune` was reduced from 4 deliveries to 3 (721,000 states after 9 minutes, growing).
  - `previewd-workers` was reduced from 3 deliveries to 2 (590,000 states after 9 minutes, growing). That is the bound Phase 2 used for its no-lock mutant.
- **A1-2, `-lncheck final`.** Liveness is checked once, on the complete graph. The verdict is the same; it avoids re-checking the partial graph every minute.
- **A1-3, the grant rule judges the latest intent (a design bug found by TLC).** With the rule of section 2, `previewd-reapproval` violated `LivenessHeadDeployed`:
  1. `opened(c1)`, `approve`, `dismiss` and `approve` are emitted;
  2. the dismissal is processed while the first deploy is still queued, and queues a revocation teardown with a newer clock seq;
  3. the re-approval then sees that queued deploy as "a job waiting" and does nothing;
  4. the worker takes the newest job, the teardown, and skips the deploy.

  The PR stays open, approved and recorded, and is never deployed. The rule now unparks only a parked deploy that is the latest job, and otherwise queues a new deploy unless the latest job already deploys the commit. The spec's event matrix (section 3.3) is corrected to match.
- **A1-4, three properties added, because the section 5 properties could not kill three mutants.**
  - `LivenessHeadDeployed`: the open head that GitHub allows, trusted or approved and recorded, eventually runs. The exceptions are a head that changed and a deliberate give-up: a fail-closed or expiry teardown, or a failed deploy of that commit. `Converged` judges the latest job, so it cannot see an intent that was dropped (V1-M06, V1-M10, V1-M11).
  - `SafetyFailClosedOnUnavailable` (`revalFails < Grace`): with bounded GHES faults, a missing escalation is masked by the next successful check (V1-M08).
  - `SafetyAuthorizedThisBoot`: a deploy past `AuthorizeDeploy` was authorized in the current boot. A re-arm that bypasses the step never triggers the action property (V1-M12).
- **A1-5, two properties reformulated.**
  - `SafetyNoUnapprovedUntrusted` checks the builder's authorization against a grant of that commit in the DB, not the label the code sets.
  - `SafetyRevocationPending` applies to every environment whose builder was authorized by approval, which includes trusted PRs whose opener lost write access (D-V1-5).
- **A1-6, the pruner never deletes the builder of what runs.** Deleting it breaks Safety 2 and the sweep's `Keep`. The spec's `Prune` predicate gains this condition.
- **A1-7, `Converged` uses GitHub truth (`AllowedTruth`).** The desired state is what GitHub allows, not what the DB has recorded. Liveness then requires previewd to catch up with GitHub.
- **A1-8, Eventual Completion:** the clause "every `PENDING_APPROVAL` job whose grant is live leaves that status" is dropped. It is not a stable condition: GitHub can withdraw the approval silently. `LivenessHeadDeployed` covers the intent instead.
- **A1-9, equivalent mutants, documented and not killable by construction.**
  - **V1-M15 (prune without raising the watermark):** the latest job is never pruned, so it always carries `MaxSeq`, and the watermark never changes a verdict. The combined mutant V1-M15b (prune the latest job and skip the watermark) is killed by `SafetyPruneKeepsVerdicts`. The watermark is therefore defense in depth, not load-bearing.
  - **V1-M16 (prune any delivery):** every recorded delivery is at or below `MaxSeq` by construction.
  - **MVP-M12 (no replay check):** the stale rule's `≥` already refuses a delivery with an existing seq.

  The Go store keeps both checks, and both are tested there.
- **A1-10, V1-M10 is checked on `previewd.cfg`.** On a trusted PR, the extra teardown of the first draft's `synchronize` makes the new head's deploy skipped, which `LivenessHeadDeployed` catches. On an untrusted PR, the re-approval path now re-queues a deploy and masks it.
- **A1-11, `JobBound = 3 × MaxWebhooks`,** checked by `TypeOK` (`nextId ≤ JobBound + 1`) rather than assumed.
- **A1-12, `previewd-grace.cfg` added (a coverage finding).** With `Grace = 1` in every configuration, `-coverage` showed two `Revalidate` branches never evaluated: a GHES failure below the limit (`revalFails[e] + 1 < Grace`) and the reset after a successful check (`revalFails[e] > 0` and allowed again). They were never model-checked, not merely uncovered. `previewd-grace.cfg` (`Grace = 2`, two GHES faults, one untrusted environment, one commit) exercises both, and the escalation after two consecutive failures. Section 6.2 is corrected: a larger `Grace` adds the recovery path, it does not only delay the teardown.

## 11. Deviations found during A2

The state-machine test (section 8) explores runs far beyond the TLC bounds: up to three environments, two commits, unbounded GitHub actions, crashes, faults and pruning in one run. It found two design bugs in the A1 model. Both violate `LivenessHeadDeployed`: an open head that GitHub allows, and that the DB records as approved, is never deployed. Both need five or more GitHub actions on two commits, above every configuration of section 6.1 (A1-1 reduced them to stay within budget). TLC reproduces both on the A1 model with the regression properties of `previewd_a2.tla`, which name the step or state that dooms the intent, so a safety search reaches them where liveness does not fit the budget. On the current model both hold: `previewd_a2.cfg` (5 actions, 17,241,260 states) and `previewd_a2-trust.cfg` (4 actions, 3,156,312 states), and the nine configurations of section 6.1 pass with every property (`README.md`).

- **A2-1, a revocation judged against any active deploy, not the latest intent.** The A1 rule queued a revocation teardown when the environment ran the revoked commit or had any active deploy of it. TLC trace (A1 model, `RegressionA21` alone, depth 10, 44,748 states):
  1. `opened(c1)`, approve c1, `synchronize(c2)`, approve c2, dismiss c1 are emitted;
  2. the deploy of c1 is queued; the grant of c2 queues an approval deploy of c2, the latest intent;
  3. the revocation of c1 matches the stale queued deploy of c1 and queues a teardown above the deploy of c2;
  4. the worker takes the teardown and skips the deploy of the head.

  This is the A1-3 bug in the revoke rule. **Rule now:** a revocation queues a teardown only when the latest job deploys the revoked commit (`HeadIntentPresent`, the predicate of the grant rule). When the latest job deploys another commit, that intent removes the revoked version itself: `ExecuteDeploy` replaces it and the park destroys it. `SafetyRevocationPending` still holds, because that newer intent is the pending replacement. `RunningCommit` and `ActiveDeployOf` are removed. Regression: `RegressionA21` (action property: a revocation teardown is created only above a latest intent that deploys its commit), and mutant V1-M20 (the A1 rule) in the Go test.

- **A2-2, an internal job ordered by previewd's clock, not by the queue.** In A1, every internal job took `seq = clock + 1`, above every stamp GitHub had given so far, including deliveries still in flight. A push that GitHub sent before the internal job was created, but that previewd received after, was then stale, and its intent was lost. First found by the Go test on a same-repo PR whose opener lost write access (D-V1-5), where nothing re-queues the lost head:
  1. c2 is approved while the PR is trusted: recorded, nothing to act on;
  2. the opener loses write access, then c1 is pushed, approved and dismissed, and c2 is pushed;
  3. the dismissal is processed before the push of c2 arrives: its revocation teardown takes `clock + 1`, above the push's stamp;
  4. the push of c2 is stale. c2 is the open head, approved in GitHub and live in the DB, and is never deployed.

  TLC reproduces the mechanism on the A1 model with `RegressionA22` (a deploy delivery in flight, newer than every delivery of its environment ever recorded, is already stale): depth 7, 1,499 states (depth 8, 2,714 states, in the trusted variant with 4 GitHub actions). **Rule now:** an internal job takes `MaxSeq(e) + 1`. It still supersedes every recorded intent of its environment (`SafetyInternalJobsAreNewest`), and it loses to any delivery GitHub sent after the latest recorded intent, even one still in flight. In the model, GitHub stamps are `Stamp(clock) = clock × K` with `K = JobBound + 1`: at most `JobBound` internal jobs follow one stamp, so an internal seq is never a stamp. In the store a seq is UUIDv1 ticks and an internal job is one tick (100 ns) above `MaxSeq`. Internal jobs no longer move the clock, so `ClockBound = MaxWebhooks + MaxTicks`. A re-validation records its revocation at the current stamp (GitHub truth now voids every grant it sent so far). Safety does not depend on the old ordering: a delivery that now wins over an internal teardown goes through `AuthorizeDeploy`, which reads the DB and GitHub truth again. Regression: `RegressionA22`, and mutant V1-M21 (the A1 rule) in the Go test.

- **A2-3, `SafetyUniqueDelivery` per environment.** The first internal job of two environments with no job yet (an approval of a head whose `opened` delivery is still in flight) both take seq 1. The store's constraint is `UNIQUE (preview_id, seq)`, and every rule compares seqs within one environment, so the property is now stated per environment.

- **A2-4, store API pinned by the test (V1 spec 3.4 updated).** Writing the store backend forced the points the spec left open:
  - `Approve` and `Revoke` receive the GitHub truth the API read in the same step (`Trusted`, and for a grant `OpenHead` and the PR's `Source`), as the model's single step does;
  - `Classify(untrusted)` refuses without a live approval of the lease's commit in the same transaction (`ErrNotApproved`), so the DB half of `SafetyAuthorizeChecksBoth` holds in the store itself;
  - `Requeue` accepts a deploy until it is classified (GHES unavailable during `AuthorizeDeploy`), and refuses it after, as before;
  - `Finish` takes `now` (`finished_at`); `Delivery` carries `ReceivedAt`;
  - `ApprovalLive(env, commit)` replaces `LiveUntrusted`: under D-V1-5 the Revalidator checks every running environment and needs the DB half of `Allowed`;
  - `EnqueueInternal` takes the revocation reason, and revokes a live approval of the running commit in the same transaction;
  - `Prune` takes the builders of every existing environment (A1-6 needs the host's view).

- **A2-5, spec gaps left to B1 and D3.**
  - The `approvals` table of spec 3.1 keys a row by `(repo, pr, commit, approver, via)` and needs a grant. The model records revocations of commits that never had a grant: a new head revokes every other commit, and a dismissal can arrive before its grant. A late, older grant must stay dead. B1 must store a revocation without a prior grant, per `(env, commit)`. The test compares `ApprovalLive` for every environment and commit, so either representation is judged.
  - The spec's event matrix revoked approvals on `closed` (`pr_closed`). The model does not, and GitHub keeps approvals across close and reopen: a reopened PR deploys only if `AuthorizeDeploy` finds the approval live in both the DB and GitHub. The matrix now follows the model. The `pr_closed` and `revalidation_unavailable` reasons stay in the vocabulary, unused by the queue.


- **A2-6 (decided by the owner 2026-10-08, modeled before D4), a revoked version could outlive a GHES outage.** Security review of A2-1. When a revocation finds that the latest job deploys another commit, no teardown is queued: that newer deploy removes the revoked version when `AuthorizeDeploy` runs it (replaced, or destroyed by the park). While GHES was unavailable, `AuthorizeDeploy` requeued that deploy with backoff and changed nothing on the host, so the revoked version kept running for the whole outage. The Revalidator did not bound it either: `NeedsRevalidation` requires the builder to be the latest job, so the fail-closed grace never started. The same held for a push: its `new_head` revocation queues no teardown. The A1 rule removed the version at once, since a teardown needs no GHES, but lost the new head (A2-1). The model's liveness held only because GHES faults are bounded. Severity MEDIUM (V1 spec invariant: authorized code only, revocable).

  **Rule now:** in the GHES-unavailable branch of `AuthorizeDeploy`, the running version is destroyed first when its builder was authorized by approval and its approval is not live in the DB (`RevokedVersionRuns(e)`, a DB read, no GHES call), as the park does; the deploy is then requeued. Checked by the action property `SafetyUnavailableRemovesRevoked` in every configuration, and by mutant V1-M22 (the removal skipped): killed in `previewd-approval.cfg` at depth 16 (66,441 states, 56 s), and in the Go reference model. One GHES fault is enough: a safety property needs no outage longer than one step, so no configuration was added. `previewd-approval` (211,448 → 212,752 states) and `previewd-grace` (125,236 → 125,796) grew with the destroyed states; the other configurations kept their counts.

  *Residual (LOW, documented):* a trusted version whose opener lost write access (D-V1-5) keeps running during the same outage when a newer deploy waits: the DB holds no evidence of the loss, and a re-validation teardown above the newer deploy would skip it (the A2-1 problem). It is removed when GHES answers.

  In the store (B1): the orchestrator reads the builder's `jobs.trust` and `ApprovalLive` before `Requeue`. The A2 state-machine test asserts that `ApprovalLive` answers as the model in this branch.

- **A2-5 in B1.** The store keeps grants (`approvals`), explicit revocations per `(env, commit)` (`revocations`, with or without a grant) and the new-head revocation (`heads`, one row per environment: every commit but the newest head is revoked at its seq, the head at the newest seq of any other deploy) apart. That represents the model's `approvalsDB` over an unbounded set of commits, including a commit no delivery has named yet. `TestV1Store_StateMachine` compares `ApprovalLive` with the model for every environment and commit after every command.

- **D2 (2026-10-08), replay of approval deliveries.** The store now replay-checks grant and revoke deliveries, by delivery ID and signed body, against every recorded delivery, as it does deploy and teardown deliveries. `previewd.tla` applies a redelivered grant again. The store's behavior is a refinement: a redelivery the store drops corresponds to the model behavior in which GitHub never redelivered, an unfair action, so every safety property and every liveness property under the model's fairness still holds. The TLA+ model is unchanged and TLC was not re-run. The Go reference model follows the store exactly (`approvalDeliveries`, kept apart from the webhook deliveries that `RegressionA22` and the pruning ghosts judge), and `ForgedRedelivery` now resends a captured body of any kind.
