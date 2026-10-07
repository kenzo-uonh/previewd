# V1 formal model design (task A0)

Status: draft for owner review, 2026-10-08. Prerequisite of task A1 in `docs/specs/V1-previewd.md`: A1 implements exactly this design in `previewd.tla`. Any deviation found while modeling is written back here first.

The MVP model (`previewd.tla`, `docs/formal/README.md`) stays the base. V1 adds commit identity, trust, approvals, revocation, re-validation, pruning and expiry. Every MVP property keeps holding with the V1 features disabled (section 6.1).

## 1. Commit identity and trust

The MVP model identifies a delivery only by its order `ts`. It cannot say "the approval of the exact head commit" or "a push revokes the approval". V1 adds the minimum identity those rules need.

### 1.1 Constants

| Constant | Meaning | Typical value |
|---|---|---|
| `Commits` | commit identifiers (model values) | `{"c1", "c2"}` |
| `UntrustedEnvs` | environments whose PR comes from a fork or an external author, a subset of `EnvIDs` | `{"e1"}` |
| `MaxWebhooks` | GitHub actions that emit a delivery (PR, review and label events), redeliveries included | 3..4 |
| `MaxPermissionLoss` | silent GitHub-side changes: an approver loses write access, no webhook | 0..1 |
| `MaxGhesFaults` | GHES unavailable during `AuthorizeDeploy` or `Revalidate` | 0..1 |
| `Grace` | consecutive unavailable re-validations before the fail-closed teardown | 1 |
| `MaxPrunes` | `Prune` steps | 0..2 |
| `TTL`, `MaxClock` | environment lifetime and clock bound, in clock ticks; `TTL = 0` disables expiry | 0 or 1, ≤ `MaxWebhooks + 3` |

Trust is a property of the PR, not of a job. A PR's head repository and opener do not change during its life, so `UntrustedEnvs` is a constant. The re-validation of a trusted opener's write permission is decision D-V1-5 of the spec, outside this model until decided.

### 1.2 GitHub-side truth

GitHub becomes an explicit process with its own state. The MVP model's "any ts, any content" delivery is replaced by deliveries emitted from consistent GitHub state.

| Variable | Domain | Meaning |
|---|---|---|
| `head[e]` | `Commits ∪ {None}` | current head commit of the PR |
| `open[e]` | `BOOLEAN` | PR open |
| `approvedGH[e]` | `SUBSET Commits` | commits with a currently valid approval by an approver who still has write access |
| `clock` | `0..MaxClock` | one global clock. GitHub stamps deliveries with it, and previewd stamps internal jobs and revocations with it. This abstracts UUIDv1 ticks and `now` with clocks synchronized within the skew bound (V1-I7 stays outside the model). |
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
| `GitHub` | none; bounded by `MaxWebhooks`, `MaxPermissionLoss` | `Open(e, c)`, `Push(e, c)` (needs `c ≠ head[e]`), `Close(e)`, `Reopen(e)`, `Approve(e)` (approves `head[e]`), `Revoke(e, c)` (`c ∈ approvedGH[e]`), `PermissionLoss(e)` (empties `approvedGH[e]`, emits nothing), `Redeliver(d)` |
| `Clock` | none; bounded by `MaxClock` | `Tick` |
| `Api` | WF | `ReceiveWebhook` (any `d ∈ inflight`) |
| `Worker` (each) | WF | `AcquireJob`, `AuthorizeDeploy`, `ExecuteDeploy`, `StartContainer`, `PublishRoute`, `CommitDeploy`, `ExecuteTeardown`, `CommitTeardown` |
| `Revalidator` | WF | `Revalidate(e)` |
| `Expirer` | WF | `Expire(e)` |
| `Pruner` | none; bounded by `MaxPrunes` | `Prune` |
| `Supervisor` | WF | `StartupSweep` |
| `Chaos` | none; bounded | `SimulateCrash` (daemon crash or host reboot) |

Guards keep the fair loops from stuttering forever:
- `Revalidate(e)` is enabled only for an untrusted environment that exists, has a successful builder, and either is no longer approved in GitHub truth or has `revalFails[e] > 0`, or while a GHES fault remains in the budget.
- `Expire(e)` is enabled only when `clock − deployedAt[e] ≥ TTL > 0` and no newer job exists.

A fair action that is always enabled but changes nothing would satisfy weak fairness vacuously.

Transition rules beyond the MVP:
- **`ReceiveWebhook` `deploy`/`teardown`:** MVP rules, with the stale check against `max(MaxSeq(e), watermark[e])`. An accepted `synchronize` also records a `revoke` (ts of the delivery) for every other commit of `e`. No teardown job is queued.
- **`ReceiveWebhook` `grant`:** recorded unless it is a replay. A `PENDING_APPROVAL` job of `(e, commit)` becomes `QUEUED`. Otherwise, a deploy job with `origin = "approval"` and the delivery ts is queued if all of the following hold:
  - the delivery ts is above `MaxSeq(e)`;
  - `head[e] = commit` and `open[e]` (a GHES read, atomic in the model);
  - no deploy of that commit is pending.
- **`ReceiveWebhook` `revoke`:** recorded. If the environment runs that commit and no grant of it stays live, a teardown is queued (`origin = "revocation"`, `seq = ++clock`).
- **`AuthorizeDeploy`:**
  - trusted environment: allow (`authz = "trusted"`);
  - untrusted environment with `LiveApproval(e, j.commit) ∧ j.commit ∈ approvedGH[e]`: allow (`authz = "approved"`);
  - untrusted without both: park. The previous version is destroyed and the job becomes `PENDING_APPROVAL`, in one step;
  - GHES fault: `QUEUED`, attempt counted, nothing changed on the host.
- **`Revalidate(e)`:**
  - if approved in GitHub truth and live in DB: reset `revalFails[e]`;
  - if not: record an internal `revoke` and queue a teardown (`origin = "revalidation"`, `seq = ++clock`);
  - GHES fault: `revalFails[e] + 1`, and at `Grace` the same teardown.
- **`Expire(e)`:** a teardown with `origin = "ttl"`, `seq = ++clock`.
- **`Prune`:** delete one terminal job that is not the highest-seq job of its environment, after raising `watermark[e]` to at least its seq. Or delete one delivery record whose ts is at most `MaxSeq(env)`, added to `prunedDeliveries`. Which job or delivery is unconstrained: an over-approximation of "older than the retention".
- **`StartupSweep`:** MVP rules. `PENDING_APPROVAL` jobs are untouched. A re-armed deploy goes through `AuthorizeDeploy` again, so an untrusted environment comes back after a reboot only with a re-validated approval.

## 3. Checkable form of "pruning keeps verdicts"

"The verdict of every possible next delivery is the same as in a twin store never pruned" compares two behaviors. TLC cannot check that. The stale rule reads only `MaxSeq(e) = max({watermark[e]} ∪ {j.ts : j ∈ jobs of e})`, and the replay rule reads only the delivery set. A single-behavior invariant over ghost variables is therefore enough:

- `SafetyPruneKeepsVerdicts == ∀ e: MaxSeq(e) = maxTs[e]`, where `maxTs[e]` is raised on every accepted job and never lowered.
- `SafetyPrunedDeliveriesStale == ∀ d ∈ prunedDeliveries: d.ts ≤ MaxSeq(d.env)`: a replay of a pruned delivery is stale, never accepted.
- `SafetyPruneKeepsLatest == ∀ e: JobsOf(e) ≠ {} ⇒ the highest-ts job of e exists`.

Together they imply that every future `deploy`/`teardown` verdict is the same as without pruning.

## 4. Desired state (`Converged`) and liveness under gating

```tla
Allowed(e, c) == e ∉ UntrustedEnvs ∨ (LiveApproval(e, c) ∧ c ∈ approvedGH[e])
Converged(e) ==
  IF JobsOf(e) ≠ {} ∧ db_jobs[Latest(e)].type = "deploy"
       ∧ db_jobs[Latest(e)].status = "SUCCESS" ∧ Allowed(e, db_jobs[Latest(e)].commit)
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
| `SafetyPruneKeepsVerdicts`, `SafetyPrunedDeliveriesStale`, `SafetyPruneKeepsLatest` | section 3 | invariants |
| All MVP safety properties | unchanged statements over the extended state | invariants and action |

The statement "an untrusted environment runs only with a live approval" cannot be an invariant: a revocation is a GitHub event, and previewd acts on it after delivery. `SafetyRevocationPending` (the DB already knows, so a removal is queued) and `LivenessRevokedTornDown` (GitHub knows, so previewd eventually acts) together express it.

### 5.2 Liveness

| Name | Statement |
|---|---|
| `LivenessRevokedTornDown` | `∀ e ∈ UntrustedEnvs: (Exists(e) ∧ environments[e].commit ∉ approvedGH[e]) ~> (¬Exists(e) ∨ environments[e].commit ∈ approvedGH[e])`. Relies on WF of `Revalidator`, `Worker` and `Api`. |
| `LivenessExpired` | `∀ e: (TTL > 0 ∧ Exists(e) ∧ clock − deployedAt[e] ≥ TTL) ~> (¬Exists(e) ∨ a newer deploy SUCCESS)` |
| `LivenessEventualCompletion` (amended) | every `QUEUED` job reaches a terminal state or `PENDING_APPROVAL`; every `PENDING_APPROVAL` job whose grant is live leaves that status |
| `LivenessEventualConsistency` (amended) | `<>[] ∀ e: Converged(e)` with the section 4 definition |

## 6. Bounds and configurations

### 6.1 Regression and feature configurations

Each configuration enables only the features it targets. Budget per configuration: at most 5 million distinct states and 15 minutes on 16 cores, measured before A1 is accepted. Over budget, reduce `MaxWebhooks` first, then `Commits`. Never remove a property. No symmetry reduction, since it is unsound with liveness.

| Config | Purpose | EnvIDs (untrusted) | Commits | Workers | MaxWebhooks | Crashes | GHES faults | PermLoss | Prunes | TTL |
|---|---|---|---|---|---|---|---|---|---|---|
| `previewd.cfg` | MVP regression | e1, e2 (none) | c1 | 1 | 3 | 1 | 0 | 0 | 0 | 0 |
| `previewd-workers.cfg` | MVP regression, lock | e1, e2 (none) | c1 | 2 | 3 | 1 | 0 | 0 | 0 | 0 |
| `previewd-approval.cfg` | gate, revocation, new head | e1 (e1) | c1, c2 | 1 | 4 | 0 | 1 | 1 | 0 | 0 |
| `previewd-approval-reboot.cfg` | revalidated rebuild after reboot | e1 (e1) | c1 | 1 | 3 | 1 | 0 | 0 | 0 | 0 |
| `previewd-mixed.cfg` | trusted and untrusted together, lock across trust | e1, e2 (e2) | c1 | 2 | 3 | 0 | 0 | 0 | 0 | 0 |
| `previewd-prune.cfg` | watermark, pruned deliveries | e1 (none) | c1 | 1 | 4 | 1 | 0 | 0 | 2 | 0 |
| `previewd-ttl.cfg` | expiry through the queue | e1 (none) | c1 | 1 | 2 | 0 | 0 | 0 | 0 | 1 |

The MVP regression configurations run the restructured model. Their state counts will differ from the MVP's (634,821 and 2,779,645) because GitHub is now an explicit process. Every MVP property must still hold, and every MVP mutant must still be killed.

### 6.2 Why these bounds are enough

Small-scope argument, stated so a reviewer can challenge it:
- **Two commits** are the least that express "approval of another commit", "a push revokes", and "an approval delivered after the PR moved on".
- **One untrusted environment** carries every approval rule, since approvals never cross environments (the store keys them by environment).
- **Interactions across environments** are trust-independent apart from the lock. `previewd-mixed.cfg` and the MVP configurations cover them.
- **`Grace = 1`** exercises the fail-closed path; larger values only delay it.
- **Pruning** is over-approximated (any terminal non-latest job, at any time), so a bounded `MaxPrunes = 2` explores both "prune before the next delivery" and "prune between replays".

## 7. Acceptance criteria

A1 is accepted when every configuration of 6.1 passes within budget, coverage shows every new action producing states with no unevaluated sub-expression, and every mutant below is killed by the named property in the named configuration. The mutants are applied to the translated model, as in Phase 2. The MVP mutants (12, plus the route mutants) are re-run on the regression configurations.

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

Out of model, and checked by Go tests instead:
- an untrusted deploy receiving trusted secrets (`Injector.Section`);
- approver matched by login instead of ID;
- the V1-I7 time binding;
- TLS and the CIDR filter;
- the preflight and the build probe.

The task list names the test for each.

## 8. Mapping to the state-machine test (A2)

| Model action | Store method (V1 spec 3.4) | SPBT command |
|---|---|---|
| `ReceiveWebhook` deploy/teardown | `Enqueue` (watermark-aware) | `ReceiveWebhook` (existing, plus commit) |
| `ReceiveWebhook` grant | `Approve` | `Approve(env, commit)` |
| `ReceiveWebhook` revoke | `Revoke` | `Revoke(env, commit)` |
| `AuthorizeDeploy` allow / park / fault | `Classify`, `Park`, `Requeue` | `Authorize(outcome)` with a fake GitHub truth |
| `Revalidate`, `Expire` | `LiveUntrusted`, `Expired`, `EnqueueInternal` | `Revalidate`, `Expire` |
| `Prune` | `Prune` | `Prune` |
| GitHub actions, `Tick` | none (test-side truth) | `Push`, `PermissionLoss`, `AdvanceClock` |

The SPBT reference model implements sections 1 to 4 independently of the store, as in Phase 3.

## 9. Spec changes from this design

- **S-1 (applied with this note):** `approvals` stores `granted_seq` and `revoked_seq` (delivery order) instead of relying on timestamps. Liveness of an approval is "a grant newer than every revocation of the same `(repo, pr, commit, approver)`".
- **S-2 (applied):** A0 inserted before A1 in the task list. A1 means "implement this note".
- **D-V1-5 (to decide, recorded in the spec):** the re-validation loop re-checks untrusted environments only. A same-repo PR whose opener loses write access keeps its trusted environment, with the full secret set, until the next event. Proposal: re-validate the opener's permission for trusted environments too (same loop, same grace), and model it as `PermissionLoss` on trusted environments (it then joins `previewd-mixed.cfg`).
