------------------------------ MODULE previewd ------------------------------
(***************************************************************************)
(* previewd orchestration model, V1 (docs/formal/V1-model.md, task A1).   *)
(*                                                                         *)
(* Flow: GitHub (explicit, unfair) -> signed deliveries reordered by the   *)
(* network -> Api (SQLite queue, approvals) -> Workers (authorize, deploy, *)
(* teardown) -> host environments; Supervisor (startup sweep), Revalidator *)
(* and Expirer (fair previewd loops), Pruner and Chaos (unfair).           *)
(*                                                                         *)
(* MVP deviations, still in force (docs/specs/formal_verification_plan.md):*)
(*   D1 a delivery at or below the highest seq of its environment is stale *)
(*   D2 the sweep requeues an interrupted teardown                         *)
(*   D3 the sweep keeps only intact environments built by the newest       *)
(*      executed job, and re-arms a latest SUCCESS deploy it removed       *)
(*   D4 SKIPPED is terminal; D5 Safety 2 is the prose rule                 *)
(* V1 (V1-model.md): commit identity, trust from GitHub truth (D-V1-5),    *)
(* order-independent approvals, AuthorizeDeploy with park, revocation,     *)
(* continuous re-validation with a fail-closed grace, expiry, pruning      *)
(* behind a never-pruned watermark. Every V1 feature is off when its       *)
(* constant is 0 or empty: previewd.cfg and previewd-workers.cfg are the   *)
(* MVP regression configurations.                                          *)
(*                                                                         *)
(* Abstractions: one global clock stamps GitHub deliveries (UUIDv1 ticks  *)
(* and now, synchronized within the skew bound); an internal job takes     *)
(* the seq just above its environment's latest intent (A2-2); each label  *)
(* is one atomic step; Docker deploy faults are                            *)
(* unbounded and terminal, teardown and GHES faults bounded; secrets       *)
(* sections, TLS, the preflight and the build probe are tested in Go.     *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxWebhooks,        \* GitHub actions that emit a delivery (redeliveries included)
    EnvIDs,             \* environment IDs (internal/envid)
    Workers,            \* reconciler workers
    MaxCrashes,         \* SimulateCrash budget
    MaxFaults,          \* transient Docker failures during teardown
    SecretChannel,      \* how ExecuteDeploy hands secrets to the container
    Commits,            \* commit identifiers
    UntrustedEnvs,      \* PRs from forks or external authors
    MaxPermissionLoss,  \* silent losses of write access (approver or opener)
    MaxGhesFaults,      \* GHES unavailable during AuthorizeDeploy or Revalidate
    Grace,              \* consecutive unavailable re-validations before teardown
    MaxPrunes,          \* Prune steps
    TTL,                \* environment lifetime in clock ticks; 0 disables expiry
    MaxTicks            \* Tick steps (time passing without events)

NoCommit == "none"
JobTypes == {"deploy", "teardown"}
DeliveryKinds == {"deploy", "teardown", "grant", "revoke"}
Statuses == {"PENDING_APPROVAL", "QUEUED", "IN_PROGRESS", "SUCCESS", "FAILED", "SKIPPED"}
Terminal == {"SUCCESS", "FAILED", "SKIPPED"}
Executed == {"IN_PROGRESS", "SUCCESS", "FAILED"}
Origins == {"webhook", "approval", "revocation", "revalidation", "ttl"}
AuthzValues == {"none", "trusted", "approved"}

\* ramfs_ro_bind is the shipped design; the others put secret bytes on a
\* block device and exist so a mutation run can prove Safety 1 bites.
SecretChannels == {"ramfs_ro_bind", "tmpfs", "container_env", "build_arg"}
DiskBackedChannels == {"tmpfs", "container_env", "build_arg"}

\* Upper bound of the clock: GitHub emissions plus ticks. Internal jobs do
\* not move it (A2-2). TypeOK fails if the model ever exceeds it.
ClockBound == MaxWebhooks + MaxTicks

\* Upper bound of job IDs, checked by TypeOK rather than assumed: the
\* completion property quantifies over 1..JobBound.
JobBound == 3 * MaxWebhooks

\* GitHub stamps a delivery Stamp(clock), a multiple of K. An internal job
\* takes MaxSeq(e) + 1: at most JobBound of them follow one stamp, so an
\* internal seq is never a stamp, and a delivery GitHub sent after the
\* latest recorded intent stays newer than every internal job (A2-2).
K == JobBound + 1
Stamp(t) == t * K
SeqBound == Stamp(ClockBound) + JobBound

ASSUME MaxWebhooks \in Nat \ {0}
ASSUME EnvIDs # {} /\ Workers # {} /\ Commits # {} /\ NoCommit \notin Commits
ASSUME UntrustedEnvs \subseteq EnvIDs
ASSUME {MaxCrashes, MaxFaults, MaxPermissionLoss, MaxGhesFaults, MaxPrunes, TTL, MaxTicks} \subseteq Nat
ASSUME Grace \in Nat \ {0}
ASSUME SecretChannel \in SecretChannels

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

EnvRecords == [state: {"absent", "running"}, network_bound: BOOLEAN,
               secrets_mounted: BOOLEAN, route_published: BOOLEAN,
               secrets_persisted_to_disk: BOOLEAN, deployed_ts: 0..SeqBound,
               commit: Commits \cup {NoCommit}]

Absent == [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE,
           route_published |-> FALSE, secrets_persisted_to_disk |-> FALSE,
           deployed_ts |-> 0, commit |-> NoCommit]

\* Leftover from an earlier run whose state was lost: the sweep removes it.
Stray == [Absent EXCEPT !.state = "running", !.network_bound = TRUE,
                        !.secrets_mounted = TRUE, !.route_published = TRUE]

\* Disk contamination is irreversible: destroying the container keeps it.
Destroyed(r) == [r EXCEPT !.state = "absent", !.network_bound = FALSE,
                          !.secrets_mounted = FALSE, !.route_published = FALSE,
                          !.deployed_ts = 0, !.commit = NoCommit]

Delivery(t, k, e, c) == [ts |-> t, kind |-> k, env |-> e, commit |-> c]

NewJob(typ, e, t, c, o) == [type |-> typ, env_id |-> e, ts |-> t, status |-> "QUEUED",
                            commit |-> c, origin |-> o, authz |-> "none", authzEpoch |-> 0]

ApprovalRecord(k, e, c, t) == [kind |-> k, env |-> e, commit |-> c, ts |-> t]

\* Approvals matter only for PRs that can need one: generating them for a
\* PR that can never need one would only grow the state space.
ApprovalsRelevant(e) == e \in UntrustedEnvs \/ MaxPermissionLoss > 0

(*--algorithm previewd

variables
    \* GitHub-side truth.
    head = [e \in EnvIDs |-> NoCommit],
    open = [e \in EnvIDs |-> FALSE],
    approvedGH = [e \in EnvIDs |-> {}],
    openerOK = [e \in EnvIDs |-> TRUE],
    clock = 0,
    ghActions = 0,
    permLosses = 0,
    ticks = 0,
    emitted = {},
    inflight = {},
    \* previewd: SQLite.
    deliveries = {},            \* <<ts, env>> of recorded deploy/teardown deliveries
    db_jobs = [i \in {} |-> NewJob("deploy", "none", 0, NoCommit, "webhook")],
    nextId = 1,
    approvalsDB = {},
    watermark = [e \in EnvIDs |-> 0],
    \* previewd: host and memory.
    environments \in [EnvIDs -> {Absent, Stray}],
    deployedAt = [e \in EnvIDs |-> 0],
    revalFails = [e \in EnvIDs |-> 0],
    daemon = "down",
    crashes = 0,
    faults = 0,
    ghesFaults = 0,
    prunes = 0,
    \* Ghosts, read by properties only.
    maxTs = [e \in EnvIDs |-> 0],
    prunedDeliveries = {};

define
    JobsOf(e) == {j \in DOMAIN db_jobs : db_jobs[j].env_id = e}

    \* The stale rule reads this: the highest seq ever recorded for e.
    MaxSeq(e) == Max({watermark[e]} \cup {db_jobs[j].ts : j \in JobsOf(e)})

    Latest(e) == CHOOSE j \in JobsOf(e) :
                     \A k \in JobsOf(e) : db_jobs[k].ts <= db_jobs[j].ts

    \* The per-environment lock is the IN_PROGRESS row itself.
    Locked(e) == \E j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"

    Ready == {e \in EnvIDs : ~Locked(e) /\
                             \E j \in JobsOf(e) : db_jobs[j].status = "QUEUED"}

    NewestQueued(e) ==
        CHOOSE j \in JobsOf(e) :
            /\ db_jobs[j].status = "QUEUED"
            /\ \A k \in JobsOf(e) : db_jobs[k].status = "QUEUED"
                                    => db_jobs[k].ts <= db_jobs[j].ts

    \* Trust from GitHub truth, never cached (D-V1-5).
    Trusted(e) == e \notin UntrustedEnvs /\ openerOK[e]

    IsGrant(a, e, c) == a.kind = "grant" /\ a.env = e /\ a.commit = c
    IsRevoke(a, e, c) == a.kind = "revoke" /\ a.env = e /\ a.commit = c

    \* Order-independent: a grant newer than every revocation of (e, c).
    LiveIn(A, e, c) == \E g \in A : IsGrant(g, e, c) /\
                           \A r \in A : IsRevoke(r, e, c) => r.ts < g.ts
    LiveApproval(e, c) == LiveIn(approvalsDB, e, c)
    ApprovedNow(e, c) == LiveApproval(e, c) /\ c \in approvedGH[e]
    Allowed(e, c) == Trusted(e) \/ ApprovedNow(e, c)

    Exists(e) == \/ environments[e].state = "running"
                 \/ environments[e].network_bound
                 \/ environments[e].secrets_mounted
                 \/ environments[e].route_published

    Intact(e) == /\ environments[e].state = "running"
                 /\ environments[e].network_bound
                 /\ environments[e].secrets_mounted
                 /\ environments[e].route_published

    Builder(e) == {j \in JobsOf(e) : /\ db_jobs[j].type = "deploy"
                                     /\ db_jobs[j].ts = environments[e].deployed_ts}
    BuilderSucceeded(e) == \E j \in Builder(e) : db_jobs[j].status = "SUCCESS"
    BuilderIsLatest(e) == JobsOf(e) # {} /\ Latest(e) \in Builder(e)

    PendingOf(j, e, c) == /\ db_jobs[j].env_id = e /\ db_jobs[j].commit = c
                          /\ db_jobs[j].status = "PENDING_APPROVAL"

    \* The latest intent of e deploys c: a grant needs no new job (A1-3), and
    \* a revocation of c needs a teardown (A2-1). Judged on the latest job
    \* only: an older queued deploy behind a newer intent will be skipped,
    \* and a running version behind a newer deploy will be replaced or
    \* removed by it, so neither counts.
    HeadIntentPresent(e, c) ==
        /\ JobsOf(e) # {}
        /\ db_jobs[Latest(e)].type = "deploy"
        /\ db_jobs[Latest(e)].commit = c
        /\ db_jobs[Latest(e)].status \in {"QUEUED", "IN_PROGRESS", "PENDING_APPROVAL", "SUCCESS"}

    \* A2-6: what runs was authorized by approval, and the DB no longer
    \* holds a live grant of its commit. A DB read, no GHES call: the
    \* GHES-unavailable branch of AuthorizeDeploy removes it, as the park does.
    RevokedVersionRuns(e) ==
        /\ Exists(e)
        /\ \E j \in Builder(e) : db_jobs[j].authz = "approved"
        /\ ~LiveApproval(e, environments[e].commit)

    \* Every running environment, trusted or not (D-V1-5).
    NeedsRevalidation(e) == Exists(e) /\ BuilderSucceeded(e) /\ BuilderIsLatest(e)

    Expirable(e) == /\ TTL > 0 /\ Intact(e) /\ BuilderSucceeded(e) /\ BuilderIsLatest(e)
                    /\ clock - deployedAt[e] >= TTL

    \* Terminal, not the latest of its environment, not the builder of what
    \* runs (the sweep and Safety 2 read it).
    \* Neither the builder of what exists nor a job newer than it: the
    \* sweep's Keep reads them all (A1-6; widened by F2, V1-model.md 11).
    PrunableJobs == {j \in DOMAIN db_jobs :
                        /\ db_jobs[j].status \in Terminal
                        /\ j # Latest(db_jobs[j].env_id)
                        /\ ~ /\ Exists(db_jobs[j].env_id)
                             /\ environments[db_jobs[j].env_id].deployed_ts # 0
                             /\ db_jobs[j].ts >= environments[db_jobs[j].env_id].deployed_ts}

    (***********************************************************************)
    (* StartupSweep (MVP D2, D3), on the pre-sweep state.                  *)
    (***********************************************************************)
    Keep(e) ==
        /\ Intact(e)
        /\ \E j \in Builder(e) :
              /\ db_jobs[j].status = "SUCCESS"
              /\ \A k \in JobsOf(e) :
                    db_jobs[k].ts > db_jobs[j].ts =>
                        \/ db_jobs[k].status = "QUEUED"
                        \/ /\ db_jobs[k].status = "IN_PROGRESS"
                           /\ db_jobs[k].type = "teardown"

    \* A re-armed deploy is authorized again: an untrusted environment comes
    \* back after a reboot only with a re-validated approval.
    SweptJob(j) ==
        LET r == db_jobs[j] IN
        CASE r.status = "IN_PROGRESS" /\ r.type = "deploy"   -> [r EXCEPT !.status = "FAILED"]
          [] r.status = "IN_PROGRESS" /\ r.type = "teardown" -> [r EXCEPT !.status = "QUEUED"]
          [] r.status = "SUCCESS" /\ r.type = "deploy"
               /\ j = Latest(r.env_id) /\ ~Keep(r.env_id)    -> [r EXCEPT !.status = "QUEUED",
                                                                        !.authz = "none",
                                                                        !.authzEpoch = 0]
          [] OTHER                                           -> r

    (***********************************************************************)
    (* Properties. They use their own copies of the operators a mutant may *)
    (* change, so a mutant cannot weaken the property that judges it.      *)
    (***********************************************************************)
    LiveApprovalSpec(e, c) == \E g \in approvalsDB : IsGrant(g, e, c) /\
                                  \A r \in approvalsDB : IsRevoke(r, e, c) => r.ts < g.ts
    HasGrant(e, c) == \E g \in approvalsDB : IsGrant(g, e, c)
    AllowedTruth(e, c) == Trusted(e) \/ c \in approvedGH[e]
    Running(e, c) == Intact(e) /\ environments[e].commit = c

    TypeOK ==
        /\ head \in [EnvIDs -> Commits \cup {NoCommit}]
        /\ open \in [EnvIDs -> BOOLEAN]
        /\ approvedGH \in [EnvIDs -> SUBSET Commits]
        /\ openerOK \in [EnvIDs -> BOOLEAN]
        /\ clock \in 0..ClockBound
        /\ ghActions \in 0..MaxWebhooks
        /\ \A d \in emitted \cup inflight :
              d \in [ts: {Stamp(t) : t \in 1..ClockBound}, kind: DeliveryKinds, env: EnvIDs, commit: Commits]
        /\ DOMAIN db_jobs \subseteq 1..(nextId - 1)
        /\ nextId <= JobBound + 1
        /\ \A j \in DOMAIN db_jobs :
              db_jobs[j] \in [type: JobTypes, env_id: EnvIDs, ts: 1..SeqBound,
                              status: Statuses, commit: Commits, origin: Origins,
                              authz: AuthzValues, authzEpoch: 0..MaxCrashes]
        /\ environments \in [EnvIDs -> EnvRecords]
        /\ daemon \in {"down", "up"}
        /\ crashes \in 0..MaxCrashes
        /\ faults \in 0..MaxFaults
        /\ ghesFaults \in 0..MaxGhesFaults
        /\ revalFails \in [EnvIDs -> 0..Grace]

    \* Safety 1: no secret byte ever reaches a block device.
    SafetyZeroSecretLeakage ==
        \A e \in EnvIDs : ~environments[e].secrets_persisted_to_disk

    \* Safety 2 (D5): after the sweep, everything on the host, route
    \* documents included, belongs to an IN_PROGRESS or SUCCESS deploy that
    \* no newer teardown has undone.
    Owned(e) ==
        \E j \in Builder(e) :
            /\ db_jobs[j].status \in {"IN_PROGRESS", "SUCCESS"}
            /\ ~\E k \in JobsOf(e) : /\ db_jobs[k].type = "teardown"
                                     /\ db_jobs[k].status = "SUCCESS"
                                     /\ db_jobs[k].ts > db_jobs[j].ts
    SafetyNoOrphanedResources ==
        daemon = "up" => \A e \in EnvIDs : Exists(e) => Owned(e)

    \* Safety 3: no older intent pending or running once a newer one has
    \* executed; a running environment is never older than a completed
    \* intent.
    SafetyMonotonicity ==
        /\ \A j, k \in DOMAIN db_jobs :
              /\ db_jobs[j].env_id = db_jobs[k].env_id
              /\ db_jobs[j].ts < db_jobs[k].ts
              /\ db_jobs[k].status \in Executed
              => db_jobs[j].status \notin {"QUEUED", "IN_PROGRESS"}
        /\ \A e \in EnvIDs :
              environments[e].state = "running" =>
                  \A k \in JobsOf(e) :
                      db_jobs[k].status \in {"SUCCESS", "FAILED"}
                          => db_jobs[k].ts <= environments[e].deployed_ts

    \* Per environment, as the store's UNIQUE (preview_id, seq): two
    \* environments' first internal jobs may share a seq (A2-2).
    SafetyUniqueDelivery ==
        \A j, k \in DOMAIN db_jobs :
            j # k /\ db_jobs[j].env_id = db_jobs[k].env_id => db_jobs[j].ts # db_jobs[k].ts

    SafetyOneJobPerEnv ==
        \A e \in EnvIDs :
            Cardinality({j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"}) <= 1

    SafetyRouteImpliesRunning ==
        \A e \in EnvIDs :
            environments[e].route_published => environments[e].state = "running"

    \* V1: whatever runs was authorized. An untrusted environment's builder
    \* was approved; an approval-based authorization had a grant of that
    \* exact commit in the DB.
    SafetyNoUnapprovedUntrusted ==
        daemon = "up" =>
            \A e \in EnvIDs : Exists(e) =>
                \E j \in Builder(e) :
                    /\ db_jobs[j].authz # "none"
                    /\ e \in UntrustedEnvs => db_jobs[j].authz = "approved"
                    /\ db_jobs[j].authz = "approved" => HasGrant(e, db_jobs[j].commit)

    \* V1: a parked intent is the latest, so the version it supersedes is gone.
    SafetyParkRemovesPrevious ==
        daemon = "up" =>
            \A e \in EnvIDs :
                JobsOf(e) # {} /\ db_jobs[Latest(e)].status = "PENDING_APPROVAL"
                    => ~Exists(e)

    \* V1: once the DB knows an approval is gone, a removal or a
    \* replacement is already queued.
    SafetyRevocationPending ==
        daemon = "up" =>
            \A e \in EnvIDs :
                /\ Exists(e)
                /\ \E j \in Builder(e) : db_jobs[j].status = "SUCCESS" /\ db_jobs[j].authz = "approved"
                /\ ~LiveApprovalSpec(e, environments[e].commit)
                => \E j \in JobsOf(e) :
                      /\ db_jobs[j].ts > environments[e].deployed_ts
                      /\ db_jobs[j].status \in {"QUEUED", "IN_PROGRESS", "PENDING_APPROVAL"}

    \* V1: GHES never stays unavailable Grace times in a row without the
    \* fail-closed teardown.
    SafetyFailClosedOnUnavailable == \A e \in EnvIDs : revalFails[e] < Grace

    \* V1: pruning never changes a verdict (V1-model.md section 3).
    SafetyPruneKeepsVerdicts == \A e \in EnvIDs : MaxSeq(e) = maxTs[e]
    SafetyPrunedDeliveriesStale == \A r \in prunedDeliveries : r[1] <= MaxSeq(r[2])
    SafetyPruneKeepsLatest ==
        \A e \in EnvIDs : maxTs[e] > 0 => \E j \in JobsOf(e) : db_jobs[j].ts = maxTs[e]

    \* Desired state: running at the latest job's commit iff that job is a
    \* SUCCESS deploy GitHub still allows; absent otherwise (parked included).
    Converged(e) ==
        IF /\ JobsOf(e) # {}
           /\ db_jobs[Latest(e)].type = "deploy"
           /\ db_jobs[Latest(e)].status = "SUCCESS"
           /\ AllowedTruth(e, db_jobs[Latest(e)].commit)
        THEN Running(e, db_jobs[Latest(e)].commit)
        ELSE ~Exists(e)

    \* previewd gave up on (e, c) by design: a fail-closed or expiry
    \* teardown, or a deploy of c that failed.
    GaveUp(e, c) ==
        \E j \in JobsOf(e) :
            \/ db_jobs[j].origin \in {"revalidation", "ttl"}
            \/ db_jobs[j].type = "deploy" /\ db_jobs[j].commit = c /\ db_jobs[j].status = "FAILED"
end define;

\* Append one internal job just above the latest seq of its environment:
\* it supersedes every recorded intent, and loses to any delivery GitHub
\* sent after that intent, even one still in flight (A2-2).
macro Internal(e, typ, c, o) begin
    db_jobs := db_jobs @@ (nextId :> NewJob(typ, e, MaxSeq(e) + 1, c, o));
    nextId := nextId + 1;
    maxTs[e] := MaxSeq(e) + 1;
end macro;

\* GitHub stamps and sends one delivery.
macro Emit(k, e, c) begin
    inflight := inflight \cup {Delivery(Stamp(clock + 1), k, e, c)};
    emitted := emitted \cup {Delivery(Stamp(clock + 1), k, e, c)};
    clock := clock + 1;
    ghActions := ghActions + 1;
end macro;

(***************************************************************************)
(* GitHub: human and external actions, never forced.                       *)
(***************************************************************************)
process GitHub = "github"
begin
GitHubActs:
    while TRUE do
        either
            \* opened, reopened
            await ghActions < MaxWebhooks;
            with e \in {x \in EnvIDs : ~open[x]},
                 c \in (IF head[e] = NoCommit THEN Commits ELSE {head[e]}) do
                open[e] := TRUE;
                head[e] := c;
                Emit("deploy", e, c);
            end with;
        or
            \* synchronize (a push; the same commit again is a force-push back)
            await ghActions < MaxWebhooks;
            with e \in {x \in EnvIDs : open[x]}, c \in Commits do
                head[e] := c;
                Emit("deploy", e, c);
            end with;
        or
            \* closed
            await ghActions < MaxWebhooks;
            with e \in {x \in EnvIDs : open[x]} do
                open[e] := FALSE;
                Emit("teardown", e, head[e]);
            end with;
        or
            \* an approver approves the head (review, or label under D-V1-3)
            await ghActions < MaxWebhooks;
            with e \in {x \in EnvIDs : open[x] /\ head[x] # NoCommit /\ ApprovalsRelevant(x)} do
                approvedGH[e] := approvedGH[e] \cup {head[e]};
                Emit("grant", e, head[e]);
            end with;
        or
            \* dismissal, change request, label removal
            await ghActions < MaxWebhooks;
            with e \in EnvIDs, c \in approvedGH[e] do
                approvedGH[e] := approvedGH[e] \ {c};
                Emit("revoke", e, c);
            end with;
        or
            \* GitHub redelivers a delivery (same ts, same body)
            await ghActions < MaxWebhooks;
            with d \in emitted \ inflight do
                inflight := inflight \cup {d};
                ghActions := ghActions + 1;
            end with;
        or
            \* silent loss of write access: no webhook (D-V1-5)
            await permLosses < MaxPermissionLoss;
            with e \in EnvIDs do
                if e \in UntrustedEnvs then
                    approvedGH[e] := {};
                else
                    openerOK[e] := FALSE;
                end if;
                permLosses := permLosses + 1;
            end with;
        or
            \* time passes
            await ticks < MaxTicks;
            ticks := ticks + 1;
            clock := clock + 1;
        end either;
    end while;
end process;

(***************************************************************************)
(* Api: one SQLite transaction per delivery.                               *)
(***************************************************************************)
fair process Api = "api"
begin
ReceiveWebhook:
    while TRUE do
        await daemon = "up" /\ inflight # {};
        with d \in inflight do
            inflight := inflight \ {d};
            if d.kind \in JobTypes then
                if <<d.ts, d.env>> \in deliveries then
                    skip;   \* replay
                elsif d.ts <= MaxSeq(d.env) then
                    deliveries := deliveries \cup {<<d.ts, d.env>>};   \* stale (D1)
                else
                    deliveries := deliveries \cup {<<d.ts, d.env>>};
                    db_jobs := db_jobs @@ (nextId :> NewJob(d.kind, d.env, d.ts, d.commit, "webhook"));
                    nextId := nextId + 1;
                    maxTs[d.env] := d.ts;
                    if d.kind = "deploy" then
                        \* new head: approvals of every other commit are revoked;
                        \* the deploy itself supersedes the old version.
                        approvalsDB := approvalsDB \cup
                            {ApprovalRecord("revoke", d.env, c, d.ts) : c \in Commits \ {d.commit}};
                    end if;
                end if;
            elsif d.kind = "grant" then
                with A = approvalsDB \cup {ApprovalRecord("grant", d.env, d.commit, d.ts)} do
                    approvalsDB := A;
                    if ~Trusted(d.env) /\ LiveIn(A, d.env, d.commit) then
                        \* The latest intent is the parked deploy of this commit:
                        \* unpark it. Otherwise, if the commit is still the open
                        \* head and no deploy of it is the latest intent, queue
                        \* one (newest, so nothing older can skip it).
                        if JobsOf(d.env) # {} /\ PendingOf(Latest(d.env), d.env, d.commit) then
                            db_jobs[Latest(d.env)].status := "QUEUED";
                        elsif /\ open[d.env] /\ head[d.env] = d.commit
                              /\ ~HeadIntentPresent(d.env, d.commit) then
                            Internal(d.env, "deploy", d.commit, "approval");
                        end if;
                    end if;
                end with;
            else
                with A = approvalsDB \cup {ApprovalRecord("revoke", d.env, d.commit, d.ts)} do
                    approvalsDB := A;
                    \* Judged on the latest intent (A2-1): when it deploys
                    \* another commit, that intent already removes this one
                    \* (ExecuteDeploy replaces it, the park destroys it), and
                    \* a teardown above it would skip the new head.
                    if /\ ~Trusted(d.env) /\ ~LiveIn(A, d.env, d.commit)
                       /\ HeadIntentPresent(d.env, d.commit) then
                        Internal(d.env, "teardown", d.commit, "revocation");
                    end if;
                end with;
            end if;
        end with;
    end while;
end process;

(***************************************************************************)
(* Reconciler workers. job is the lease (0 = none), epoch the crash count  *)
(* when it was taken: a lease from an earlier boot is dropped.             *)
(***************************************************************************)
fair process Worker \in Workers
variables job = 0, epoch = 0;
begin
AcquireJob:
    await daemon = "up" /\ Ready # {};
    with e \in Ready, t = NewestQueued(e) do
        \* Lease the newest intent; older queued and parked intents are skipped.
        db_jobs := [j \in DOMAIN db_jobs |->
                       IF /\ db_jobs[j].env_id = e
                          /\ \/ db_jobs[j].status = "QUEUED"
                             \/ db_jobs[j].status = "PENDING_APPROVAL" /\ db_jobs[j].ts < db_jobs[t].ts
                       THEN [db_jobs[j] EXCEPT !.status =
                                IF j = t THEN "IN_PROGRESS" ELSE "SKIPPED"]
                       ELSE db_jobs[j]];
        job := t;
        epoch := crashes;
        if db_jobs[t].type = "deploy" then
            goto AuthorizeDeploy;
        else
            goto ExecuteTeardown;
        end if;
    end with;

AuthorizeDeploy:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id, c = db_jobs[job].commit do
            either
                \* GHES unavailable: back to QUEUED. A version authorized by
                \* approval whose grant the DB no longer holds live is removed
                \* first (A2-6): a newer intent supersedes it and cannot run
                \* until GHES answers. Nothing else changes on the host.
                await ghesFaults < MaxGhesFaults;
                ghesFaults := ghesFaults + 1;
                if RevokedVersionRuns(e) then
                    environments[e] := Destroyed(environments[e]);
                end if;
                db_jobs[job].status := "QUEUED";
                job := 0;
                goto AcquireJob;
            or
                await Trusted(e);
                db_jobs[job] := [db_jobs[job] EXCEPT !.authz = "trusted", !.authzEpoch = crashes];
                goto ExecuteDeploy;
            or
                await ~Trusted(e) /\ ApprovedNow(e, c);
                db_jobs[job] := [db_jobs[job] EXCEPT !.authz = "approved", !.authzEpoch = crashes];
                goto ExecuteDeploy;
            or
                \* Park: the superseded version is removed, the intent waits.
                await ~Trusted(e) /\ ~ApprovedNow(e, c);
                environments[e] := Destroyed(environments[e]);
                db_jobs[job].status := "PENDING_APPROVAL";
                job := 0;
                goto AcquireJob;
            end either;
        end with;
    end if;

ExecuteDeploy:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id do
            either
                \* Remove the previous version, fetch, network, build, stage.
                environments[e] :=
                    [state |-> "absent", network_bound |-> TRUE,
                     secrets_mounted |-> TRUE, route_published |-> FALSE,
                     secrets_persisted_to_disk |->
                         environments[e].secrets_persisted_to_disk
                         \/ SecretChannel \in DiskBackedChannels,
                     deployed_ts |-> db_jobs[job].ts,
                     commit |-> db_jobs[job].commit];
                goto StartContainer;
            or
                environments[e] := Destroyed(environments[e]);
                db_jobs[job].status := "FAILED";
                job := 0;
                goto AcquireJob;
            end either;
        end with;
    end if;

StartContainer:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id do
            either
                environments[e].state := "running";
                goto PublishRoute;
            or
                environments[e] := Destroyed(environments[e]);
                db_jobs[job].status := "FAILED";
                job := 0;
                goto AcquireJob;
            end either;
        end with;
    end if;

PublishRoute:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id do
            either
                environments[e].route_published := TRUE;
                goto CommitDeploy;
            or
                environments[e] := Destroyed(environments[e]);
                db_jobs[job].status := "FAILED";
                job := 0;
                goto AcquireJob;
            end either;
        end with;
    end if;

CommitDeploy:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        db_jobs[job].status := "SUCCESS";
        deployedAt[db_jobs[job].env_id] := clock;
        job := 0;
        goto AcquireJob;
    end if;

ExecuteTeardown:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id do
            either
                environments[e] := Destroyed(environments[e]);
                goto CommitTeardown;
            or
                \* Transient Docker failure: back to QUEUED, never FAILED.
                await faults < MaxFaults;
                faults := faults + 1;
                db_jobs[job].status := "QUEUED";
                job := 0;
                goto AcquireJob;
            end either;
        end with;
    end if;

CommitTeardown:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        db_jobs[job].status := "SUCCESS";
        job := 0;
        goto AcquireJob;
    end if;
end process;

(***************************************************************************)
(* Revalidator: every running environment, trusted or not (D-V1-5).        *)
(***************************************************************************)
fair process Revalidator = "revalidator"
begin
Revalidate:
    while TRUE do
        await daemon = "up";
        with e \in {x \in EnvIDs : NeedsRevalidation(x)} do
            either
                \* GHES unavailable; after Grace in a row, fail closed.
                await ghesFaults < MaxGhesFaults;
                ghesFaults := ghesFaults + 1;
                if revalFails[e] + 1 >= Grace then
                    revalFails[e] := 0;
                    Internal(e, "teardown", environments[e].commit, "revalidation");
                else
                    revalFails[e] := revalFails[e] + 1;
                end if;
            or
                await revalFails[e] > 0 \/ ~Allowed(e, environments[e].commit);
                if Allowed(e, environments[e].commit) then
                    revalFails[e] := 0;
                else
                    revalFails[e] := 0;
                    \* GitHub truth now: every grant it sent so far is void.
                    if LiveApproval(e, environments[e].commit) then
                        approvalsDB := approvalsDB \cup
                            {ApprovalRecord("revoke", e, environments[e].commit, Stamp(clock))};
                    end if;
                    Internal(e, "teardown", environments[e].commit, "revalidation");
                end if;
            end either;
        end with;
    end while;
end process;

(***************************************************************************)
(* Expirer: environments past their TTL go through the queue.              *)
(***************************************************************************)
fair process Expirer = "expirer"
begin
Expire:
    while TRUE do
        await daemon = "up";
        with e \in {x \in EnvIDs : Expirable(x)} do
            Internal(e, "teardown", environments[e].commit, "ttl");
        end with;
    end while;
end process;

(***************************************************************************)
(* Pruner: retention, over-approximated (any eligible row, any time).      *)
(***************************************************************************)
process Pruner = "pruner"
begin
Prune:
    while prunes < MaxPrunes do
        await daemon = "up";
        either
            with j \in PrunableJobs do
                watermark[db_jobs[j].env_id] :=
                    Max({watermark[db_jobs[j].env_id], db_jobs[j].ts});
                db_jobs := [k \in DOMAIN db_jobs \ {j} |-> db_jobs[k]];
            end with;
        or
            with r \in {x \in deliveries : x[1] <= MaxSeq(x[2])} do
                deliveries := deliveries \ {r};
                prunedDeliveries := prunedDeliveries \cup {r};
            end with;
        end either;
        prunes := prunes + 1;
    end while;
end process;

(***************************************************************************)
(* StartupSweep: at every start, before anything is served.                *)
(***************************************************************************)
fair process Supervisor = "supervisor"
begin
StartupSweep:
    while TRUE do
        await daemon = "down";
        db_jobs := [j \in DOMAIN db_jobs |-> SweptJob(j)]
        || environments := [e \in EnvIDs |->
                               IF Keep(e) THEN environments[e]
                               ELSE Destroyed(environments[e])];
        revalFails := [e \in EnvIDs |-> 0];
        daemon := "up";
    end while;
end process;

(***************************************************************************)
(* SimulateCrash: daemon crash, or host reboot (staged secrets wiped).     *)
(***************************************************************************)
process Chaos = "chaos"
begin
SimulateCrash:
    while crashes < MaxCrashes do
        await daemon = "up";
        either
            skip;
        or
            environments := [e \in EnvIDs |->
                                [environments[e] EXCEPT !.secrets_mounted = FALSE]];
        end either;
        daemon := "down";
        crashes := crashes + 1;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES pc, head, open, approvedGH, openerOK, clock, ghActions, permLosses, 
          ticks, emitted, inflight, deliveries, db_jobs, nextId, approvalsDB, 
          watermark, environments, deployedAt, revalFails, daemon, crashes, 
          faults, ghesFaults, prunes, maxTs, prunedDeliveries

(* define statement *)
JobsOf(e) == {j \in DOMAIN db_jobs : db_jobs[j].env_id = e}


MaxSeq(e) == Max({watermark[e]} \cup {db_jobs[j].ts : j \in JobsOf(e)})

Latest(e) == CHOOSE j \in JobsOf(e) :
                 \A k \in JobsOf(e) : db_jobs[k].ts <= db_jobs[j].ts


Locked(e) == \E j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"

Ready == {e \in EnvIDs : ~Locked(e) /\
                         \E j \in JobsOf(e) : db_jobs[j].status = "QUEUED"}

NewestQueued(e) ==
    CHOOSE j \in JobsOf(e) :
        /\ db_jobs[j].status = "QUEUED"
        /\ \A k \in JobsOf(e) : db_jobs[k].status = "QUEUED"
                                => db_jobs[k].ts <= db_jobs[j].ts


Trusted(e) == e \notin UntrustedEnvs /\ openerOK[e]

IsGrant(a, e, c) == a.kind = "grant" /\ a.env = e /\ a.commit = c
IsRevoke(a, e, c) == a.kind = "revoke" /\ a.env = e /\ a.commit = c


LiveIn(A, e, c) == \E g \in A : IsGrant(g, e, c) /\
                       \A r \in A : IsRevoke(r, e, c) => r.ts < g.ts
LiveApproval(e, c) == LiveIn(approvalsDB, e, c)
ApprovedNow(e, c) == LiveApproval(e, c) /\ c \in approvedGH[e]
Allowed(e, c) == Trusted(e) \/ ApprovedNow(e, c)

Exists(e) == \/ environments[e].state = "running"
             \/ environments[e].network_bound
             \/ environments[e].secrets_mounted
             \/ environments[e].route_published

Intact(e) == /\ environments[e].state = "running"
             /\ environments[e].network_bound
             /\ environments[e].secrets_mounted
             /\ environments[e].route_published

Builder(e) == {j \in JobsOf(e) : /\ db_jobs[j].type = "deploy"
                                 /\ db_jobs[j].ts = environments[e].deployed_ts}
BuilderSucceeded(e) == \E j \in Builder(e) : db_jobs[j].status = "SUCCESS"
BuilderIsLatest(e) == JobsOf(e) # {} /\ Latest(e) \in Builder(e)

PendingOf(j, e, c) == /\ db_jobs[j].env_id = e /\ db_jobs[j].commit = c
                      /\ db_jobs[j].status = "PENDING_APPROVAL"






HeadIntentPresent(e, c) ==
    /\ JobsOf(e) # {}
    /\ db_jobs[Latest(e)].type = "deploy"
    /\ db_jobs[Latest(e)].commit = c
    /\ db_jobs[Latest(e)].status \in {"QUEUED", "IN_PROGRESS", "PENDING_APPROVAL", "SUCCESS"}




RevokedVersionRuns(e) ==
    /\ Exists(e)
    /\ \E j \in Builder(e) : db_jobs[j].authz = "approved"
    /\ ~LiveApproval(e, environments[e].commit)


NeedsRevalidation(e) == Exists(e) /\ BuilderSucceeded(e) /\ BuilderIsLatest(e)

Expirable(e) == /\ TTL > 0 /\ Intact(e) /\ BuilderSucceeded(e) /\ BuilderIsLatest(e)
                /\ clock - deployedAt[e] >= TTL





PrunableJobs == {j \in DOMAIN db_jobs :
                    /\ db_jobs[j].status \in Terminal
                    /\ j # Latest(db_jobs[j].env_id)
                    /\ ~ /\ Exists(db_jobs[j].env_id)
                         /\ environments[db_jobs[j].env_id].deployed_ts # 0
                         /\ db_jobs[j].ts >= environments[db_jobs[j].env_id].deployed_ts}




Keep(e) ==
    /\ Intact(e)
    /\ \E j \in Builder(e) :
          /\ db_jobs[j].status = "SUCCESS"
          /\ \A k \in JobsOf(e) :
                db_jobs[k].ts > db_jobs[j].ts =>
                    \/ db_jobs[k].status = "QUEUED"
                    \/ /\ db_jobs[k].status = "IN_PROGRESS"
                       /\ db_jobs[k].type = "teardown"



SweptJob(j) ==
    LET r == db_jobs[j] IN
    CASE r.status = "IN_PROGRESS" /\ r.type = "deploy"   -> [r EXCEPT !.status = "FAILED"]
      [] r.status = "IN_PROGRESS" /\ r.type = "teardown" -> [r EXCEPT !.status = "QUEUED"]
      [] r.status = "SUCCESS" /\ r.type = "deploy"
           /\ j = Latest(r.env_id) /\ ~Keep(r.env_id)    -> [r EXCEPT !.status = "QUEUED",
                                                                    !.authz = "none",
                                                                    !.authzEpoch = 0]
      [] OTHER                                           -> r





LiveApprovalSpec(e, c) == \E g \in approvalsDB : IsGrant(g, e, c) /\
                              \A r \in approvalsDB : IsRevoke(r, e, c) => r.ts < g.ts
HasGrant(e, c) == \E g \in approvalsDB : IsGrant(g, e, c)
AllowedTruth(e, c) == Trusted(e) \/ c \in approvedGH[e]
Running(e, c) == Intact(e) /\ environments[e].commit = c

TypeOK ==
    /\ head \in [EnvIDs -> Commits \cup {NoCommit}]
    /\ open \in [EnvIDs -> BOOLEAN]
    /\ approvedGH \in [EnvIDs -> SUBSET Commits]
    /\ openerOK \in [EnvIDs -> BOOLEAN]
    /\ clock \in 0..ClockBound
    /\ ghActions \in 0..MaxWebhooks
    /\ \A d \in emitted \cup inflight :
          d \in [ts: {Stamp(t) : t \in 1..ClockBound}, kind: DeliveryKinds, env: EnvIDs, commit: Commits]
    /\ DOMAIN db_jobs \subseteq 1..(nextId - 1)
    /\ nextId <= JobBound + 1
    /\ \A j \in DOMAIN db_jobs :
          db_jobs[j] \in [type: JobTypes, env_id: EnvIDs, ts: 1..SeqBound,
                          status: Statuses, commit: Commits, origin: Origins,
                          authz: AuthzValues, authzEpoch: 0..MaxCrashes]
    /\ environments \in [EnvIDs -> EnvRecords]
    /\ daemon \in {"down", "up"}
    /\ crashes \in 0..MaxCrashes
    /\ faults \in 0..MaxFaults
    /\ ghesFaults \in 0..MaxGhesFaults
    /\ revalFails \in [EnvIDs -> 0..Grace]


SafetyZeroSecretLeakage ==
    \A e \in EnvIDs : ~environments[e].secrets_persisted_to_disk




Owned(e) ==
    \E j \in Builder(e) :
        /\ db_jobs[j].status \in {"IN_PROGRESS", "SUCCESS"}
        /\ ~\E k \in JobsOf(e) : /\ db_jobs[k].type = "teardown"
                                 /\ db_jobs[k].status = "SUCCESS"
                                 /\ db_jobs[k].ts > db_jobs[j].ts
SafetyNoOrphanedResources ==
    daemon = "up" => \A e \in EnvIDs : Exists(e) => Owned(e)




SafetyMonotonicity ==
    /\ \A j, k \in DOMAIN db_jobs :
          /\ db_jobs[j].env_id = db_jobs[k].env_id
          /\ db_jobs[j].ts < db_jobs[k].ts
          /\ db_jobs[k].status \in Executed
          => db_jobs[j].status \notin {"QUEUED", "IN_PROGRESS"}
    /\ \A e \in EnvIDs :
          environments[e].state = "running" =>
              \A k \in JobsOf(e) :
                  db_jobs[k].status \in {"SUCCESS", "FAILED"}
                      => db_jobs[k].ts <= environments[e].deployed_ts



SafetyUniqueDelivery ==
    \A j, k \in DOMAIN db_jobs :
        j # k /\ db_jobs[j].env_id = db_jobs[k].env_id => db_jobs[j].ts # db_jobs[k].ts

SafetyOneJobPerEnv ==
    \A e \in EnvIDs :
        Cardinality({j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"}) <= 1

SafetyRouteImpliesRunning ==
    \A e \in EnvIDs :
        environments[e].route_published => environments[e].state = "running"




SafetyNoUnapprovedUntrusted ==
    daemon = "up" =>
        \A e \in EnvIDs : Exists(e) =>
            \E j \in Builder(e) :
                /\ db_jobs[j].authz # "none"
                /\ e \in UntrustedEnvs => db_jobs[j].authz = "approved"
                /\ db_jobs[j].authz = "approved" => HasGrant(e, db_jobs[j].commit)


SafetyParkRemovesPrevious ==
    daemon = "up" =>
        \A e \in EnvIDs :
            JobsOf(e) # {} /\ db_jobs[Latest(e)].status = "PENDING_APPROVAL"
                => ~Exists(e)



SafetyRevocationPending ==
    daemon = "up" =>
        \A e \in EnvIDs :
            /\ Exists(e)
            /\ \E j \in Builder(e) : db_jobs[j].status = "SUCCESS" /\ db_jobs[j].authz = "approved"
            /\ ~LiveApprovalSpec(e, environments[e].commit)
            => \E j \in JobsOf(e) :
                  /\ db_jobs[j].ts > environments[e].deployed_ts
                  /\ db_jobs[j].status \in {"QUEUED", "IN_PROGRESS", "PENDING_APPROVAL"}



SafetyFailClosedOnUnavailable == \A e \in EnvIDs : revalFails[e] < Grace


SafetyPruneKeepsVerdicts == \A e \in EnvIDs : MaxSeq(e) = maxTs[e]
SafetyPrunedDeliveriesStale == \A r \in prunedDeliveries : r[1] <= MaxSeq(r[2])
SafetyPruneKeepsLatest ==
    \A e \in EnvIDs : maxTs[e] > 0 => \E j \in JobsOf(e) : db_jobs[j].ts = maxTs[e]



Converged(e) ==
    IF /\ JobsOf(e) # {}
       /\ db_jobs[Latest(e)].type = "deploy"
       /\ db_jobs[Latest(e)].status = "SUCCESS"
       /\ AllowedTruth(e, db_jobs[Latest(e)].commit)
    THEN Running(e, db_jobs[Latest(e)].commit)
    ELSE ~Exists(e)



GaveUp(e, c) ==
    \E j \in JobsOf(e) :
        \/ db_jobs[j].origin \in {"revalidation", "ttl"}
        \/ db_jobs[j].type = "deploy" /\ db_jobs[j].commit = c /\ db_jobs[j].status = "FAILED"

VARIABLES job, epoch

vars == << pc, head, open, approvedGH, openerOK, clock, ghActions, permLosses, 
           ticks, emitted, inflight, deliveries, db_jobs, nextId, approvalsDB, 
           watermark, environments, deployedAt, revalFails, daemon, crashes, 
           faults, ghesFaults, prunes, maxTs, prunedDeliveries, job, epoch >>

ProcSet == {"github"} \cup {"api"} \cup (Workers) \cup {"revalidator"} \cup {"expirer"} \cup {"pruner"} \cup {"supervisor"} \cup {"chaos"}

Init == (* Global variables *)
        /\ head = [e \in EnvIDs |-> NoCommit]
        /\ open = [e \in EnvIDs |-> FALSE]
        /\ approvedGH = [e \in EnvIDs |-> {}]
        /\ openerOK = [e \in EnvIDs |-> TRUE]
        /\ clock = 0
        /\ ghActions = 0
        /\ permLosses = 0
        /\ ticks = 0
        /\ emitted = {}
        /\ inflight = {}
        /\ deliveries = {}
        /\ db_jobs = [i \in {} |-> NewJob("deploy", "none", 0, NoCommit, "webhook")]
        /\ nextId = 1
        /\ approvalsDB = {}
        /\ watermark = [e \in EnvIDs |-> 0]
        /\ environments \in [EnvIDs -> {Absent, Stray}]
        /\ deployedAt = [e \in EnvIDs |-> 0]
        /\ revalFails = [e \in EnvIDs |-> 0]
        /\ daemon = "down"
        /\ crashes = 0
        /\ faults = 0
        /\ ghesFaults = 0
        /\ prunes = 0
        /\ maxTs = [e \in EnvIDs |-> 0]
        /\ prunedDeliveries = {}
        (* Process Worker *)
        /\ job = [self \in Workers |-> 0]
        /\ epoch = [self \in Workers |-> 0]
        /\ pc = [self \in ProcSet |-> CASE self = "github" -> "GitHubActs"
                                        [] self = "api" -> "ReceiveWebhook"
                                        [] self \in Workers -> "AcquireJob"
                                        [] self = "revalidator" -> "Revalidate"
                                        [] self = "expirer" -> "Expire"
                                        [] self = "pruner" -> "Prune"
                                        [] self = "supervisor" -> "StartupSweep"
                                        [] self = "chaos" -> "SimulateCrash"]

GitHubActs == /\ pc["github"] = "GitHubActs"
              /\ \/ /\ ghActions < MaxWebhooks
                    /\ \E e \in {x \in EnvIDs : ~open[x]}:
                         \E c \in (IF head[e] = NoCommit THEN Commits ELSE {head[e]}):
                           /\ open' = [open EXCEPT ![e] = TRUE]
                           /\ head' = [head EXCEPT ![e] = c]
                           /\ inflight' = (inflight \cup {Delivery(Stamp(clock + 1), "deploy", e, c)})
                           /\ emitted' = (emitted \cup {Delivery(Stamp(clock + 1), "deploy", e, c)})
                           /\ clock' = clock + 1
                           /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<approvedGH, openerOK, permLosses, ticks>>
                 \/ /\ ghActions < MaxWebhooks
                    /\ \E e \in {x \in EnvIDs : open[x]}:
                         \E c \in Commits:
                           /\ head' = [head EXCEPT ![e] = c]
                           /\ inflight' = (inflight \cup {Delivery(Stamp(clock + 1), "deploy", e, c)})
                           /\ emitted' = (emitted \cup {Delivery(Stamp(clock + 1), "deploy", e, c)})
                           /\ clock' = clock + 1
                           /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<open, approvedGH, openerOK, permLosses, ticks>>
                 \/ /\ ghActions < MaxWebhooks
                    /\ \E e \in {x \in EnvIDs : open[x]}:
                         /\ open' = [open EXCEPT ![e] = FALSE]
                         /\ inflight' = (inflight \cup {Delivery(Stamp(clock + 1), "teardown", e, (head[e]))})
                         /\ emitted' = (emitted \cup {Delivery(Stamp(clock + 1), "teardown", e, (head[e]))})
                         /\ clock' = clock + 1
                         /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<head, approvedGH, openerOK, permLosses, ticks>>
                 \/ /\ ghActions < MaxWebhooks
                    /\ \E e \in {x \in EnvIDs : open[x] /\ head[x] # NoCommit /\ ApprovalsRelevant(x)}:
                         /\ approvedGH' = [approvedGH EXCEPT ![e] = approvedGH[e] \cup {head[e]}]
                         /\ inflight' = (inflight \cup {Delivery(Stamp(clock + 1), "grant", e, (head[e]))})
                         /\ emitted' = (emitted \cup {Delivery(Stamp(clock + 1), "grant", e, (head[e]))})
                         /\ clock' = clock + 1
                         /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<head, open, openerOK, permLosses, ticks>>
                 \/ /\ ghActions < MaxWebhooks
                    /\ \E e \in EnvIDs:
                         \E c \in approvedGH[e]:
                           /\ approvedGH' = [approvedGH EXCEPT ![e] = approvedGH[e] \ {c}]
                           /\ inflight' = (inflight \cup {Delivery(Stamp(clock + 1), "revoke", e, c)})
                           /\ emitted' = (emitted \cup {Delivery(Stamp(clock + 1), "revoke", e, c)})
                           /\ clock' = clock + 1
                           /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<head, open, openerOK, permLosses, ticks>>
                 \/ /\ ghActions < MaxWebhooks
                    /\ \E d \in emitted \ inflight:
                         /\ inflight' = (inflight \cup {d})
                         /\ ghActions' = ghActions + 1
                    /\ UNCHANGED <<head, open, approvedGH, openerOK, clock, permLosses, ticks, emitted>>
                 \/ /\ permLosses < MaxPermissionLoss
                    /\ \E e \in EnvIDs:
                         /\ IF e \in UntrustedEnvs
                               THEN /\ approvedGH' = [approvedGH EXCEPT ![e] = {}]
                                    /\ UNCHANGED openerOK
                               ELSE /\ openerOK' = [openerOK EXCEPT ![e] = FALSE]
                                    /\ UNCHANGED approvedGH
                         /\ permLosses' = permLosses + 1
                    /\ UNCHANGED <<head, open, clock, ghActions, ticks, emitted, inflight>>
                 \/ /\ ticks < MaxTicks
                    /\ ticks' = ticks + 1
                    /\ clock' = clock + 1
                    /\ UNCHANGED <<head, open, approvedGH, openerOK, ghActions, permLosses, emitted, inflight>>
              /\ pc' = [pc EXCEPT !["github"] = "GitHubActs"]
              /\ UNCHANGED << deliveries, db_jobs, nextId, approvalsDB, 
                              watermark, environments, deployedAt, revalFails, 
                              daemon, crashes, faults, ghesFaults, prunes, 
                              maxTs, prunedDeliveries, job, epoch >>

GitHub == GitHubActs

ReceiveWebhook == /\ pc["api"] = "ReceiveWebhook"
                  /\ daemon = "up" /\ inflight # {}
                  /\ \E d \in inflight:
                       /\ inflight' = inflight \ {d}
                       /\ IF d.kind \in JobTypes
                             THEN /\ IF <<d.ts, d.env>> \in deliveries
                                        THEN /\ TRUE
                                             /\ UNCHANGED << deliveries, 
                                                             db_jobs, nextId, 
                                                             approvalsDB, 
                                                             maxTs >>
                                        ELSE /\ IF d.ts <= MaxSeq(d.env)
                                                   THEN /\ deliveries' = (deliveries \cup {<<d.ts, d.env>>})
                                                        /\ UNCHANGED << db_jobs, 
                                                                        nextId, 
                                                                        approvalsDB, 
                                                                        maxTs >>
                                                   ELSE /\ deliveries' = (deliveries \cup {<<d.ts, d.env>>})
                                                        /\ db_jobs' = db_jobs @@ (nextId :> NewJob(d.kind, d.env, d.ts, d.commit, "webhook"))
                                                        /\ nextId' = nextId + 1
                                                        /\ maxTs' = [maxTs EXCEPT ![d.env] = d.ts]
                                                        /\ IF d.kind = "deploy"
                                                              THEN /\ approvalsDB' = (           approvalsDB \cup
                                                                                      {ApprovalRecord("revoke", d.env, c, d.ts) : c \in Commits \ {d.commit}})
                                                              ELSE /\ TRUE
                                                                   /\ UNCHANGED approvalsDB
                             ELSE /\ IF d.kind = "grant"
                                        THEN /\ LET A == approvalsDB \cup {ApprovalRecord("grant", d.env, d.commit, d.ts)} IN
                                                  /\ approvalsDB' = A
                                                  /\ IF ~Trusted(d.env) /\ LiveIn(A, d.env, d.commit)
                                                        THEN /\ IF JobsOf(d.env) # {} /\ PendingOf(Latest(d.env), d.env, d.commit)
                                                                   THEN /\ db_jobs' = [db_jobs EXCEPT ![Latest(d.env)].status = "QUEUED"]
                                                                        /\ UNCHANGED << nextId, 
                                                                                        maxTs >>
                                                                   ELSE /\ IF /\ open[d.env] /\ head[d.env] = d.commit
                                                                              /\ ~HeadIntentPresent(d.env, d.commit)
                                                                              THEN /\ db_jobs' = db_jobs @@ (nextId :> NewJob("deploy", (d.env), MaxSeq((d.env)) + 1, (d.commit), "approval"))
                                                                                   /\ nextId' = nextId + 1
                                                                                   /\ maxTs' = [maxTs EXCEPT ![(d.env)] = MaxSeq((d.env)) + 1]
                                                                              ELSE /\ TRUE
                                                                                   /\ UNCHANGED << db_jobs, 
                                                                                                   nextId, 
                                                                                                   maxTs >>
                                                        ELSE /\ TRUE
                                                             /\ UNCHANGED << db_jobs, 
                                                                             nextId, 
                                                                             maxTs >>
                                        ELSE /\ LET A == approvalsDB \cup {ApprovalRecord("revoke", d.env, d.commit, d.ts)} IN
                                                  /\ approvalsDB' = A
                                                  /\ IF /\ ~Trusted(d.env) /\ ~LiveIn(A, d.env, d.commit)
                                                        /\ HeadIntentPresent(d.env, d.commit)
                                                        THEN /\ db_jobs' = db_jobs @@ (nextId :> NewJob("teardown", (d.env), MaxSeq((d.env)) + 1, (d.commit), "revocation"))
                                                             /\ nextId' = nextId + 1
                                                             /\ maxTs' = [maxTs EXCEPT ![(d.env)] = MaxSeq((d.env)) + 1]
                                                        ELSE /\ TRUE
                                                             /\ UNCHANGED << db_jobs, 
                                                                             nextId, 
                                                                             maxTs >>
                                  /\ UNCHANGED deliveries
                  /\ pc' = [pc EXCEPT !["api"] = "ReceiveWebhook"]
                  /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                  ghActions, permLosses, ticks, emitted, 
                                  watermark, environments, deployedAt, 
                                  revalFails, daemon, crashes, faults, 
                                  ghesFaults, prunes, prunedDeliveries, job, 
                                  epoch >>

Api == ReceiveWebhook

AcquireJob(self) == /\ pc[self] = "AcquireJob"
                    /\ daemon = "up" /\ Ready # {}
                    /\ \E e \in Ready:
                         LET t == NewestQueued(e) IN
                           /\ db_jobs' = [j \in DOMAIN db_jobs |->
                                             IF /\ db_jobs[j].env_id = e
                                                /\ \/ db_jobs[j].status = "QUEUED"
                                                   \/ db_jobs[j].status = "PENDING_APPROVAL" /\ db_jobs[j].ts < db_jobs[t].ts
                                             THEN [db_jobs[j] EXCEPT !.status =
                                                      IF j = t THEN "IN_PROGRESS" ELSE "SKIPPED"]
                                             ELSE db_jobs[j]]
                           /\ job' = [job EXCEPT ![self] = t]
                           /\ epoch' = [epoch EXCEPT ![self] = crashes]
                           /\ IF db_jobs'[t].type = "deploy"
                                 THEN /\ pc' = [pc EXCEPT ![self] = "AuthorizeDeploy"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "ExecuteTeardown"]
                    /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                    ghActions, permLosses, ticks, emitted, 
                                    inflight, deliveries, nextId, approvalsDB, 
                                    watermark, environments, deployedAt, 
                                    revalFails, daemon, crashes, faults, 
                                    ghesFaults, prunes, maxTs, 
                                    prunedDeliveries >>

AuthorizeDeploy(self) == /\ pc[self] = "AuthorizeDeploy"
                         /\ IF epoch[self] # crashes
                               THEN /\ job' = [job EXCEPT ![self] = 0]
                                    /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                    /\ UNCHANGED << db_jobs, environments, 
                                                    ghesFaults >>
                               ELSE /\ LET e == db_jobs[job[self]].env_id IN
                                         LET c == db_jobs[job[self]].commit IN
                                           \/ /\ ghesFaults < MaxGhesFaults
                                              /\ ghesFaults' = ghesFaults + 1
                                              /\ IF RevokedVersionRuns(e)
                                                    THEN /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                                    ELSE /\ TRUE
                                                         /\ UNCHANGED environments
                                              /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "QUEUED"]
                                              /\ job' = [job EXCEPT ![self] = 0]
                                              /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                           \/ /\ Trusted(e)
                                              /\ db_jobs' = [db_jobs EXCEPT ![job[self]] = [db_jobs[job[self]] EXCEPT !.authz = "trusted", !.authzEpoch = crashes]]
                                              /\ pc' = [pc EXCEPT ![self] = "ExecuteDeploy"]
                                              /\ UNCHANGED <<environments, ghesFaults, job>>
                                           \/ /\ ~Trusted(e) /\ ApprovedNow(e, c)
                                              /\ db_jobs' = [db_jobs EXCEPT ![job[self]] = [db_jobs[job[self]] EXCEPT !.authz = "approved", !.authzEpoch = crashes]]
                                              /\ pc' = [pc EXCEPT ![self] = "ExecuteDeploy"]
                                              /\ UNCHANGED <<environments, ghesFaults, job>>
                                           \/ /\ ~Trusted(e) /\ ~ApprovedNow(e, c)
                                              /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                              /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "PENDING_APPROVAL"]
                                              /\ job' = [job EXCEPT ![self] = 0]
                                              /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                              /\ UNCHANGED ghesFaults
                         /\ UNCHANGED << head, open, approvedGH, openerOK, 
                                         clock, ghActions, permLosses, ticks, 
                                         emitted, inflight, deliveries, nextId, 
                                         approvalsDB, watermark, deployedAt, 
                                         revalFails, daemon, crashes, faults, 
                                         prunes, maxTs, prunedDeliveries, 
                                         epoch >>

ExecuteDeploy(self) == /\ pc[self] = "ExecuteDeploy"
                       /\ IF epoch[self] # crashes
                             THEN /\ job' = [job EXCEPT ![self] = 0]
                                  /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                  /\ UNCHANGED << db_jobs, environments >>
                             ELSE /\ LET e == db_jobs[job[self]].env_id IN
                                       \/ /\ environments' = [environments EXCEPT ![e] = [state |-> "absent", network_bound |-> TRUE,
                                                                                          secrets_mounted |-> TRUE, route_published |-> FALSE,
                                                                                          secrets_persisted_to_disk |->
                                                                                              environments[e].secrets_persisted_to_disk
                                                                                              \/ SecretChannel \in DiskBackedChannels,
                                                                                          deployed_ts |-> db_jobs[job[self]].ts,
                                                                                          commit |-> db_jobs[job[self]].commit]]
                                          /\ pc' = [pc EXCEPT ![self] = "StartContainer"]
                                          /\ UNCHANGED <<db_jobs, job>>
                                       \/ /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                          /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "FAILED"]
                                          /\ job' = [job EXCEPT ![self] = 0]
                                          /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                       /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                       ghActions, permLosses, ticks, emitted, 
                                       inflight, deliveries, nextId, 
                                       approvalsDB, watermark, deployedAt, 
                                       revalFails, daemon, crashes, faults, 
                                       ghesFaults, prunes, maxTs, 
                                       prunedDeliveries, epoch >>

StartContainer(self) == /\ pc[self] = "StartContainer"
                        /\ IF epoch[self] # crashes
                              THEN /\ job' = [job EXCEPT ![self] = 0]
                                   /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                   /\ UNCHANGED << db_jobs, environments >>
                              ELSE /\ LET e == db_jobs[job[self]].env_id IN
                                        \/ /\ environments' = [environments EXCEPT ![e].state = "running"]
                                           /\ pc' = [pc EXCEPT ![self] = "PublishRoute"]
                                           /\ UNCHANGED <<db_jobs, job>>
                                        \/ /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                           /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "FAILED"]
                                           /\ job' = [job EXCEPT ![self] = 0]
                                           /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                        /\ UNCHANGED << head, open, approvedGH, openerOK, 
                                        clock, ghActions, permLosses, ticks, 
                                        emitted, inflight, deliveries, nextId, 
                                        approvalsDB, watermark, deployedAt, 
                                        revalFails, daemon, crashes, faults, 
                                        ghesFaults, prunes, maxTs, 
                                        prunedDeliveries, epoch >>

PublishRoute(self) == /\ pc[self] = "PublishRoute"
                      /\ IF epoch[self] # crashes
                            THEN /\ job' = [job EXCEPT ![self] = 0]
                                 /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                 /\ UNCHANGED << db_jobs, environments >>
                            ELSE /\ LET e == db_jobs[job[self]].env_id IN
                                      \/ /\ environments' = [environments EXCEPT ![e].route_published = TRUE]
                                         /\ pc' = [pc EXCEPT ![self] = "CommitDeploy"]
                                         /\ UNCHANGED <<db_jobs, job>>
                                      \/ /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                         /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "FAILED"]
                                         /\ job' = [job EXCEPT ![self] = 0]
                                         /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                      /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                      ghActions, permLosses, ticks, emitted, 
                                      inflight, deliveries, nextId, 
                                      approvalsDB, watermark, deployedAt, 
                                      revalFails, daemon, crashes, faults, 
                                      ghesFaults, prunes, maxTs, 
                                      prunedDeliveries, epoch >>

CommitDeploy(self) == /\ pc[self] = "CommitDeploy"
                      /\ IF epoch[self] # crashes
                            THEN /\ job' = [job EXCEPT ![self] = 0]
                                 /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                 /\ UNCHANGED << db_jobs, deployedAt >>
                            ELSE /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "SUCCESS"]
                                 /\ deployedAt' = [deployedAt EXCEPT ![db_jobs'[job[self]].env_id] = clock]
                                 /\ job' = [job EXCEPT ![self] = 0]
                                 /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                      /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                      ghActions, permLosses, ticks, emitted, 
                                      inflight, deliveries, nextId, 
                                      approvalsDB, watermark, environments, 
                                      revalFails, daemon, crashes, faults, 
                                      ghesFaults, prunes, maxTs, 
                                      prunedDeliveries, epoch >>

ExecuteTeardown(self) == /\ pc[self] = "ExecuteTeardown"
                         /\ IF epoch[self] # crashes
                               THEN /\ job' = [job EXCEPT ![self] = 0]
                                    /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                    /\ UNCHANGED << db_jobs, environments, 
                                                    faults >>
                               ELSE /\ LET e == db_jobs[job[self]].env_id IN
                                         \/ /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                            /\ pc' = [pc EXCEPT ![self] = "CommitTeardown"]
                                            /\ UNCHANGED <<db_jobs, faults, job>>
                                         \/ /\ faults < MaxFaults
                                            /\ faults' = faults + 1
                                            /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "QUEUED"]
                                            /\ job' = [job EXCEPT ![self] = 0]
                                            /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                            /\ UNCHANGED environments
                         /\ UNCHANGED << head, open, approvedGH, openerOK, 
                                         clock, ghActions, permLosses, ticks, 
                                         emitted, inflight, deliveries, nextId, 
                                         approvalsDB, watermark, deployedAt, 
                                         revalFails, daemon, crashes, 
                                         ghesFaults, prunes, maxTs, 
                                         prunedDeliveries, epoch >>

CommitTeardown(self) == /\ pc[self] = "CommitTeardown"
                        /\ IF epoch[self] # crashes
                              THEN /\ job' = [job EXCEPT ![self] = 0]
                                   /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                   /\ UNCHANGED db_jobs
                              ELSE /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "SUCCESS"]
                                   /\ job' = [job EXCEPT ![self] = 0]
                                   /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                        /\ UNCHANGED << head, open, approvedGH, openerOK, 
                                        clock, ghActions, permLosses, ticks, 
                                        emitted, inflight, deliveries, nextId, 
                                        approvalsDB, watermark, environments, 
                                        deployedAt, revalFails, daemon, 
                                        crashes, faults, ghesFaults, prunes, 
                                        maxTs, prunedDeliveries, epoch >>

Worker(self) == AcquireJob(self) \/ AuthorizeDeploy(self)
                   \/ ExecuteDeploy(self) \/ StartContainer(self)
                   \/ PublishRoute(self) \/ CommitDeploy(self)
                   \/ ExecuteTeardown(self) \/ CommitTeardown(self)

Revalidate == /\ pc["revalidator"] = "Revalidate"
              /\ daemon = "up"
              /\ \E e \in {x \in EnvIDs : NeedsRevalidation(x)}:
                   \/ /\ ghesFaults < MaxGhesFaults
                      /\ ghesFaults' = ghesFaults + 1
                      /\ IF revalFails[e] + 1 >= Grace
                            THEN /\ revalFails' = [revalFails EXCEPT ![e] = 0]
                                 /\ db_jobs' = db_jobs @@ (nextId :> NewJob("teardown", e, MaxSeq(e) + 1, (environments[e].commit), "revalidation"))
                                 /\ nextId' = nextId + 1
                                 /\ maxTs' = [maxTs EXCEPT ![e] = MaxSeq(e) + 1]
                            ELSE /\ revalFails' = [revalFails EXCEPT ![e] = revalFails[e] + 1]
                                 /\ UNCHANGED << db_jobs, nextId, maxTs >>
                      /\ UNCHANGED approvalsDB
                   \/ /\ revalFails[e] > 0 \/ ~Allowed(e, environments[e].commit)
                      /\ IF Allowed(e, environments[e].commit)
                            THEN /\ revalFails' = [revalFails EXCEPT ![e] = 0]
                                 /\ UNCHANGED << db_jobs, nextId, approvalsDB, 
                                                 maxTs >>
                            ELSE /\ revalFails' = [revalFails EXCEPT ![e] = 0]
                                 /\ IF LiveApproval(e, environments[e].commit)
                                       THEN /\ approvalsDB' = (           approvalsDB \cup
                                                               {ApprovalRecord("revoke", e, environments[e].commit, Stamp(clock))})
                                       ELSE /\ TRUE
                                            /\ UNCHANGED approvalsDB
                                 /\ db_jobs' = db_jobs @@ (nextId :> NewJob("teardown", e, MaxSeq(e) + 1, (environments[e].commit), "revalidation"))
                                 /\ nextId' = nextId + 1
                                 /\ maxTs' = [maxTs EXCEPT ![e] = MaxSeq(e) + 1]
                      /\ UNCHANGED ghesFaults
              /\ pc' = [pc EXCEPT !["revalidator"] = "Revalidate"]
              /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                              ghActions, permLosses, ticks, emitted, inflight, 
                              deliveries, watermark, environments, deployedAt, 
                              daemon, crashes, faults, prunes, 
                              prunedDeliveries, job, epoch >>

Revalidator == Revalidate

Expire == /\ pc["expirer"] = "Expire"
          /\ daemon = "up"
          /\ \E e \in {x \in EnvIDs : Expirable(x)}:
               /\ db_jobs' = db_jobs @@ (nextId :> NewJob("teardown", e, MaxSeq(e) + 1, (environments[e].commit), "ttl"))
               /\ nextId' = nextId + 1
               /\ maxTs' = [maxTs EXCEPT ![e] = MaxSeq(e) + 1]
          /\ pc' = [pc EXCEPT !["expirer"] = "Expire"]
          /\ UNCHANGED << head, open, approvedGH, openerOK, clock, ghActions, 
                          permLosses, ticks, emitted, inflight, deliveries, 
                          approvalsDB, watermark, environments, deployedAt, 
                          revalFails, daemon, crashes, faults, ghesFaults, 
                          prunes, prunedDeliveries, job, epoch >>

Expirer == Expire

Prune == /\ pc["pruner"] = "Prune"
         /\ IF prunes < MaxPrunes
               THEN /\ daemon = "up"
                    /\ \/ /\ \E j \in PrunableJobs:
                               /\ watermark' = [watermark EXCEPT ![db_jobs[j].env_id] = Max({watermark[db_jobs[j].env_id], db_jobs[j].ts})]
                               /\ db_jobs' = [k \in DOMAIN db_jobs \ {j} |-> db_jobs[k]]
                          /\ UNCHANGED <<deliveries, prunedDeliveries>>
                       \/ /\ \E r \in {x \in deliveries : x[1] <= MaxSeq(x[2])}:
                               /\ deliveries' = deliveries \ {r}
                               /\ prunedDeliveries' = (prunedDeliveries \cup {r})
                          /\ UNCHANGED <<db_jobs, watermark>>
                    /\ prunes' = prunes + 1
                    /\ pc' = [pc EXCEPT !["pruner"] = "Prune"]
               ELSE /\ pc' = [pc EXCEPT !["pruner"] = "Done"]
                    /\ UNCHANGED << deliveries, db_jobs, watermark, prunes, 
                                    prunedDeliveries >>
         /\ UNCHANGED << head, open, approvedGH, openerOK, clock, ghActions, 
                         permLosses, ticks, emitted, inflight, nextId, 
                         approvalsDB, environments, deployedAt, revalFails, 
                         daemon, crashes, faults, ghesFaults, maxTs, job, 
                         epoch >>

Pruner == Prune

StartupSweep == /\ pc["supervisor"] = "StartupSweep"
                /\ daemon = "down"
                /\ /\ db_jobs' = [j \in DOMAIN db_jobs |-> SweptJob(j)]
                   /\ environments' = [e \in EnvIDs |->
                                          IF Keep(e) THEN environments[e]
                                          ELSE Destroyed(environments[e])]
                /\ revalFails' = [e \in EnvIDs |-> 0]
                /\ daemon' = "up"
                /\ pc' = [pc EXCEPT !["supervisor"] = "StartupSweep"]
                /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                ghActions, permLosses, ticks, emitted, 
                                inflight, deliveries, nextId, approvalsDB, 
                                watermark, deployedAt, crashes, faults, 
                                ghesFaults, prunes, maxTs, prunedDeliveries, 
                                job, epoch >>

Supervisor == StartupSweep

SimulateCrash == /\ pc["chaos"] = "SimulateCrash"
                 /\ IF crashes < MaxCrashes
                       THEN /\ daemon = "up"
                            /\ \/ /\ TRUE
                                  /\ UNCHANGED environments
                               \/ /\ environments' = [e \in EnvIDs |->
                                                         [environments[e] EXCEPT !.secrets_mounted = FALSE]]
                            /\ daemon' = "down"
                            /\ crashes' = crashes + 1
                            /\ pc' = [pc EXCEPT !["chaos"] = "SimulateCrash"]
                       ELSE /\ pc' = [pc EXCEPT !["chaos"] = "Done"]
                            /\ UNCHANGED << environments, daemon, crashes >>
                 /\ UNCHANGED << head, open, approvedGH, openerOK, clock, 
                                 ghActions, permLosses, ticks, emitted, 
                                 inflight, deliveries, db_jobs, nextId, 
                                 approvalsDB, watermark, deployedAt, 
                                 revalFails, faults, ghesFaults, prunes, maxTs, 
                                 prunedDeliveries, job, epoch >>

Chaos == SimulateCrash

Next == GitHub \/ Api \/ Revalidator \/ Expirer \/ Pruner \/ Supervisor
           \/ Chaos
           \/ (\E self \in Workers: Worker(self))

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Api)
        /\ \A self \in Workers : WF_vars(Worker(self))
        /\ WF_vars(Revalidator)
        /\ WF_vars(Expirer)
        /\ WF_vars(Supervisor)

\* END TRANSLATION

-----------------------------------------------------------------------------
(***************************************************************************)
(* Properties over pc and primed state.                                    *)
(***************************************************************************)

DeployStages == {"ExecuteDeploy", "StartContainer", "PublishRoute", "CommitDeploy"}

\* Every lease of the current boot points at an IN_PROGRESS job, and no two
\* workers hold the same job.
SafetyLeases ==
    /\ \A w \in Workers :
          job[w] # 0 /\ epoch[w] = crashes =>
              /\ job[w] \in DOMAIN db_jobs
              /\ db_jobs[job[w]].status = "IN_PROGRESS"
    /\ \A w1, w2 \in Workers :
          w1 # w2 /\ job[w1] # 0 /\ epoch[w1] = crashes
                  /\ epoch[w2] = crashes => job[w1] # job[w2]

\* V1: a deploy past AuthorizeDeploy was authorized in this boot.
SafetyAuthorizedThisBoot ==
    \A w \in Workers :
        pc[w] \in DeployStages /\ epoch[w] = crashes /\ job[w] \in DOMAIN db_jobs =>
            /\ db_jobs[job[w]].authz # "none"
            /\ db_jobs[job[w]].authzEpoch = crashes

\* Safety 3 on every transition: a job becomes IN_PROGRESS only if it is
\* newer than every executed job of its environment.
SafetyMonotonicStep ==
    [][\A j \in DOMAIN db_jobs \cap DOMAIN db_jobs' :
          db_jobs[j].status # "IN_PROGRESS" /\ db_jobs'[j].status = "IN_PROGRESS" =>
              \A k \in JobsOf(db_jobs[j].env_id) \ {j} :
                  db_jobs[k].status \in Executed => db_jobs[k].ts < db_jobs[j].ts
      ]_vars

\* V1: authorization reads the DB and GitHub truth in the same step.
SafetyAuthorizeChecksBoth ==
    [][\A j \in DOMAIN db_jobs \cap DOMAIN db_jobs' :
          /\ db_jobs[j].authz = "none" /\ db_jobs'[j].authz = "approved" =>
                 /\ LiveApprovalSpec(db_jobs[j].env_id, db_jobs[j].commit)
                 /\ db_jobs[j].commit \in approvedGH[db_jobs[j].env_id]
          /\ db_jobs[j].authz = "none" /\ db_jobs'[j].authz = "trusted" =>
                 Trusted(db_jobs[j].env_id)
      ]_vars

\* V1: only a live grant of the exact commit unparks a job.
SafetyApprovalBindsCommit ==
    [][\A j \in DOMAIN db_jobs \cap DOMAIN db_jobs' :
          db_jobs[j].status = "PENDING_APPROVAL" /\ db_jobs'[j].status = "QUEUED" =>
              (LiveApprovalSpec(db_jobs[j].env_id, db_jobs[j].commit))'
      ]_vars

\* V1, A2-6: a GHES-unavailable AuthorizeDeploy never leaves running a
\* version authorized by approval whose grant the DB no longer holds live.
\* Without it, a revoked version superseded by a newer deploy (a push, or
\* a revocation whose latest intent deploys another commit, A2-1) runs for
\* the whole outage: the Revalidator skips it, since its builder is not
\* the latest job.
SafetyUnavailableRemovesRevoked ==
    [][\A w \in Workers :
          pc[w] = "AuthorizeDeploy" /\ pc'[w] = "AcquireJob" /\ ghesFaults' = ghesFaults + 1 =>
              \* A bound variable, not a LET: priming re-evaluates a LET in
              \* the next state, where job[w] is already 0.
              \A e \in {db_jobs[job[w]].env_id} :
              ~(/\ (Exists(e))'
                /\ (\E j \in Builder(e) : db_jobs[j].authz = "approved")'
                /\ (~LiveApprovalSpec(e, environments[e].commit))')
      ]_vars

\* V1: an internal job is above every seq of its environment.
SafetyInternalJobsAreNewest ==
    [][\A j \in DOMAIN db_jobs' \ DOMAIN db_jobs :
          db_jobs'[j].origin # "webhook" => db_jobs'[j].ts > MaxSeq(db_jobs'[j].env_id)
      ]_vars

\* Every queued job reaches a terminal state or waits for an approval.
LivenessEventualCompletion ==
    \A j \in 1..JobBound :
        (j \in DOMAIN db_jobs /\ db_jobs[j].status = "QUEUED")
            ~> (j \notin DOMAIN db_jobs
                \/ db_jobs[j].status \in Terminal \cup {"PENDING_APPROVAL"})

\* GitHub quiet, crashes and faults spent: the host matches the latest
\* intent GitHub still allows.
LivenessEventualConsistency ==
    <>[](\A e \in EnvIDs : Converged(e))

\* V1, D-V1-5: access lost in GitHub (revoked approval, approver or opener
\* without write access) eventually tears the environment down.
LivenessRevokedTornDown ==
    \A e \in EnvIDs :
        (Exists(e) /\ BuilderSucceeded(e) /\ ~AllowedTruth(e, environments[e].commit))
            ~> (~Exists(e) \/ AllowedTruth(e, environments[e].commit))

\* V1: an expired environment leaves through the queue.
LivenessExpired ==
    \A e \in EnvIDs :
        (TTL > 0 /\ Intact(e) /\ BuilderSucceeded(e) /\ BuilderIsLatest(e)
                 /\ clock - deployedAt[e] >= TTL)
            ~> (~Exists(e) \/ ~BuilderIsLatest(e))

\* V1: the open head GitHub allows (trusted, or approved and recorded)
\* eventually runs, unless it changed or previewd gave up by design.
LivenessHeadDeployed ==
    \A e \in EnvIDs, c \in Commits :
        (open[e] /\ head[e] = c /\ AllowedTruth(e, c)
                 /\ (Trusted(e) \/ LiveApprovalSpec(e, c)))
            ~> (\/ Running(e, c)
                \/ ~(open[e] /\ head[e] = c /\ AllowedTruth(e, c))
                \/ GaveUp(e, c))

=============================================================================
