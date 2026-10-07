------------------------------ MODULE previewd ------------------------------
(***************************************************************************)
(* Phase 2 of docs/specs/formal_verification_plan.md: the orchestration   *)
(* flow Webhook API -> SQLite queue (db_jobs) -> Reconciler -> physical    *)
(* environments, with crashes and host reboots.                           *)
(*                                                                         *)
(* This is the reference model of the target design. The shipped code     *)
(* still queues in memory (orchestrator.WorkerPool) and tears down inside  *)
(* the webhook handler; Phase 3 implements store/jobs.go against it.       *)
(*                                                                         *)
(* Actors                                                                  *)
(*   Api         internal/api: signed delivery -> one SQLite transaction   *)
(*   Worker      reconciler workers, one lease (job) each                  *)
(*   Supervisor  daemon start: StartupSweep, then serve                    *)
(*   Chaos       SimulateCrash: daemon crash or host reboot (not fair)     *)
(*                                                                         *)
(* Abstractions                                                            *)
(*   - Delivery order is ts in 1..MaxWebhooks (GitHub's emission order).   *)
(*     The network reorders freely: ReceiveWebhook picks any ts.           *)
(*   - Each label is one atomic step: a SQLite transaction, or one Docker  *)
(*     call whose effect is visible before the next commit.                *)
(*   - Docker faults: deploy steps may fail at any time (terminal);        *)
(*     teardown fails at most MaxFaults times (transient), then succeeds.  *)
(*   - Backoff, timeouts and the sweep's own Docker errors are not modeled.*)
(*                                                                         *)
(* Deviations from the plan, each forced by a TLC counterexample:         *)
(*   D1 ReceiveWebhook discards a delivery when ANY newer job exists for   *)
(*      the environment. The plan only counts QUEUED/IN_PROGRESS/SUCCESS, *)
(*      so after a newer deploy FAILED an older commit was deployed.       *)
(*   D2 StartupSweep requeues an interrupted teardown instead of failing   *)
(*      it: a FAILED teardown is terminal and its resources would leak.    *)
(*   D3 StartupSweep keeps an environment only when it is intact and its   *)
(*      builder is the newest executed job; it re-arms (QUEUED) a latest   *)
(*      SUCCESS deploy whose environment it removed (ramfs lost on reboot).*)
(*   D4 SKIPPED is terminal for Eventual Completion.                       *)
(*   D5 Safety 2 checks the prose rule. The plan's formula requires the    *)
(*      latest job to be IN_PROGRESS/SUCCESS, which a QUEUED redeploy in   *)
(*      front of a running environment violates in normal operation.       *)
(*                                                                         *)
(* Route documents are part of an environment (route_published): written  *)
(* by PublishRoute after the container starts, removed with it, and kept   *)
(* by the sweep only for an intact environment the database keeps. A       *)
(* route document anywhere else is an orphan the sweep destroys.          *)
(*                                                                         *)
(* Not modeled: payload identity. A body resent under a new (unsigned)     *)
(* delivery ID is refused by the store's payload hash (jobs.go, tested by  *)
(* the SPBT); here a delivery is identified by its ts.                     *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxWebhooks,    \* deliveries accepted before the stream pauses
    EnvIDs,         \* environment IDs (internal/envid)
    Workers,        \* reconciler workers
    MaxCrashes,     \* SimulateCrash budget
    MaxFaults,      \* transient Docker failures during teardown
    SecretChannel   \* how ExecuteDeploy hands secrets to the container

JobTypes == {"deploy", "teardown"}
Statuses == {"QUEUED", "IN_PROGRESS", "SUCCESS", "FAILED", "SKIPPED"}
Terminal == {"SUCCESS", "FAILED", "SKIPPED"}
Executed == {"IN_PROGRESS", "SUCCESS", "FAILED"}
Verdicts == {"accepted", "stale", "replay"}

\* ramfs_ro_bind is the shipped design (secrets.Stager + read-only bind).
\* The others put secret bytes on a block device: dockerd writes container
\* Env to config.v2.json, build args land in image history, tmpfs pages
\* can be swapped out. They exist so a mutation run can prove Safety 1 bites.
SecretChannels == {"ramfs_ro_bind", "tmpfs", "container_env", "build_arg"}
DiskBackedChannels == {"tmpfs", "container_env", "build_arg"}

ASSUME MaxWebhooks \in Nat \ {0}
ASSUME EnvIDs # {} /\ Workers # {}
ASSUME MaxCrashes \in Nat /\ MaxFaults \in Nat
ASSUME SecretChannel \in SecretChannels

EnvRecords == [state: {"absent", "running"}, network_bound: BOOLEAN,
               secrets_mounted: BOOLEAN, route_published: BOOLEAN,
               secrets_persisted_to_disk: BOOLEAN, deployed_ts: 0..MaxWebhooks]

Absent == [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE,
           route_published |-> FALSE, secrets_persisted_to_disk |-> FALSE,
           deployed_ts |-> 0]

\* Leftover from an earlier run whose state was lost: previewd owns it
\* (naming, labels) but no job tracks it. The sweep must remove it.
Stray == [Absent EXCEPT !.state = "running", !.network_bound = TRUE,
                        !.secrets_mounted = TRUE, !.route_published = TRUE]

\* Disk contamination is irreversible: destroying the container keeps it.
Destroyed(r) == [r EXCEPT !.state = "absent", !.network_bound = FALSE,
                          !.secrets_mounted = FALSE, !.route_published = FALSE,
                          !.deployed_ts = 0]

(*--algorithm previewd

variables
    \* Every delivery the API ingested, in arrival order, with its verdict.
    webhooks = <<>>,
    \* SQLite jobs table: job_id (index) -> [type, env_id, ts, status].
    db_jobs = <<>>,
    \* Host state per environment: container, internal network, staged secrets.
    environments \in [EnvIDs -> {Absent, Stray}],
    \* "down" until StartupSweep completes; SimulateCrash sets it back.
    daemon = "down",
    \* Crash count, also the boot epoch a worker lease belongs to.
    crashes = 0,
    faults = 0;

define
    JobsOf(e) == {j \in DOMAIN db_jobs : db_jobs[j].env_id = e}

    \* ts is unique per job (replay protection), so Latest is well defined.
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

    Delivered == {webhooks[i].ts : i \in DOMAIN webhooks}

    EventAt(ts) == webhooks[CHOOSE i \in DOMAIN webhooks : webhooks[i].ts = ts]

    Exists(e) == \/ environments[e].state = "running"
                 \/ environments[e].network_bound
                 \/ environments[e].secrets_mounted
                 \/ environments[e].route_published

    Intact(e) == /\ environments[e].state = "running"
                 /\ environments[e].network_bound
                 /\ environments[e].secrets_mounted
                 /\ environments[e].route_published

    \* The deploy job whose ts the environment carries (empty for a stray).
    Builder(e) == {j \in JobsOf(e) : /\ db_jobs[j].type = "deploy"
                                     /\ db_jobs[j].ts = environments[e].deployed_ts}

    (***********************************************************************)
    (* StartupSweep, evaluated on the pre-sweep state (D2, D3).            *)
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

    SweptJob(j) ==
        LET r == db_jobs[j] IN
        CASE r.status = "IN_PROGRESS" /\ r.type = "deploy"   -> [r EXCEPT !.status = "FAILED"]
          [] r.status = "IN_PROGRESS" /\ r.type = "teardown" -> [r EXCEPT !.status = "QUEUED"]
          [] r.status = "SUCCESS" /\ r.type = "deploy"
               /\ j = Latest(r.env_id) /\ ~Keep(r.env_id)    -> [r EXCEPT !.status = "QUEUED"]
          [] OTHER                                           -> r

    (***********************************************************************)
    (* Type invariant                                                      *)
    (***********************************************************************)
    TypeOK ==
        /\ Len(webhooks) <= MaxWebhooks
        /\ \A i \in DOMAIN webhooks :
              webhooks[i] \in [ts: 1..MaxWebhooks, type: JobTypes,
                               env_id: EnvIDs, verdict: Verdicts]
        /\ Len(db_jobs) <= MaxWebhooks
        /\ \A j \in DOMAIN db_jobs :
              db_jobs[j] \in [type: JobTypes, env_id: EnvIDs,
                              ts: 1..MaxWebhooks, status: Statuses]
        /\ environments \in [EnvIDs -> EnvRecords]
        /\ daemon \in {"down", "up"}
        /\ crashes \in 0..MaxCrashes
        /\ faults \in 0..MaxFaults

    (***********************************************************************)
    (* Safety 1: Zero Secret Leakage. Secret bytes never reach a block     *)
    (* device. Stronger than the plan's formula (running => ~persisted):   *)
    (* it also covers environments that are torn down or failed.           *)
    (***********************************************************************)
    SafetyZeroSecretLeakage ==
        \A e \in EnvIDs : ~environments[e].secrets_persisted_to_disk

    (***********************************************************************)
    (* Safety 2: No Orphaned Resources (D5). Once the sweep has run, every *)
    (* container, network, staged secret or route document belongs to the *)
    (* deploy job whose ts it carries; that job is IN_PROGRESS or SUCCESS, *)
    (* and no newer                                                        *)
    (* teardown has succeeded. Before the sweep, leftovers may exist: the  *)
    (* sweep is the control that removes them.                             *)
    (***********************************************************************)
    Owned(e) ==
        \E j \in Builder(e) :
            /\ db_jobs[j].status \in {"IN_PROGRESS", "SUCCESS"}
            /\ ~\E k \in JobsOf(e) : /\ db_jobs[k].type = "teardown"
                                     /\ db_jobs[k].status = "SUCCESS"
                                     /\ db_jobs[k].ts > db_jobs[j].ts

    SafetyNoOrphanedResources ==
        daemon = "up" => \A e \in EnvIDs : Exists(e) => Owned(e)

    (***********************************************************************)
    (* Safety 3: Monotonicity and Ordering. Once a newer intent has been   *)
    (* executed, no older intent for the same environment is pending or    *)
    (* running, and a running environment is never older than a completed  *)
    (* intent. SafetyMonotonicStep (below the translation) checks the same *)
    (* rule on every transition.                                           *)
    (***********************************************************************)
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

    (***********************************************************************)
    (* Queue integrity                                                     *)
    (***********************************************************************)
    SafetyUniqueDelivery ==
        \A j, k \in DOMAIN db_jobs : j # k => db_jobs[j].ts # db_jobs[k].ts

    \* A route document never points at a container that is not running.
    SafetyRouteImpliesRunning ==
        \A e \in EnvIDs :
            environments[e].route_published => environments[e].state = "running"

    SafetyOneJobPerEnv ==
        \A e \in EnvIDs :
            Cardinality({j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"}) <= 1

    \* Desired state: running iff the latest intent is a successful deploy.
    Converged(e) ==
        IF JobsOf(e) # {} /\ db_jobs[Latest(e)].type = "deploy"
                          /\ db_jobs[Latest(e)].status = "SUCCESS"
        THEN Intact(e) /\ environments[e].deployed_ts = db_jobs[Latest(e)].ts
        ELSE ~Exists(e)
end define;

(***************************************************************************)
(* ReceiveWebhook: one SQLite transaction per signed delivery.            *)
(***************************************************************************)
fair process Api = "api"
begin
ReceiveWebhook:
    while Len(webhooks) < MaxWebhooks do
        await daemon = "up";
        with ts \in 1..MaxWebhooks do
            if ts \in Delivered then
                \* GitHub redelivery of the same payload: replay protection.
                webhooks := Append(webhooks, [EventAt(ts) EXCEPT !.verdict = "replay"]);
            else
                with type \in JobTypes, e \in EnvIDs do
                    if \E j \in JobsOf(e) : db_jobs[j].ts > ts then
                        \* D1: a newer intent exists, whatever its status.
                        webhooks := Append(webhooks, [ts |-> ts, type |-> type,
                                                      env_id |-> e, verdict |-> "stale"]);
                    else
                        webhooks := Append(webhooks, [ts |-> ts, type |-> type,
                                                      env_id |-> e, verdict |-> "accepted"]);
                        db_jobs := Append(db_jobs, [type |-> type, env_id |-> e,
                                                    ts |-> ts, status |-> "QUEUED"]);
                    end if;
                end with;
            end if;
        end with;
    end while;
end process;

(***************************************************************************)
(* Reconciler workers. job is the lease (0 = none); epoch is the crash     *)
(* count at acquisition. A crash bumps crashes, so every later step of a   *)
(* lease from a previous boot drops it without touching state: the         *)
(* goroutine died with the process.                                        *)
(***************************************************************************)
fair process Worker \in Workers
variables job = 0, epoch = 0;
begin
AcquireJob:
    await daemon = "up" /\ Ready # {};
    with e \in Ready, t = NewestQueued(e) do
        \* Same transaction: lease the newest intent, skip the older ones.
        db_jobs := [j \in DOMAIN db_jobs |->
                       IF db_jobs[j].env_id = e /\ db_jobs[j].status = "QUEUED"
                       THEN [db_jobs[j] EXCEPT !.status =
                                IF j = t THEN "IN_PROGRESS" ELSE "SKIPPED"]
                       ELSE db_jobs[j]];
        job := t;
        epoch := crashes;
        if db_jobs[t].type = "deploy" then
            goto ExecuteDeploy;
        else
            goto ExecuteTeardown;
        end if;
    end with;

ExecuteDeploy:
    if epoch # crashes then
        job := 0;
        goto AcquireJob;
    else
        with e = db_jobs[job].env_id do
            either
                \* Destroy the previous version, fetch, create the internal
                \* network, build, stage secrets on ramfs.
                environments[e] :=
                    [state |-> "absent", network_bound |-> TRUE,
                     secrets_mounted |-> TRUE, route_published |-> FALSE,
                     secrets_persisted_to_disk |->
                         environments[e].secrets_persisted_to_disk
                         \/ SecretChannel \in DiskBackedChannels,
                     deployed_ts |-> db_jobs[job].ts];
                goto StartContainer;
            or
                \* Fetch, network, build or staging failed: roll back.
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
                \* Secrets reach the container only through the read-only
                \* bind of the ramfs staging directory, never through Env.
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
                \* Write the route document atomically (temp file, rename).
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
                \* Destroy container and network, then remove the staging.
                environments[e] := Destroyed(environments[e]);
                goto CommitTeardown;
            or
                \* Transient Docker failure: back to QUEUED (with backoff).
                \* A teardown never rests in FAILED.
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
(* StartupSweep: runs at every start, before the API and workers serve.    *)
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
        daemon := "up";
    end while;
end process;

(***************************************************************************)
(* SimulateCrash: not fair, crashes are never forced.                      *)
(*   daemon crash  process memory gone (leases, in-flight work)            *)
(*   host reboot   also wipes ramfs: every staged secret is lost; dockerd  *)
(*                 keeps containers and networks on disk                   *)
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
VARIABLES pc, webhooks, db_jobs, environments, daemon, crashes, faults

(* define statement *)
JobsOf(e) == {j \in DOMAIN db_jobs : db_jobs[j].env_id = e}


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

Delivered == {webhooks[i].ts : i \in DOMAIN webhooks}

EventAt(ts) == webhooks[CHOOSE i \in DOMAIN webhooks : webhooks[i].ts = ts]

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
           /\ j = Latest(r.env_id) /\ ~Keep(r.env_id)    -> [r EXCEPT !.status = "QUEUED"]
      [] OTHER                                           -> r




TypeOK ==
    /\ Len(webhooks) <= MaxWebhooks
    /\ \A i \in DOMAIN webhooks :
          webhooks[i] \in [ts: 1..MaxWebhooks, type: JobTypes,
                           env_id: EnvIDs, verdict: Verdicts]
    /\ Len(db_jobs) <= MaxWebhooks
    /\ \A j \in DOMAIN db_jobs :
          db_jobs[j] \in [type: JobTypes, env_id: EnvIDs,
                          ts: 1..MaxWebhooks, status: Statuses]
    /\ environments \in [EnvIDs -> EnvRecords]
    /\ daemon \in {"down", "up"}
    /\ crashes \in 0..MaxCrashes
    /\ faults \in 0..MaxFaults






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
    \A j, k \in DOMAIN db_jobs : j # k => db_jobs[j].ts # db_jobs[k].ts


SafetyRouteImpliesRunning ==
    \A e \in EnvIDs :
        environments[e].route_published => environments[e].state = "running"

SafetyOneJobPerEnv ==
    \A e \in EnvIDs :
        Cardinality({j \in JobsOf(e) : db_jobs[j].status = "IN_PROGRESS"}) <= 1


Converged(e) ==
    IF JobsOf(e) # {} /\ db_jobs[Latest(e)].type = "deploy"
                      /\ db_jobs[Latest(e)].status = "SUCCESS"
    THEN Intact(e) /\ environments[e].deployed_ts = db_jobs[Latest(e)].ts
    ELSE ~Exists(e)

VARIABLES job, epoch

vars == << pc, webhooks, db_jobs, environments, daemon, crashes, faults, job, 
           epoch >>

ProcSet == {"api"} \cup (Workers) \cup {"supervisor"} \cup {"chaos"}

Init == (* Global variables *)
        /\ webhooks = <<>>
        /\ db_jobs = <<>>
        /\ environments \in [EnvIDs -> {Absent, Stray}]
        /\ daemon = "down"
        /\ crashes = 0
        /\ faults = 0
        (* Process Worker *)
        /\ job = [self \in Workers |-> 0]
        /\ epoch = [self \in Workers |-> 0]
        /\ pc = [self \in ProcSet |-> CASE self = "api" -> "ReceiveWebhook"
                                        [] self \in Workers -> "AcquireJob"
                                        [] self = "supervisor" -> "StartupSweep"
                                        [] self = "chaos" -> "SimulateCrash"]

ReceiveWebhook == /\ pc["api"] = "ReceiveWebhook"
                  /\ IF Len(webhooks) < MaxWebhooks
                        THEN /\ daemon = "up"
                             /\ \E ts \in 1..MaxWebhooks:
                                  IF ts \in Delivered
                                     THEN /\ webhooks' = Append(webhooks, [EventAt(ts) EXCEPT !.verdict = "replay"])
                                          /\ UNCHANGED db_jobs
                                     ELSE /\ \E type \in JobTypes:
                                               \E e \in EnvIDs:
                                                 IF \E j \in JobsOf(e) : db_jobs[j].ts > ts
                                                    THEN /\ webhooks' = Append(webhooks, [ts |-> ts, type |-> type,
                                                                                          env_id |-> e, verdict |-> "stale"])
                                                         /\ UNCHANGED db_jobs
                                                    ELSE /\ webhooks' = Append(webhooks, [ts |-> ts, type |-> type,
                                                                                          env_id |-> e, verdict |-> "accepted"])
                                                         /\ db_jobs' = Append(db_jobs, [type |-> type, env_id |-> e,
                                                                                        ts |-> ts, status |-> "QUEUED"])
                             /\ pc' = [pc EXCEPT !["api"] = "ReceiveWebhook"]
                        ELSE /\ pc' = [pc EXCEPT !["api"] = "Done"]
                             /\ UNCHANGED << webhooks, db_jobs >>
                  /\ UNCHANGED << environments, daemon, crashes, faults, job, 
                                  epoch >>

Api == ReceiveWebhook

AcquireJob(self) == /\ pc[self] = "AcquireJob"
                    /\ daemon = "up" /\ Ready # {}
                    /\ \E e \in Ready:
                         LET t == NewestQueued(e) IN
                           /\ db_jobs' = [j \in DOMAIN db_jobs |->
                                             IF db_jobs[j].env_id = e /\ db_jobs[j].status = "QUEUED"
                                             THEN [db_jobs[j] EXCEPT !.status =
                                                      IF j = t THEN "IN_PROGRESS" ELSE "SKIPPED"]
                                             ELSE db_jobs[j]]
                           /\ job' = [job EXCEPT ![self] = t]
                           /\ epoch' = [epoch EXCEPT ![self] = crashes]
                           /\ IF db_jobs'[t].type = "deploy"
                                 THEN /\ pc' = [pc EXCEPT ![self] = "ExecuteDeploy"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "ExecuteTeardown"]
                    /\ UNCHANGED << webhooks, environments, daemon, crashes, 
                                    faults >>

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
                                                                                          deployed_ts |-> db_jobs[job[self]].ts]]
                                          /\ pc' = [pc EXCEPT ![self] = "StartContainer"]
                                          /\ UNCHANGED <<db_jobs, job>>
                                       \/ /\ environments' = [environments EXCEPT ![e] = Destroyed(environments[e])]
                                          /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "FAILED"]
                                          /\ job' = [job EXCEPT ![self] = 0]
                                          /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                       /\ UNCHANGED << webhooks, daemon, crashes, faults, 
                                       epoch >>

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
                        /\ UNCHANGED << webhooks, daemon, crashes, faults, 
                                        epoch >>

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
                      /\ UNCHANGED << webhooks, daemon, crashes, faults, epoch >>

CommitDeploy(self) == /\ pc[self] = "CommitDeploy"
                      /\ IF epoch[self] # crashes
                            THEN /\ job' = [job EXCEPT ![self] = 0]
                                 /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                 /\ UNCHANGED db_jobs
                            ELSE /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "SUCCESS"]
                                 /\ job' = [job EXCEPT ![self] = 0]
                                 /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                      /\ UNCHANGED << webhooks, environments, daemon, crashes, 
                                      faults, epoch >>

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
                         /\ UNCHANGED << webhooks, daemon, crashes, epoch >>

CommitTeardown(self) == /\ pc[self] = "CommitTeardown"
                        /\ IF epoch[self] # crashes
                              THEN /\ job' = [job EXCEPT ![self] = 0]
                                   /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                                   /\ UNCHANGED db_jobs
                              ELSE /\ db_jobs' = [db_jobs EXCEPT ![job[self]].status = "SUCCESS"]
                                   /\ job' = [job EXCEPT ![self] = 0]
                                   /\ pc' = [pc EXCEPT ![self] = "AcquireJob"]
                        /\ UNCHANGED << webhooks, environments, daemon, 
                                        crashes, faults, epoch >>

Worker(self) == AcquireJob(self) \/ ExecuteDeploy(self)
                   \/ StartContainer(self) \/ PublishRoute(self)
                   \/ CommitDeploy(self) \/ ExecuteTeardown(self)
                   \/ CommitTeardown(self)

StartupSweep == /\ pc["supervisor"] = "StartupSweep"
                /\ daemon = "down"
                /\ /\ db_jobs' = [j \in DOMAIN db_jobs |-> SweptJob(j)]
                   /\ environments' = [e \in EnvIDs |->
                                          IF Keep(e) THEN environments[e]
                                          ELSE Destroyed(environments[e])]
                /\ daemon' = "up"
                /\ pc' = [pc EXCEPT !["supervisor"] = "StartupSweep"]
                /\ UNCHANGED << webhooks, crashes, faults, job, epoch >>

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
                 /\ UNCHANGED << webhooks, db_jobs, faults, job, epoch >>

Chaos == SimulateCrash

Next == Api \/ Supervisor \/ Chaos
           \/ (\E self \in Workers: Worker(self))

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Api)
        /\ \A self \in Workers : WF_vars(Worker(self))
        /\ WF_vars(Supervisor)

\* END TRANSLATION

-----------------------------------------------------------------------------
(***************************************************************************)
(* Properties                                                              *)
(*                                                                         *)
(* Fairness: every fair process gets WF_vars of its next-state action.     *)
(* A worker is sequential (one label enabled at a time), so WF_vars(Worker)*)
(* is WF on each of AcquireJob, ExecuteDeploy, ExecuteTeardown; WF on the  *)
(* Supervisor is WF_vars(StartupSweep). Chaos has none.                    *)
(***************************************************************************)

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

\* Safety 3 as an action property: a job only becomes IN_PROGRESS when it is
\* newer than every executed job of its environment.
SafetyMonotonicStep ==
    [][\A j \in DOMAIN db_jobs :
          db_jobs[j].status # "IN_PROGRESS" /\ db_jobs'[j].status = "IN_PROGRESS" =>
              \A k \in JobsOf(db_jobs[j].env_id) \ {j} :
                  db_jobs[k].status \in Executed => db_jobs[k].ts < db_jobs[j].ts
      ]_vars

\* Liveness 1: Eventual Completion. Every queued job reaches a terminal state
\* (D4: SKIPPED is terminal).
LivenessEventualCompletion ==
    \A j \in 1..MaxWebhooks :
        (j \in DOMAIN db_jobs /\ db_jobs[j].status = "QUEUED")
            ~> (j \in DOMAIN db_jobs /\ db_jobs[j].status \in Terminal)

\* Liveness 2: Eventual Consistency. The stream is bounded by MaxWebhooks and
\* crashes by MaxCrashes, so it always pauses; the host then converges to the
\* latest intent of every environment and stays there.
LivenessEventualConsistency ==
    <>[](\A e \in EnvIDs : Converged(e))

=============================================================================
