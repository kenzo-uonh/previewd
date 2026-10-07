----------------------------- MODULE previewd -----------------------------
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS MaxWebhooks, EnvIDs, MaxCrashes

(* PlusCal Algorithm *)
(*--algorithm previewd
variables
  \* The physical state of the host/containers
  environments = [e \in EnvIDs |-> [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE]],
  \* The persistent SQLite database of jobs
  db_jobs = {},
  \* Bounded counters
  next_job_id = 1,
  webhooks_received = 0,
  crashes_simulated = 0,
  \* Indicates if the system is currently crashed (awaiting StartupSweep)
  is_crashed = FALSE,
  \* Reconciler state
  reconciler_active_job = [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0];

define
  \* Helper to check if any job exists for an env
  HasJob(env) == \E j \in db_jobs: j.env_id = env
  
  \* Helper to find the latest job for an env_id
  LatestJobForEnv(env) == 
    CHOOSE j \in {job \in db_jobs: job.env_id = env}:
      \A j2 \in {job \in db_jobs: job.env_id = env}: j2.ts <= j.ts

  \* Is this job the latest job for its env?
  IsLatestJob(job) ==
    \A j2 \in {j \in db_jobs: j.env_id = job.env_id}: j2.ts <= job.ts

  \* Safety 1: Zero Secret Leakage (Memory & Disk)
  SafetyZeroSecretLeakage ==
    \A env \in EnvIDs:
      (environments[env].state = "running") => (environments[env].secrets_persisted = FALSE)

  \* Safety 2: No Orphaned Resources (Physical to Logical Verification)
  SafetyNoOrphanedResources ==
    \A env \in EnvIDs:
      (environments[env].state = "running" \/ environments[env].network_bound = TRUE) =>
        ~(HasJob(env) /\ LatestJobForEnv(env).type = "teardown" /\ LatestJobForEnv(env).status = "SUCCESS")

  \* Safety 3: Monotonicity & Ordering
  \* Older webhook intents must not overwrite newer executed intents.
  SafetyStrictMonotonicity ==
    \A j1, j2 \in db_jobs:
      (j1.env_id = j2.env_id /\ j1.ts < j2.ts /\ j2.status \in {"IN_PROGRESS", "SUCCESS"}) =>
      ~(j1.status \in {"QUEUED", "IN_PROGRESS"})

  \* Liveness 1: Eventual Completion
  LivenessEventualCompletion ==
    \A env \in EnvIDs:
      \A ts \in 1..MaxWebhooks:
        (\E job \in db_jobs: job.env_id = env /\ job.ts = ts /\ job.status = "QUEUED")
        ~> 
        (\E job \in db_jobs: job.env_id = env /\ job.ts = ts /\ job.status \in {"SUCCESS", "FAILED", "SKIPPED"})

  \* Helper to check if any successful job exists for an env
  HasSuccessfulJob(env) == \E j \in db_jobs: j.env_id = env /\ j.status = "SUCCESS"
  
  \* Helper to find the latest SUCCESSFUL job for an env_id
  LatestSuccessfulJobForEnv(env) == 
    CHOOSE j \in {job \in db_jobs: job.env_id = env /\ job.status = "SUCCESS"}:
      \A j2 \in {job \in db_jobs: job.env_id = env /\ j2.status = "SUCCESS"}: j2.ts <= j.ts

  \* Liveness 2: Eventual Consistency
  \* Assuming webhook stream pauses, we guarantee that if the latest successful intent is a teardown (or none exist), it is absent.
  \* We allow successful deploys to remain absent if a crash wiped their volatile secrets.
  LivenessEventualConsistency ==
    (webhooks_received = MaxWebhooks) ~>
      (\A env \in EnvIDs:
         (~HasSuccessfulJob(env) \/ LatestSuccessfulJobForEnv(env).type = "teardown") =>
           environments[env].state = "absent")

end define;

fair process Reconciler = "reconciler_loop"
begin
ReconcilerLoop:
  while TRUE do
    if is_crashed then
      StartupSweep:
        is_crashed := FALSE;
        db_jobs := { IF j.status = "IN_PROGRESS" THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs };
        environments := [e \in EnvIDs |-> 
          IF (~HasJob(e) \/ (HasJob(e) /\ LatestJobForEnv(e).type = "teardown") \/ environments[e].secrets_mounted = FALSE) THEN
            [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE]
          ELSE
            environments[e]
        ];
    else
      if reconciler_active_job.id = 0 then
        either
            await \E j \in db_jobs: j.status = "QUEUED";
          AcquireJob:
            with e \in {env \in EnvIDs: \E j \in db_jobs: j.env_id = env /\ j.status = "QUEUED"} do
                with target \in {j \in db_jobs: j.env_id = e /\ j.status = "QUEUED" /\ \A j2 \in db_jobs: (j2.env_id = e /\ j2.status = "QUEUED") => j2.ts <= j.ts} do
                    reconciler_active_job := target;
                    db_jobs := { 
                        IF j.env_id = e /\ j.status = "QUEUED" THEN
                            IF j.id = target.id THEN [j EXCEPT !.status = "IN_PROGRESS"] ELSE [j EXCEPT !.status = "SKIPPED"]
                        ELSE j 
                        : j \in db_jobs 
                    };
                end with;
            end with;
        or
            await crashes_simulated < MaxCrashes;
          CrashFromIdle:
            is_crashed := TRUE;
            crashes_simulated := crashes_simulated + 1;
            environments := [e \in EnvIDs |-> [environments[e] EXCEPT !.secrets_mounted = FALSE]];
        or
            await ~(\E j \in db_jobs: j.status = "QUEUED") /\ crashes_simulated = MaxCrashes;
          IdleLoop:
            skip;
        end either;
      else
        either
          ExecuteAction:
            if reconciler_active_job.type = "deploy" then
                either
                    environments[reconciler_active_job.env_id] := [state |-> "running", network_bound |-> TRUE, secrets_mounted |-> TRUE, secrets_persisted |-> FALSE];
                    db_jobs := { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "SUCCESS"] ELSE j : j \in db_jobs };
                or
                    db_jobs := { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs };
                end either;
            else
                either
                    environments[reconciler_active_job.env_id] := [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE];
                    db_jobs := { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "SUCCESS"] ELSE j : j \in db_jobs };
                or
                    if reconciler_active_job.retries < 3 then
                        db_jobs := { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "QUEUED", !.retries = reconciler_active_job.retries + 1] ELSE j : j \in db_jobs };
                    else
                        db_jobs := { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs };
                    end if;
                end either;
            end if;
            reconciler_active_job := [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0];
        or
            await crashes_simulated < MaxCrashes;
          CrashDuringExecution:
            is_crashed := TRUE;
            crashes_simulated := crashes_simulated + 1;
            reconciler_active_job := [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0];
            environments := [e \in EnvIDs |-> [environments[e] EXCEPT !.secrets_mounted = FALSE]];
        end either;
      end if;
    end if;
  end while;
end process;

fair process WebhookSender = "github"
begin
SendLoop:
  while webhooks_received < MaxWebhooks do
    ReceiveWebhook:
      with type \in {"deploy", "teardown"}, e \in EnvIDs, ts \in 1..MaxWebhooks do
        if ~(\E j \in db_jobs: j.ts = ts) then
            if \E j \in db_jobs: j.env_id = e /\ j.ts > ts /\ j.status \in {"QUEUED", "IN_PROGRESS", "SUCCESS"} then
                \* Discard out of order
                webhooks_received := webhooks_received + 1;
            else
                db_jobs := db_jobs \cup {[id |-> next_job_id, type |-> type, env_id |-> e, ts |-> ts, status |-> "QUEUED", retries |-> 0]};
                next_job_id := next_job_id + 1;
                webhooks_received := webhooks_received + 1;
            end if;
        end if;
      end with;
  end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "d0c2b947" /\ chksum(tla) = "eacabd9")
VARIABLES pc, environments, db_jobs, next_job_id, webhooks_received, 
          crashes_simulated, is_crashed, reconciler_active_job

(* define statement *)
HasJob(env) == \E j \in db_jobs: j.env_id = env


LatestJobForEnv(env) ==
  CHOOSE j \in {job \in db_jobs: job.env_id = env}:
    \A j2 \in {job \in db_jobs: job.env_id = env}: j2.ts <= j.ts


IsLatestJob(job) ==
  \A j2 \in {j \in db_jobs: j.env_id = job.env_id}: j2.ts <= job.ts


SafetyZeroSecretLeakage ==
  \A env \in EnvIDs:
    (environments[env].state = "running") => (environments[env].secrets_persisted = FALSE)


SafetyNoOrphanedResources ==
  \A env \in EnvIDs:
    (environments[env].state = "running" \/ environments[env].network_bound = TRUE) =>
      ~(HasJob(env) /\ LatestJobForEnv(env).type = "teardown" /\ LatestJobForEnv(env).status = "SUCCESS")



SafetyStrictMonotonicity ==
  \A j1, j2 \in db_jobs:
    (j1.env_id = j2.env_id /\ j1.ts < j2.ts /\ j2.status \in {"IN_PROGRESS", "SUCCESS"}) =>
    ~(j1.status \in {"QUEUED", "IN_PROGRESS"})


LivenessEventualCompletion ==
  \A env \in EnvIDs:
    \A ts \in 1..MaxWebhooks:
      (\E job \in db_jobs: job.env_id = env /\ job.ts = ts /\ job.status = "QUEUED")
      ~>
      (\E job \in db_jobs: job.env_id = env /\ job.ts = ts /\ job.status \in {"SUCCESS", "FAILED", "SKIPPED"})



LivenessEventualConsistency ==
  (webhooks_received = MaxWebhooks) ~>
    (\A env \in EnvIDs:
       IF HasJob(env) /\ LatestJobForEnv(env).type = "deploy" /\ LatestJobForEnv(env).status = "SUCCESS" THEN
         environments[env].state = "running"
       ELSE
         environments[env].state = "absent")


vars == << pc, environments, db_jobs, next_job_id, webhooks_received, 
           crashes_simulated, is_crashed, reconciler_active_job >>

ProcSet == {"reconciler_loop"} \cup {"github"}

Init == (* Global variables *)
        /\ environments = [e \in EnvIDs |-> [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE]]
        /\ db_jobs = {}
        /\ next_job_id = 1
        /\ webhooks_received = 0
        /\ crashes_simulated = 0
        /\ is_crashed = FALSE
        /\ reconciler_active_job = [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0]
        /\ pc = [self \in ProcSet |-> CASE self = "reconciler_loop" -> "ReconcilerLoop"
                                        [] self = "github" -> "SendLoop"]

ReconcilerLoop == /\ pc["reconciler_loop"] = "ReconcilerLoop"
                  /\ IF is_crashed
                        THEN /\ pc' = [pc EXCEPT !["reconciler_loop"] = "StartupSweep"]
                        ELSE /\ IF reconciler_active_job.id = 0
                                   THEN /\ \/ /\ \E j \in db_jobs: j.status = "QUEUED"
                                              /\ pc' = [pc EXCEPT !["reconciler_loop"] = "AcquireJob"]
                                           \/ /\ crashes_simulated < MaxCrashes
                                              /\ pc' = [pc EXCEPT !["reconciler_loop"] = "CrashFromIdle"]
                                           \/ /\ ~(\E j \in db_jobs: j.status = "QUEUED") /\ crashes_simulated = MaxCrashes
                                              /\ pc' = [pc EXCEPT !["reconciler_loop"] = "IdleLoop"]
                                   ELSE /\ \/ /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ExecuteAction"]
                                           \/ /\ crashes_simulated < MaxCrashes
                                              /\ pc' = [pc EXCEPT !["reconciler_loop"] = "CrashDuringExecution"]
                  /\ UNCHANGED << environments, db_jobs, next_job_id, 
                                  webhooks_received, crashes_simulated, 
                                  is_crashed, reconciler_active_job >>

StartupSweep == /\ pc["reconciler_loop"] = "StartupSweep"
                /\ is_crashed' = FALSE
                /\ db_jobs' = { IF j.status = "IN_PROGRESS" THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs }
                /\ environments' =                 [e \in EnvIDs |->
                                     IF (~HasJob(e) \/ (HasJob(e) /\ LatestJobForEnv(e).type = "teardown") \/ environments[e].secrets_mounted = FALSE) THEN
                                       [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE]
                                     ELSE
                                       environments[e]
                                   ]
                /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
                /\ UNCHANGED << next_job_id, webhooks_received, 
                                crashes_simulated, reconciler_active_job >>

AcquireJob == /\ pc["reconciler_loop"] = "AcquireJob"
              /\ \E e \in {env \in EnvIDs: \E j \in db_jobs: j.env_id = env /\ j.status = "QUEUED"}:
                   \E target \in {j \in db_jobs: j.env_id = e /\ j.status = "QUEUED" /\ \A j2 \in db_jobs: (j2.env_id = e /\ j2.status = "QUEUED") => j2.ts <= j.ts}:
                     /\ reconciler_active_job' = target
                     /\ db_jobs' =            {
                                       IF j.env_id = e /\ j.status = "QUEUED" THEN
                                           IF j.id = target.id THEN [j EXCEPT !.status = "IN_PROGRESS"] ELSE [j EXCEPT !.status = "SKIPPED"]
                                       ELSE j
                                       : j \in db_jobs
                                   }
              /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
              /\ UNCHANGED << environments, next_job_id, webhooks_received, 
                              crashes_simulated, is_crashed >>

CrashFromIdle == /\ pc["reconciler_loop"] = "CrashFromIdle"
                 /\ is_crashed' = TRUE
                 /\ crashes_simulated' = crashes_simulated + 1
                 /\ environments' = [e \in EnvIDs |-> [environments[e] EXCEPT !.secrets_mounted = FALSE]]
                 /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
                 /\ UNCHANGED << db_jobs, next_job_id, webhooks_received, 
                                 reconciler_active_job >>

IdleLoop == /\ pc["reconciler_loop"] = "IdleLoop"
            /\ TRUE
            /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
            /\ UNCHANGED << environments, db_jobs, next_job_id, 
                            webhooks_received, crashes_simulated, is_crashed, 
                            reconciler_active_job >>

ExecuteAction == /\ pc["reconciler_loop"] = "ExecuteAction"
                 /\ IF reconciler_active_job.type = "deploy"
                       THEN /\ \/ /\ environments' = [environments EXCEPT ![reconciler_active_job.env_id] = [state |-> "running", network_bound |-> TRUE, secrets_mounted |-> TRUE, secrets_persisted |-> FALSE]]
                                  /\ db_jobs' = { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "SUCCESS"] ELSE j : j \in db_jobs }
                               \/ /\ db_jobs' = { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs }
                                  /\ UNCHANGED environments
                       ELSE /\ \/ /\ environments' = [environments EXCEPT ![reconciler_active_job.env_id] = [state |-> "absent", network_bound |-> FALSE, secrets_mounted |-> FALSE, secrets_persisted |-> FALSE]]
                                  /\ db_jobs' = { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "SUCCESS"] ELSE j : j \in db_jobs }
                               \/ /\ IF reconciler_active_job.retries < 3
                                        THEN /\ db_jobs' = { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "QUEUED", !.retries = reconciler_active_job.retries + 1] ELSE j : j \in db_jobs }
                                        ELSE /\ db_jobs' = { IF j.id = reconciler_active_job.id THEN [j EXCEPT !.status = "FAILED"] ELSE j : j \in db_jobs }
                                  /\ UNCHANGED environments
                 /\ reconciler_active_job' = [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0]
                 /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
                 /\ UNCHANGED << next_job_id, webhooks_received, 
                                 crashes_simulated, is_crashed >>

CrashDuringExecution == /\ pc["reconciler_loop"] = "CrashDuringExecution"
                        /\ is_crashed' = TRUE
                        /\ crashes_simulated' = crashes_simulated + 1
                        /\ reconciler_active_job' = [id |-> 0, type |-> "none", env_id |-> "none", ts |-> 0, status |-> "none", retries |-> 0]
                        /\ environments' = [e \in EnvIDs |-> [environments[e] EXCEPT !.secrets_mounted = FALSE]]
                        /\ pc' = [pc EXCEPT !["reconciler_loop"] = "ReconcilerLoop"]
                        /\ UNCHANGED << db_jobs, next_job_id, 
                                        webhooks_received >>

Reconciler == ReconcilerLoop \/ StartupSweep \/ AcquireJob \/ CrashFromIdle
                 \/ IdleLoop \/ ExecuteAction \/ CrashDuringExecution

SendLoop == /\ pc["github"] = "SendLoop"
            /\ IF webhooks_received < MaxWebhooks
                  THEN /\ pc' = [pc EXCEPT !["github"] = "ReceiveWebhook"]
                  ELSE /\ pc' = [pc EXCEPT !["github"] = "Done"]
            /\ UNCHANGED << environments, db_jobs, next_job_id, 
                            webhooks_received, crashes_simulated, is_crashed, 
                            reconciler_active_job >>

ReceiveWebhook == /\ pc["github"] = "ReceiveWebhook"
                  /\ \E type \in {"deploy", "teardown"}:
                       \E e \in EnvIDs:
                         \E ts \in 1..MaxWebhooks:
                           IF ~(\E j \in db_jobs: j.ts = ts)
                              THEN /\ IF \E j \in db_jobs: j.env_id = e /\ j.ts > ts /\ j.status \in {"QUEUED", "IN_PROGRESS", "SUCCESS"}
                                         THEN /\ webhooks_received' = webhooks_received + 1
                                              /\ UNCHANGED << db_jobs, 
                                                              next_job_id >>
                                         ELSE /\ db_jobs' = (db_jobs \cup {[id |-> next_job_id, type |-> type, env_id |-> e, ts |-> ts, status |-> "QUEUED", retries |-> 0]})
                                              /\ next_job_id' = next_job_id + 1
                                              /\ webhooks_received' = webhooks_received + 1
                              ELSE /\ TRUE
                                   /\ UNCHANGED << db_jobs, next_job_id, 
                                                   webhooks_received >>
                  /\ pc' = [pc EXCEPT !["github"] = "SendLoop"]
                  /\ UNCHANGED << environments, crashes_simulated, is_crashed, 
                                  reconciler_active_job >>

WebhookSender == SendLoop \/ ReceiveWebhook

Next == Reconciler \/ WebhookSender

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Reconciler)
        /\ WF_vars(WebhookSender)

\* END TRANSLATION 

=============================================================================
