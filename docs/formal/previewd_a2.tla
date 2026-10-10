----------------------------- MODULE previewd_a2 -----------------------------
(***************************************************************************)
(* Regression properties for the two design bugs the V1 state-machine     *)
(* test found beyond the TLC bounds of previewd.tla (task A2,             *)
(* docs/formal/V1-model.md section 11). Each names the step or the state   *)
(* that dooms an intent, so a safety search finds it at depths where the  *)
(* liveness property that judges it does not fit the state budget. Both   *)
(* fail on the A1 model and hold on the current one (previewd_a2.cfg,     *)
(* previewd_a2-trust.cfg).                                                 *)
(***************************************************************************)
EXTENDS previewd

\* A2-1: a revocation teardown is queued only above a latest intent that
\* deploys the revoked commit. In the A1 model it was also queued above a
\* newer deploy of another commit (an older queued deploy or the running
\* version matched), and the worker then skipped that deploy: an open,
\* approved head was never deployed. An action property, because the state
\* "a teardown above a deploy of the head" is also reached legitimately
\* when a newer push of the head is still in flight.
RegressionA21 ==
    [][\A j \in DOMAIN db_jobs' \ DOMAIN db_jobs :
          db_jobs'[j].origin = "revocation" =>
              /\ JobsOf(db_jobs'[j].env_id) # {}
              /\ db_jobs[Latest(db_jobs'[j].env_id)].type = "deploy"
              /\ db_jobs[Latest(db_jobs'[j].env_id)].commit = db_jobs'[j].commit
      ]_vars

\* A2-2: a deploy delivery still in flight is newer than every delivery of
\* its environment ever recorded (pruned ones included), yet already stale:
\* only an internal job can be above it, with a seq above a stamp GitHub
\* gave later. Its intent is lost.
RegressionA22 ==
    ~\E d \in inflight :
        /\ d.kind = "deploy"
        /\ \A r \in deliveries \cup prunedDeliveries : r[2] = d.env => r[1] < d.ts
        /\ d.ts <= MaxSeq(d.env)

=============================================================================
