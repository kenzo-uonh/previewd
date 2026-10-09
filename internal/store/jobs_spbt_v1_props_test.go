package store

// Properties of docs/formal/V1-model.md section 5 and A1-4, the fair drain,
// and the tests of the V1 state machine (see jobs_spbt_v1_test.go).

import (
	"flag"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property copies of the operators a mutant may change: a mutant of the
// algorithm cannot weaken the property that judges it.

// liveSpec is LiveApprovalSpec(e, c): the newest grant of (e, c) is newer
// than the newest revocation of (e, c).
func liveSpec(a []v1ApprovalRecord, e, c string) bool {
	var grant, revoke int64
	for _, r := range a {
		if r.EnvID != e || r.Commit != c {
			continue
		}
		if r.Grant {
			grant = max(grant, r.Seq)
		} else {
			revoke = max(revoke, r.Seq)
		}
	}
	return grant > 0 && grant > revoke
}

func hasGrant(a []v1ApprovalRecord, e, c string) bool {
	return slices.ContainsFunc(a, func(r v1ApprovalRecord) bool { return r.Grant && r.EnvID == e && r.Commit == c })
}

func (x *v1Machine) trustedSpec(m *v1Model, e string) bool {
	return !x.cfg.untrusted[e] && m.openerOK[e]
}

// allowedTruth is GitHub's view (A1-7).
func (x *v1Machine) allowedTruth(m *v1Model, e, c string) bool {
	return x.trustedSpec(m, e) || m.approvedGH[e][c]
}

func runningSpec(m *v1Model, e, c string) bool {
	return m.intact(e) && m.host[e].Commit == c
}

// gaveUp is GaveUp(e, c): a fail-closed or expiry teardown, or a failed
// deploy of c.
func gaveUp(m *v1Model, e, c string) bool {
	for _, j := range m.jobs {
		if j.EnvID == e && (j.Origin == v1OriginRevalidation || j.Origin == v1OriginTTL ||
			(j.Type == JobDeploy && j.Commit == c && j.Status == StatusFailed)) {
			return true
		}
	}
	return false
}

// Check runs after every command: the store against the model, then the
// action properties against the state before the command, then the
// invariants.
func (x *v1Machine) Check(t *rapid.T) {
	if x.st != nil {
		x.st.verify(t, x)
	}
	x.checkActions(t, &x.prev, &x.m)
	x.checkInvariants(t)
	x.prev = x.m.clone()
}

func (x *v1Machine) checkActions(t *rapid.T, prev, cur *v1Model) {
	for _, id := range slices.Sorted(maps.Keys(cur.jobs)) {
		j := cur.jobs[id]
		p, existed := prev.jobs[id]
		if !existed {
			if j.Origin != v1OriginWebhook && j.Seq <= prev.maxSeq(j.EnvID) {
				t.Fatalf("SafetyInternalJobsAreNewest: %s job %d seq %d, MaxSeq(%s) was %d", j.Origin, id, j.Seq, j.EnvID, prev.maxSeq(j.EnvID))
			}
			// previewd_a2.tla: a revocation teardown only above a latest
			// intent that deploys the revoked commit.
			if l, ok := prev.latest(j.EnvID); j.Origin == v1OriginRevocation && (!ok || l.Type != JobDeploy || l.Commit != j.Commit) {
				t.Fatalf("RegressionA21: revocation teardown %d of %s at %s queued above %+v", id, j.EnvID, short(j.Commit), l)
			}
			continue
		}
		if p.Status != StatusInProgress && j.Status == StatusInProgress {
			for _, k := range prev.jobs {
				if k.EnvID == j.EnvID && k.ID != id && k.executed() && k.Seq >= j.Seq {
					t.Fatalf("SafetyMonotonicStep: job %d (seq %d) leased after executed job %d (seq %d)", id, j.Seq, k.ID, k.Seq)
				}
			}
		}
		if p.Trust == v1TrustUnclassified && j.Trust == v1TrustUntrusted &&
			(!liveSpec(prev.approvals, j.EnvID, j.Commit) || !prev.approvedGH[j.EnvID][j.Commit]) {
			t.Fatalf("SafetyAuthorizeChecksBoth: job %d approved; live in DB %v, approved in GitHub %v",
				id, liveSpec(prev.approvals, j.EnvID, j.Commit), prev.approvedGH[j.EnvID][j.Commit])
		}
		if p.Trust == v1TrustUnclassified && j.Trust == v1TrustTrusted && !x.trustedSpec(prev, j.EnvID) {
			t.Fatalf("SafetyAuthorizeChecksBoth: job %d trusted, %s is not trusted in GitHub", id, j.EnvID)
		}
		// A2-6: the only IN_PROGRESS -> QUEUED move of a deploy is the
		// GHES-unavailable branch of AuthorizeDeploy.
		if p.Status == StatusInProgress && j.Status == StatusQueued && j.Type == JobDeploy && cur.exists(j.EnvID) {
			if b, ok := cur.builder(j.EnvID); ok && b.Trust == v1TrustUntrusted && !liveSpec(cur.approvals, j.EnvID, cur.host[j.EnvID].Commit) {
				t.Fatalf("SafetyUnavailableRemovesRevoked: job %d requeued, %s still runs %s (job %d) without a live grant",
					id, j.EnvID, short(cur.host[j.EnvID].Commit), b.ID)
			}
		}
		if p.Status == v1StatusPending && j.Status == StatusQueued && !liveSpec(cur.approvals, j.EnvID, j.Commit) {
			t.Fatalf("SafetyApprovalBindsCommit: job %d (%s) unparked without a live grant of its commit", id, j.Commit)
		}
	}
}

func (x *v1Machine) checkInvariants(t *rapid.T) {
	m := &x.m
	jobs := m.sortedJobs()

	inProgress := map[string]int{}
	type envSeq struct {
		env string
		seq int64
	}
	seqs := map[envSeq]int64{}
	for _, j := range jobs {
		if j.Seq <= 0 || (j.Type == JobTeardown && (j.Status == StatusFailed || j.Status == v1StatusPending || j.Trust != v1TrustUnclassified)) ||
			j.terminal() != (j.FinishedAt != 0) {
			t.Fatalf("TypeOK: job %+v", j)
		}
		if j.Status == StatusInProgress {
			inProgress[j.EnvID]++
		}
		// Per environment, as UNIQUE (preview_id, seq) (A2-2).
		if other, ok := seqs[envSeq{j.EnvID, j.Seq}]; ok {
			t.Fatalf("SafetyUniqueDelivery: jobs %d and %d of %s share seq %d", other, j.ID, j.EnvID, j.Seq)
		}
		seqs[envSeq{j.EnvID, j.Seq}] = j.ID
	}
	for e, n := range inProgress {
		if n > 1 {
			t.Fatalf("SafetyOneJobPerEnv: %d IN_PROGRESS jobs for %s", n, e)
		}
	}

	for _, j := range jobs {
		for _, k := range jobs {
			if j.EnvID == k.EnvID && j.Seq < k.Seq && k.executed() && (j.Status == StatusQueued || j.Status == StatusInProgress) {
				t.Fatalf("SafetyMonotonicity: job %d (seq %d) is %s while newer job %d is %s", j.ID, j.Seq, j.Status, k.ID, k.Status)
			}
		}
	}

	for _, e := range x.envs {
		h := m.host[e]
		if h.Running {
			for _, k := range m.jobsOf(e) {
				if (k.Status == StatusSuccess || k.Status == StatusFailed) && k.Seq > h.Seq {
					t.Fatalf("SafetyMonotonicity: %s runs seq %d behind completed job %d (seq %d)", e, h.Seq, k.ID, k.Seq)
				}
			}
		}
		if h.Routed && !h.Running {
			t.Fatalf("SafetyRouteImpliesRunning: %s has a route document but no running container", e)
		}
		x.checkEnvironment(t, e)
		if m.revalFails[e] >= x.cfg.grace {
			t.Fatalf("SafetyFailClosedOnUnavailable: %s has %d unavailable re-validations, grace %d", e, m.revalFails[e], x.cfg.grace)
		}
		if got := m.maxSeq(e); got != m.maxTs[e] {
			t.Fatalf("SafetyPruneKeepsVerdicts: MaxSeq(%s) = %d, highest seq ever accepted %d", e, got, m.maxTs[e])
		}
		if m.maxTs[e] > 0 && !slices.ContainsFunc(m.jobsOf(e), func(j v1Job) bool { return j.Seq == m.maxTs[e] }) {
			t.Fatalf("SafetyPruneKeepsLatest: the job of %s with seq %d is gone", e, m.maxTs[e])
		}
	}
	x.checkRegressions(t)
	for _, r := range m.prunedDeliveries {
		if r.Seq > m.maxSeq(r.EnvID) {
			t.Fatalf("SafetyPrunedDeliveriesStale: pruned delivery seq %d above MaxSeq(%s) = %d", r.Seq, r.EnvID, m.maxSeq(r.EnvID))
		}
	}

	held := map[int64]bool{}
	for w, wk := range m.workers {
		if wk.Next == stepIdle {
			continue
		}
		j, ok := m.jobs[wk.JobID]
		if !ok || j.Status != StatusInProgress || j.LeaseEpoch != m.epoch || held[j.ID] {
			t.Fatalf("SafetyLeases: worker %d holds job %d, model %+v", w, wk.JobID, j)
		}
		held[j.ID] = true
		if deployStage(wk.Next) && (j.Trust == v1TrustUnclassified || m.authzEpoch[j.ID] != m.epoch) {
			t.Fatalf("SafetyAuthorizedThisBoot: worker %d deploys job %d (trust %s) not authorized in epoch %d",
				w, j.ID, j.Trust, m.epoch)
		}
	}
}

// checkRegressions holds the invariant RegressionA22 of
// docs/formal/previewd_a2.tla, the state that doomed an intent in the A1
// model (V1-model.md section 11); RegressionA21 is an action property, in
// checkActions.
func (x *v1Machine) checkRegressions(t *rapid.T) {
	m := &x.m
	for _, i := range x.inflight {
		d := x.emitted[i]
		if d.Kind != v1KindDeploy || d.Seq > m.maxSeq(d.EnvID) {
			continue
		}
		recordedNewer := func(r v1DeliveryRecord) bool { return r.EnvID == d.EnvID && r.Seq >= d.Seq }
		if !slices.ContainsFunc(slices.Collect(maps.Values(m.deliveries)), recordedNewer) &&
			!slices.ContainsFunc(m.prunedDeliveries, recordedNewer) {
			t.Fatalf("RegressionA22: in-flight deploy %s of %s is newer than every recorded delivery, yet stale (MaxSeq %d)", d.ID, d.EnvID, m.maxSeq(d.EnvID))
		}
	}
}

// checkEnvironment holds the per-environment safety properties.
func (x *v1Machine) checkEnvironment(t *rapid.T, e string) {
	m := &x.m
	h := m.host[e]
	latest, hasJobs := m.latest(e)
	if hasJobs && latest.Status == v1StatusPending && h.exists() {
		t.Fatalf("SafetyParkRemovesPrevious: %s still exists behind parked job %d", e, latest.ID)
	}
	if !h.exists() {
		return
	}
	b, ok := m.builder(e)
	// Safety 2 (D5): owned by an IN_PROGRESS or SUCCESS deploy no newer
	// teardown has undone.
	owned := ok && (b.Status == StatusInProgress || b.Status == StatusSuccess)
	for _, k := range m.jobsOf(e) {
		if ok && k.Type == JobTeardown && k.Status == StatusSuccess && k.Seq > b.Seq {
			owned = false
		}
	}
	if !owned {
		t.Fatalf("SafetyNoOrphanedResources: %s exists (%+v), builder %+v (found %v)", e, h, b, ok)
	}
	if b.Trust == v1TrustUnclassified || (x.cfg.untrusted[e] && b.Trust != v1TrustUntrusted) ||
		(b.Trust == v1TrustUntrusted && !hasGrant(m.approvals, e, b.Commit)) {
		t.Fatalf("SafetyNoUnapprovedUntrusted: %s runs job %d (trust %s, untrusted %v, grant of %s %v)",
			e, b.ID, b.Trust, x.cfg.untrusted[e], b.Commit, hasGrant(m.approvals, e, b.Commit))
	}
	if b.Status == StatusSuccess && b.Trust == v1TrustUntrusted && !liveSpec(m.approvals, e, h.Commit) &&
		!slices.ContainsFunc(m.jobsOf(e), func(k v1Job) bool {
			return k.Seq > h.Seq && (k.Status == StatusQueued || k.Status == StatusInProgress || k.Status == v1StatusPending)
		}) {
		t.Fatalf("SafetyRevocationPending: %s runs %s without a live approval and nothing newer is pending", e, h.Commit)
	}
}

// drain runs the fair processes (Api, workers, Revalidator, Expirer) with
// GitHub quiet, no crash and no fault, until nothing is enabled, then checks
// the liveness properties.
func (x *v1Machine) drain(t *rapid.T) {
	x.settle(t)
	x.checkLiveness(t)
}

// settle runs the fair processes until nothing is enabled. Time passes only
// when a requeued job waits for its backoff. Between two random rounds it is
// a schedule where GitHub stays quiet for a while, so the next round acts on
// running environments.
func (x *v1Machine) settle(t *rapid.T) {
	m := &x.m
	for range 100 + 20*(len(m.jobs)+len(x.emitted)) {
		progressed := false
		for len(x.inflight) > 0 {
			d := x.emitted[x.inflight[0]]
			x.inflight = x.inflight[1:]
			x.receive(t, d)
			x.Check(t)
			progressed = true
		}
		for w := range m.workers {
			if m.workers[w].Next != stepIdle {
				x.step(t, w, true)
				progressed = true
			} else if x.acquire(t, w) {
				progressed = true
			}
			x.Check(t)
		}
		if x.cfg.mutant != v1M07 {
			for _, e := range x.envsWhere(x.needsRevalidation) {
				if m.revalFails[e] > 0 || !x.allowed(e, m.host[e].Commit) {
					x.revalidate(t, e, true)
					x.Check(t)
					progressed = true
				}
			}
		}
		if x.cfg.mutant != v1M17 {
			for _, e := range x.expirableEnvs() {
				x.expire(t, e)
				x.Check(t)
				progressed = true
			}
		}
		if progressed {
			continue
		}
		if slices.ContainsFunc(m.sortedJobs(), func(j v1Job) bool { return j.Status == StatusQueued }) {
			m.clock++ // a backoff is pending
			x.Check(t)
			continue
		}
		return
	}
	t.Fatalf("the fair processes did not settle: %+v", m.sortedJobs())
}

func (x *v1Machine) checkLiveness(t *rapid.T) {
	m := &x.m
	for _, e := range x.envs {
		h := m.host[e]
		if h.exists() && m.builderSucceeded(e) && !x.allowedTruth(m, e, h.Commit) {
			t.Fatalf("LivenessRevokedTornDown: %s still runs %s, which GitHub no longer allows", e, h.Commit)
		}
		if x.cfg.ttl > 0 && m.intact(e) && m.builderSucceeded(e) && m.builderIsLatest(e) && m.clock-m.deployedAt[e] >= x.cfg.ttl {
			t.Fatalf("LivenessExpired: %s deployed at %d still runs at %d, TTL %d", e, m.deployedAt[e], m.clock, x.cfg.ttl)
		}
		if l, ok := m.latest(e); x.cfg.ttl > 0 && ok && l.Type == JobDeploy && l.Status == v1StatusPending &&
			x.now().UnixMilli()-l.CreatedAt >= (time.Duration(x.cfg.ttl)*v1Tick).Milliseconds() {
			t.Fatalf("LivenessParkedExpired: %s still parked at %d, created %d, TTL %d", e, x.now().UnixMilli(), l.CreatedAt, x.cfg.ttl)
		}
		for _, c := range v1Commits {
			if m.open[e] && m.head[e] == c && x.allowedTruth(m, e, c) && (x.trustedSpec(m, e) || liveSpec(m.approvals, e, c)) &&
				!runningSpec(m, e, c) && !gaveUp(m, e, c) {
				t.Fatalf("LivenessHeadDeployed: open head %s of %s is allowed and recorded but not running; jobs %+v", c, e, m.jobsOf(e))
			}
		}
	}
	for _, j := range m.sortedJobs() {
		if j.Status == StatusQueued || j.Status == StatusInProgress {
			t.Fatalf("LivenessEventualCompletion: job %+v never completed", j)
		}
	}
	for _, e := range x.envs {
		l, ok := m.latest(e)
		if ok && l.Type == JobDeploy && l.Status == StatusSuccess && x.allowedTruth(m, e, l.Commit) {
			if !runningSpec(m, e, l.Commit) {
				t.Fatalf("LivenessEventualConsistency: %s should run %s (job %d), host has %+v", e, l.Commit, l.ID, m.host[e])
			}
		} else if m.exists(e) {
			t.Fatalf("LivenessEventualConsistency: %s should be absent (latest %+v), host has %+v", e, l, m.host[e])
		}
	}
}

// v1Actions is the action set, with the reconciler and network commands
// listed more than once: rapid picks actions uniformly, and the paths that
// matter (a deploy that completes, then a revocation delivered out of
// order) need several of them in a row.
func v1Actions(x *v1Machine) map[string]func(*rapid.T) {
	actions := rapid.StateMachineActions(x)
	for i := range 5 {
		actions[fmt.Sprintf("Step#%d", i+2)] = x.Step
	}
	actions["Push#2"] = x.Push
	for i := range 2 {
		actions[fmt.Sprintf("ReceiveWebhook#%d", i+2)] = x.ReceiveWebhook
	}
	actions["AcquireJob#2"] = x.AcquireJob
	actions["Approve#2"] = x.Approve
	actions["Tick#2"] = x.Tick
	return actions
}

// v1QuietActions is every action that emits no new delivery.
func v1QuietActions(x *v1Machine) map[string]func(*rapid.T) {
	return map[string]func(*rapid.T){
		"":               x.Check,
		"PermissionLoss": x.PermissionLoss,
		"Tick":           x.Tick,
		"Redeliver":      x.Redeliver,
		"ReceiveWebhook": x.ReceiveWebhook,
		"AcquireJob":     x.AcquireJob,
		"Step":           x.Step,
		"Revalidate":     x.Revalidate,
		"Expire":         x.Expire,
		"Prune":          x.Prune,
		"SimulateCrash":  x.SimulateCrash,
	}
}

func runV1(t *rapid.T, mutant v1Mutant, st v1Backend) {
	x := newV1Machine(t, mutant, st)
	if st != nil {
		defer st.close(t)
	}
	actions := v1Actions(x)
	for round := range v1Rounds {
		t.Repeat(actions)
		if round < v1Rounds-1 && rapid.Bool().Draw(t, "settle") {
			x.settle(t)
		}
	}
	// A quiet ending: GitHub sends nothing new while permissions change
	// silently under running environments (D-V1-5).
	if rapid.Bool().Draw(t, "quiet ending") {
		x.settle(t)
		t.Repeat(v1QuietActions(x))
	}
	x.drain(t)
}

// TestV1Model_StateMachine checks the reference model alone against every
// property, on random behaviors far beyond the TLC bounds.
func TestV1Model_StateMachine(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		runV1(t, v1Faithful, nil)
	})
}

// v1MutantCases is V1-model.md section 7, with the property A1 recorded as
// killing each mutant (docs/formal/README.md); where TLC first tripped
// another property (✓²), that one is accepted too. V1-M15 and V1-M16 are
// equivalent by construction (A1-9) and must survive.
var v1MutantCases = []struct {
	name     string
	mutant   v1Mutant
	killedBy []string // empty: equivalent, must survive
	checks   int      // runs, when the path is rarer than v1MutantChecks covers
}{
	{"V1-M01", v1M01, []string{"SafetyAuthorizeChecksBoth", "SafetyNoUnapprovedUntrusted"}, 0},
	{"V1-M02", v1M02, []string{"SafetyAuthorizeChecksBoth", "LivenessRevokedTornDown"}, 0},
	{"V1-M03", v1M03, []string{"SafetyApprovalBindsCommit"}, 0},
	{"V1-M04", v1M04, []string{"SafetyParkRemovesPrevious"}, 0},
	{"V1-M05", v1M05, []string{"SafetyRevocationPending"}, 0},
	{"V1-M06", v1M06, []string{"LivenessHeadDeployed", "LivenessEventualConsistency"}, 0},
	{"V1-M06b", v1M06b, []string{"SafetyAuthorizeChecksBoth", "SafetyApprovalBindsCommit", "LivenessHeadDeployed"}, 0},
	{"V1-M07", v1M07, []string{"LivenessRevokedTornDown", "LivenessEventualConsistency"}, 0},
	{"V1-M08", v1M08, []string{"SafetyFailClosedOnUnavailable"}, 0},
	{"V1-M09", v1M09, []string{"SafetyAuthorizeChecksBoth", "SafetyNoUnapprovedUntrusted"}, 0},
	{"V1-M10", v1M10, []string{"LivenessHeadDeployed", "RegressionA21"}, 0},
	{"V1-M11", v1M11, []string{"LivenessHeadDeployed", "RegressionA21"}, 0},
	{"V1-M12", v1M12, []string{"SafetyAuthorizedThisBoot"}, 0},
	{"V1-M13", v1M13, []string{"SafetyInternalJobsAreNewest", "SafetyUniqueDelivery"}, 0},
	{"V1-M14", v1M14, []string{"SafetyPruneKeepsLatest"}, 0},
	{"V1-M15", v1M15, nil, 0},
	{"V1-M15b", v1M15b, []string{"SafetyPruneKeepsVerdicts"}, 0},
	{"V1-M16", v1M16, nil, 0},
	{"V1-M17", v1M17, []string{"LivenessExpired", "LivenessParkedExpired"}, 0},
	{"V1-M18", v1M18, []string{"SafetyMonotonicity", "SafetyOneJobPerEnv", "SafetyMonotonicStep"}, 0},
	// A trusted opener losing write access under a running environment,
	// then a quiet ending: about 4 seeds in 12 missed it at 1,000 runs.
	{"V1-M19", v1M19, []string{"LivenessRevokedTornDown", "LivenessEventualConsistency"}, 10 * v1MutantChecks},
	{"V1-M20", v1M20, []string{"RegressionA21", "LivenessHeadDeployed"}, 0},
	{"V1-M21", v1M21, []string{"RegressionA22", "LivenessHeadDeployed"}, 0},
	// An approved version superseded, then a GHES fault at the next
	// authorization: rare at 1,000 runs.
	{"V1-M22", v1M22, []string{"SafetyUnavailableRemovesRevoked"}, 5 * v1MutantChecks},
	{"V1-M23", v1M23, []string{"LivenessParkedExpired"}, 0},
}

// v1MutantChecks is the least number of runs a mutant gets.
const v1MutantChecks = 1000

// rapidRecorder is a rapid.TB that records a failure instead of failing
// the test, so a mutant run can be required to fail.
type rapidRecorder struct {
	name   string
	failed bool
	msgs   []string
}

func (r *rapidRecorder) Helper()                     {}
func (r *rapidRecorder) Name() string                { return r.name }
func (r *rapidRecorder) Logf(string, ...any)         {}
func (r *rapidRecorder) Log(...any)                  {}
func (r *rapidRecorder) Skipf(f string, args ...any) { r.Errorf("skipped: "+f, args...) }
func (r *rapidRecorder) Skip(args ...any)            { r.Error(append([]any{"skipped:"}, args...)...) }
func (r *rapidRecorder) SkipNow()                    { r.Error("skipped") }
func (r *rapidRecorder) Errorf(f string, args ...any) {
	r.failed = true
	r.msgs = append(r.msgs, fmt.Sprintf(f, args...))
}
func (r *rapidRecorder) Error(args ...any) {
	r.failed = true
	r.msgs = append(r.msgs, fmt.Sprint(args...))
}
func (r *rapidRecorder) Fatalf(f string, args ...any) { r.Errorf(f, args...) }
func (r *rapidRecorder) Fatal(args ...any)            { r.Error(args...) }
func (r *rapidRecorder) FailNow()                     { r.failed = true }
func (r *rapidRecorder) Fail()                        { r.failed = true }
func (r *rapidRecorder) Failed() bool                 { return r.failed }

// setTestFlag sets a registered flag for the duration of the test.
func setTestFlag(t *testing.T, name, value string) {
	t.Helper()
	f := flag.Lookup(name)
	if f == nil {
		t.Fatalf("flag %s is not registered", name)
	}
	old := f.Value.String()
	if err := f.Value.Set(value); err != nil {
		t.Fatalf("set flag %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := f.Value.Set(old); err != nil {
			t.Errorf("restore flag %s: %v", name, err)
		}
	})
}

// TestV1Model_Mutants applies each V1 mutant to the reference model's
// algorithm and requires the generated behaviors to reach a state where the
// property A1 named fails. It proves that the commands reach every guarded
// path and that the Go properties are as strong as the TLA+ ones; the same
// commands and properties then judge the store (TestV1Store_StateMachine).
func TestV1Model_Mutants(t *testing.T) {
	// A mutant's counterexample is expected: no failure file, and no time
	// spent minimizing it. Some paths (a silent permission loss on a running
	// environment, an expired one) are rare, so each mutant gets at least
	// v1MutantChecks runs.
	setTestFlag(t, "rapid.nofailfile", "true")
	setTestFlag(t, "rapid.shrinktime", "1s")
	checks := flag.Lookup("rapid.checks")
	if checks == nil {
		t.Fatal("flag rapid.checks is not registered")
	}
	n, err := strconv.Atoi(checks.Value.String())
	if err != nil {
		t.Fatalf("rapid.checks: %v", err)
	}
	if n < v1MutantChecks {
		setTestFlag(t, "rapid.checks", strconv.Itoa(v1MutantChecks))
	}
	for _, tc := range v1MutantCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.checks > max(n, v1MutantChecks) {
				setTestFlag(t, "rapid.checks", strconv.Itoa(tc.checks))
			}
			rec := &rapidRecorder{name: t.Name()}
			rapid.Check(rec, func(rt *rapid.T) {
				runV1(rt, tc.mutant, nil)
			})
			report := strings.Join(rec.msgs, "\n")
			if len(tc.killedBy) == 0 {
				if rec.failed {
					t.Fatalf("equivalent mutant %s was killed:\n%s", tc.name, report)
				}
				return
			}
			if !rec.failed {
				t.Fatalf("mutant %s survived; expected one of %v", tc.name, tc.killedBy)
			}
			// The property that failed is the first one rapid reports.
			killer, at := "", len(report)
			for _, p := range tc.killedBy {
				if i := strings.Index(report, p+":"); i >= 0 && i < at {
					killer, at = p, i
				}
			}
			if killer == "" {
				t.Fatalf("mutant %s killed by another property; expected one of %v:\n%s", tc.name, tc.killedBy, firstLines(report, 8))
			}
			t.Logf("%s killed by %s", tc.name, killer)
		})
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	return strings.Join(lines[:min(n, len(lines))], "\n")
}
