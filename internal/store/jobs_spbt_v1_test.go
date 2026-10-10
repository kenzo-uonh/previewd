package store

// Stateful property-based test of the V1 queue (task A2 of
// docs/specs/V1-previewd.md; command mapping in docs/formal/V1-model.md
// section 8).
//
// The reference model below is written from docs/formal/previewd.tla (V1),
// not from jobs.go, and keeps its rules one for one:
//   - GitHub holds the truth (head commit, open state, approvals, opener
//     write access) and emits deliveries stamped with one global clock; the
//     network reorders and redelivers them freely;
//   - ReceiveWebhook: deploy/teardown through the replay and stale rules
//     (stale against max(jobs, watermark)), a deploy revoking every other
//     commit; grant and revoke recorded order-independently, the grant
//     judging the latest job (A1-3);
//   - AcquireJob, AuthorizeDeploy (trusted, approved, park, GHES fault),
//     ExecuteDeploy -> StartContainer -> PublishRoute -> CommitDeploy,
//     ExecuteTeardown -> CommitTeardown with requeue;
//   - Revalidate over every running environment with the fail-closed grace
//     (D-V1-5), Expire (TTL), Prune behind the watermark, never the latest
//     job nor the builder of what runs (A1-6);
//   - SimulateCrash (daemon crash or host reboot) and StartupSweep, which
//     sends a re-armed deploy through AuthorizeDeploy again.
//
// The model's clock is a minute counter; GitHub stamps a delivery with the
// clock's UUIDv1 ticks. An internal job takes seq = MaxSeq(e) + 1 (A2-2): it
// supersedes every recorded intent of its environment and loses to any
// delivery GitHub sent after that intent, even one still in flight. A minute
// holds 6e8 ticks, so an internal seq never reaches the next GitHub stamp,
// which is what the spacing K = JobBound + 1 guarantees in the TLA+ model.
//
// After every command, Check judges the model with the properties of
// V1-model.md section 5 and A1-4 (action properties against the state
// before the command). The properties use their own copies of the operators
// a mutant may change (liveSpec, hasGrant, allowedTruth, runningSpec), as in
// the TLA+ model. After the random sequence, drain runs the fair processes
// with GitHub quiet and no fault, then checks the liveness properties.
//
// The store under test is a v1Backend. TestV1Model_StateMachine checks the
// reference model alone and TestV1Model_Mutants proves that each V1 mutant
// of A0 section 7 is caught by the property A1 named.
// jobs_spbt_v1_store_test.go drives the real Store with the same machine and
// compares every table with the model after every command.

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"pgregory.net/rapid"
)

// v1Envs and v1Commits are the identities the machine draws from: three
// environments (trust drawn per run) and the two commits that express "an
// approval of another commit" and "a push revokes" (V1-model.md 6.2).
var (
	v1Envs    = []string{"pr-1-0a0a0a0a0a", "pr-2-0b0b0b0b0b", "pr-3-0c0c0c0c0c"}
	v1Commits = []string{strings.Repeat("c1", 20), strings.Repeat("c2", 20)}
)

const (
	// uuidV1EpochOffset is the number of 100 ns intervals between the UUID
	// epoch (1582-10-15) and the Unix epoch.
	uuidV1EpochOffset = int64(122_192_928_000_000_000)
	// v1Tick is one step of the model's clock. It is longer than the
	// longest teardown backoff, so a requeued job is due one tick later.
	v1Tick       = time.Minute
	v1SeqPerTick = int64(v1Tick / 100)
	// v1Clock0 is the clock at the start of every run (2027).
	v1Clock0 = int64(234_000_000)
	// v1DeliveryMaxAge stands for PREVIEWD_DELIVERY_MAX_AGE in Prune.
	v1DeliveryMaxAge = 5 * time.Minute
	// v1Rounds is the number of rapid Repeat rounds per run: deep paths
	// (open, approve, dismiss, approve, each reordered) need more steps
	// than one round's default average.
	v1Rounds = 3
)

// uuidV1Ticks is a time in UUIDv1 timestamp units: the seq of a delivery
// GitHub sends at t, and the base of an internal job's seq.
func uuidV1Ticks(t time.Time) int64 {
	return t.UnixNano()/100 + uuidV1EpochOffset
}

// short names a commit in logs.
func short(c string) string { return c[:min(len(c), 2)] }

// v1TimeAt is the wall time of a clock value.
func v1TimeAt(clock int64) time.Time {
	return time.Unix(0, (clock*v1SeqPerTick-uuidV1EpochOffset)*100).UTC()
}

// Statuses, origins and trust levels of the V1 schema (spec section 3.1),
// kept apart from the store's constants so the model does not read them.
const v1StatusPending JobStatus = "PENDING_APPROVAL"

type v1Origin string

const (
	v1OriginWebhook      v1Origin = "webhook"
	v1OriginApproval     v1Origin = "approval"
	v1OriginRevocation   v1Origin = "revocation"
	v1OriginRevalidation v1Origin = "revalidation"
	v1OriginTTL          v1Origin = "ttl"
)

// v1Trust is jobs.trust. A deploy is classified by AuthorizeDeploy:
// trusted, or untrusted with a live approval of its commit (the model's
// authz "approved"). Everything else stays unclassified.
type v1Trust string

const (
	v1TrustUnclassified v1Trust = "unclassified"
	v1TrustTrusted      v1Trust = "trusted"
	v1TrustUntrusted    v1Trust = "untrusted"
)

// v1Job is one row of jobs in schema version 3, as the test compares it.
// The source columns other than the commit are a function of the
// environment (v1SourceOf).
type v1Job struct {
	ID         int64
	EnvID      string
	Type       JobType
	Origin     v1Origin
	Seq        int64
	Status     JobStatus
	Trust      v1Trust
	Attempts   int64
	NotBefore  int64 // Unix ms
	LeaseEpoch int64
	CreatedAt  int64 // Unix ms
	FinishedAt int64 // Unix ms, 0 while not terminal
	Commit     string
}

func (j v1Job) terminal() bool {
	return j.Status == StatusSuccess || j.Status == StatusFailed || j.Status == StatusSkipped
}

func (j v1Job) executed() bool {
	return j.Status == StatusInProgress || j.Status == StatusSuccess || j.Status == StatusFailed
}

// v1ApprovalRecord is one grant or revocation of (env, commit) at a
// delivery seq: the model's approvalsDB.
type v1ApprovalRecord struct {
	Grant  bool
	EnvID  string
	Commit string
	Seq    int64
}

// v1DeliveryRecord is one row of deliveries.
type v1DeliveryRecord struct {
	EnvID      string
	Seq        int64
	Verdict    Verdict
	Payload    string
	ReceivedAt int64 // Unix ms
}

type v1Kind string

const (
	v1KindDeploy   v1Kind = "deploy"
	v1KindTeardown v1Kind = "teardown"
	v1KindGrant    v1Kind = "grant"
	v1KindRevoke   v1Kind = "revoke"
)

// v1Emission is one delivery GitHub sent. A redelivery keeps the ID, the
// body and the seq.
type v1Emission struct {
	ID      string
	Payload string
	Kind    v1Kind
	EnvID   string
	Commit  string
	Seq     int64
}

// v1HostEnv is the mocked host's view of one environment. Seq is the
// builder's seq (the model's deployed_ts), Commit the commit it runs.
type v1HostEnv struct {
	Running, NetworkBound, SecretsMounted, Routed bool
	JobID                                         int64 // builder; 0 for a stray
	Seq                                           int64
	Commit                                        string
}

func (h v1HostEnv) exists() bool {
	return h.Running || h.NetworkBound || h.SecretsMounted || h.Routed
}

func (h v1HostEnv) intact() bool {
	return h.Running && h.NetworkBound && h.SecretsMounted && h.Routed
}

// stepAuthorize is AuthorizeDeploy, between AcquireJob and ExecuteDeploy.
const stepAuthorize = stepCommitTeardown + 1

type v1Worker struct {
	JobID int64
	Next  step
}

func deployStage(s step) bool {
	return s == stepExecuteDeploy || s == stepStartContainer || s == stepPublishRoute || s == stepCommitDeploy
}

// v1Model is the reference state: GitHub truth, SQLite, host and memory,
// and the ghosts the properties read. It is copied before every command so
// the action properties can compare the two states.
type v1Model struct {
	// GitHub truth.
	head       map[string]string
	open       map[string]bool
	approvedGH map[string]map[string]bool
	openerOK   map[string]bool
	clock      int64

	// previewd: SQLite.
	jobs       map[int64]v1Job
	nextID     int64
	deliveries map[string]v1DeliveryRecord // webhook deploy and teardown deliveries
	// Approval and revocation deliveries, replay-checked like the others
	// (D2) but kept apart: RegressionA22 and prunedDeliveries are about
	// webhook job deliveries only.
	approvalDeliveries map[string]v1DeliveryRecord
	approvals          []v1ApprovalRecord
	watermark          map[string]int64
	epoch              int64

	// previewd: host and memory.
	host       map[string]v1HostEnv
	deployedAt map[string]int64 // clock at CommitDeploy
	revalFails map[string]int
	workers    [spbtWorkers]v1Worker

	// Ghosts, read by properties only.
	authzEpoch       map[int64]int64 // boot epoch of each classification
	maxTs            map[string]int64
	prunedDeliveries []v1DeliveryRecord
}

func (m *v1Model) clone() v1Model {
	c := *m
	c.head = maps.Clone(m.head)
	c.open = maps.Clone(m.open)
	c.approvedGH = make(map[string]map[string]bool, len(m.approvedGH))
	for e, set := range m.approvedGH {
		c.approvedGH[e] = maps.Clone(set)
	}
	c.openerOK = maps.Clone(m.openerOK)
	c.jobs = maps.Clone(m.jobs)
	c.deliveries = maps.Clone(m.deliveries)
	c.approvalDeliveries = maps.Clone(m.approvalDeliveries)
	c.approvals = slices.Clone(m.approvals)
	c.watermark = maps.Clone(m.watermark)
	c.host = maps.Clone(m.host)
	c.deployedAt = maps.Clone(m.deployedAt)
	c.revalFails = maps.Clone(m.revalFails)
	c.authzEpoch = maps.Clone(m.authzEpoch)
	c.maxTs = maps.Clone(m.maxTs)
	c.prunedDeliveries = slices.Clone(m.prunedDeliveries)
	return c
}

// sortedJobs returns every job, oldest first (the order of Store.Jobs).
func (m *v1Model) sortedJobs() []v1Job {
	jobs := make([]v1Job, 0, len(m.jobs))
	for _, id := range slices.Sorted(maps.Keys(m.jobs)) {
		jobs = append(jobs, m.jobs[id])
	}
	return jobs
}

func (m *v1Model) jobsOf(e string) []v1Job {
	var jobs []v1Job
	for _, j := range m.sortedJobs() {
		if j.EnvID == e {
			jobs = append(jobs, j)
		}
	}
	return jobs
}

// latest is Latest(e): the job of e with the highest seq.
func (m *v1Model) latest(e string) (v1Job, bool) {
	var best v1Job
	found := false
	for _, j := range m.jobs {
		if j.EnvID == e && (!found || j.Seq > best.Seq) {
			best, found = j, true
		}
	}
	return best, found
}

// maxSeq is MaxSeq(e), what the stale rule reads.
func (m *v1Model) maxSeq(e string) int64 {
	s := m.watermark[e]
	for _, j := range m.jobs {
		if j.EnvID == e {
			s = max(s, j.Seq)
		}
	}
	return s
}

// builder is Builder(e): the deploy whose seq the host records.
func (m *v1Model) builder(e string) (v1Job, bool) {
	h, ok := m.host[e]
	if !ok || h.Seq == 0 {
		return v1Job{}, false
	}
	for _, j := range m.jobs {
		if j.EnvID == e && j.Type == JobDeploy && j.Seq == h.Seq {
			return j, true
		}
	}
	return v1Job{}, false
}

func (m *v1Model) builderSucceeded(e string) bool {
	b, ok := m.builder(e)
	return ok && b.Status == StatusSuccess
}

func (m *v1Model) builderIsLatest(e string) bool {
	b, ok := m.builder(e)
	l, found := m.latest(e)
	return ok && found && l.ID == b.ID
}

func (m *v1Model) exists(e string) bool { return m.host[e].exists() }
func (m *v1Model) intact(e string) bool { return m.host[e].intact() }

// runningCommit and activeDeployOf are the revoke rule of A1, before A2-1:
// only V1-M20 reads them.
func (m *v1Model) runningCommit(e, c string) bool {
	return m.exists(e) && m.host[e].Commit == c
}

func (m *v1Model) activeDeployOf(e, c string) bool {
	for _, j := range m.jobs {
		if j.EnvID == e && j.Type == JobDeploy && j.Commit == c &&
			(j.Status == StatusQueued || j.Status == StatusInProgress || j.Status == v1StatusPending) {
			return true
		}
	}
	return false
}

// headIntentPresent: the latest intent of e already deploys c.
func (m *v1Model) headIntentPresent(e, c string) bool {
	l, ok := m.latest(e)
	return ok && l.Type == JobDeploy && l.Commit == c &&
		(l.Status == StatusQueued || l.Status == StatusInProgress || l.Status == v1StatusPending || l.Status == StatusSuccess)
}

// v1LiveIn is the algorithm's LiveIn: a grant of (e, c) newer than every
// revocation of (e, c), whatever the order they arrived in.
func v1LiveIn(a []v1ApprovalRecord, e, c string) bool {
	for _, g := range a {
		if !g.Grant || g.EnvID != e || g.Commit != c {
			continue
		}
		live := true
		for _, r := range a {
			if !r.Grant && r.EnvID == e && r.Commit == c && r.Seq >= g.Seq {
				live = false
				break
			}
		}
		if live {
			return true
		}
	}
	return false
}

// v1Config is what the TLA+ configurations fix as constants, drawn per run.
type v1Config struct {
	untrusted map[string]bool // UntrustedEnvs
	grace     int             // Grace
	ttl       int64           // TTL in ticks, 0 disables expiry
	mutant    v1Mutant
}

// v1Mutant selects one fault of V1-model.md section 7 in the reference
// model's algorithm, never in the properties that judge it.
type v1Mutant int

const (
	v1Faithful v1Mutant = iota
	v1M01               // AuthorizeDeploy allows an untrusted job without a live approval
	v1M02               // AuthorizeDeploy reads the DB approval, not GitHub truth
	v1M03               // a grant unparks a parked deploy of another commit
	v1M04               // park leaves the previous version running
	v1M05               // a revoke delivery is recorded but queues no teardown
	v1M06               // LiveApproval ignores ordering: any revocation kills any grant (A0)
	v1M06b              // approvals and revocations applied in arrival order (README)
	v1M07               // Revalidator not fair
	v1M08               // GHES unavailability during re-validation never escalates
	v1M09               // GHES fault during AuthorizeDeploy treated as allow
	v1M10               // synchronize queues a teardown newer than its own deploy
	v1M11               // a grant of the current head with no job waiting does nothing
	v1M12               // the sweep re-arms a deploy that skips AuthorizeDeploy
	v1M13               // internal job seq not above the latest
	v1M14               // Prune deletes the latest job
	v1M15               // Prune does not raise the watermark
	v1M15b              // Prune deletes the latest job and skips the watermark
	v1M16               // Prune deletes a delivery whatever its seq
	v1M17               // Expirer not fair
	v1M18               // untrusted environments not locked
	v1M19               // only untrusted environments re-validated (before D-V1-5)
	v1M20               // a revocation judges any active deploy or the running commit (A1 rule, A2-1)
	v1M21               // an internal job takes a seq above now (A1 rule, A2-2)
	v1M22               // GHES unavailable in AuthorizeDeploy leaves a revoked version running (before A2-6)
	v1M23               // a parked intent never expires (before the G leftover)
)

// v1Grant is a grant delivery as the API hands it to the store, with the
// GitHub truth it read in the same step and its replay keys.
type v1Grant struct {
	ID       string
	Payload  string
	EnvID    string
	Commit   string
	Seq      int64
	Trusted  bool // the environment needs no approval (D-V1-5)
	OpenHead bool // the PR is open and Commit is its head
}

// v1Revocation is a revoke delivery as the API hands it to the store.
type v1Revocation struct {
	ID      string
	Payload string
	EnvID   string
	Commit  string
	Seq     int64
	Trusted bool
}

// v1Lease is the part of a lease the model predicts.
type v1Lease struct {
	JobID    int64
	EnvID    string
	Type     JobType
	Seq      int64
	Epoch    int64
	Attempts int64
	Commit   string
}

// v1PruneRequest is one Prune call.
type v1PruneRequest struct {
	Now            time.Time
	Retention      time.Duration
	DeliveryMaxAge time.Duration
	Batch          int
	Builders       []int64 // builder job IDs of every environment that exists
	Yield          time.Duration
}

// v1Backend is the store under test, driven in lockstep with the model.
// Each method performs one store operation, fails the run on any error the
// model does not predict, and returns what the store answered. verify
// compares every table with the model.
type v1Backend interface {
	configure(cfg v1Config)
	crash(t *rapid.T)
	boot(t *rapid.T, now time.Time, observed []Observation) SweepResult
	enqueue(t *rapid.T, d v1Emission, now time.Time) (Verdict, int64)
	approve(t *rapid.T, g v1Grant, now time.Time) (Verdict, int64)
	revoke(t *rapid.T, r v1Revocation, now time.Time) (Verdict, int64)
	acquire(t *rapid.T, now time.Time) (v1Lease, bool)
	// classify returns true when the store refused the classification
	// because no live approval of the commit exists.
	classify(t *rapid.T, jobID int64, trust v1Trust) (refused bool)
	park(t *rapid.T, jobID int64)
	// requeue returns true when the store refused to requeue a classified
	// deploy.
	requeue(t *rapid.T, jobID int64, notBefore time.Time) (refused bool)
	// finish returns true when the store refused to fail a teardown.
	finish(t *rapid.T, jobID int64, status JobStatus, now time.Time) (refused bool)
	enqueueInternal(t *rapid.T, envID string, origin v1Origin, revoke bool, now time.Time) int64
	approvalLive(t *rapid.T, envID, commit string) bool
	prune(t *rapid.T, req v1PruneRequest) (jobs, deliveries int64)
	verify(t *rapid.T, x *v1Machine)
	close(t *rapid.T)
}

type v1Machine struct {
	t    *rapid.T
	envs []string // the environments of this run, a prefix of v1Envs
	cfg  v1Config
	m    v1Model
	prev v1Model // state before the current command
	st   v1Backend

	emitted  []v1Emission
	inflight []int // indices into emitted
	forged   int
}

func newV1Machine(t *rapid.T, mutant v1Mutant, st v1Backend) *v1Machine {
	envs := v1Envs[:rapid.IntRange(1, len(v1Envs)).Draw(t, "environments")]
	cfg := v1Config{untrusted: map[string]bool{}, mutant: mutant}
	for _, e := range envs {
		cfg.untrusted[e] = rapid.Bool().Draw(t, "untrusted "+e)
	}
	cfg.grace = rapid.IntRange(1, 2).Draw(t, "grace")
	cfg.ttl = rapid.Int64Range(0, 3).Draw(t, "ttl")

	m := v1Model{
		head:       map[string]string{},
		open:       map[string]bool{},
		approvedGH: map[string]map[string]bool{},
		openerOK:   map[string]bool{},
		clock:      v1Clock0,
		jobs:       map[int64]v1Job{},
		nextID:     1,
		deliveries: map[string]v1DeliveryRecord{},
		watermark:  map[string]int64{},

		approvalDeliveries: map[string]v1DeliveryRecord{},
		host:               map[string]v1HostEnv{},
		deployedAt:         map[string]int64{},
		revalFails:         map[string]int{},
		authzEpoch:         map[int64]int64{},
		maxTs:              map[string]int64{},
	}
	for _, e := range envs {
		m.approvedGH[e] = map[string]bool{}
		m.openerOK[e] = true
		// Init: a leftover from an earlier install that no job tracks.
		if rapid.Bool().Draw(t, "stray "+e) {
			m.host[e] = v1HostEnv{Running: true, NetworkBound: true, SecretsMounted: true, Routed: true}
		}
	}
	x := &v1Machine{t: t, envs: envs, cfg: cfg, m: m, st: st}
	if st != nil {
		st.configure(cfg)
	}
	x.boot(t)
	x.prev = x.m.clone()
	return x
}

func (x *v1Machine) now() time.Time { return v1TimeAt(x.m.clock) }

// log records one model transition; rapid prints it for a failing run only.
func (x *v1Machine) log(format string, args ...any) {
	if x.t != nil {
		x.t.Logf(format, args...)
	}
}

// trusted is Trusted(e): from GitHub truth, never cached (D-V1-5).
func (x *v1Machine) trusted(e string) bool {
	return !x.cfg.untrusted[e] && x.m.openerOK[e]
}

// liveIn is the algorithm's LiveApproval over a, with V1-M06 applied.
func (x *v1Machine) liveIn(a []v1ApprovalRecord, e, c string) bool {
	switch x.cfg.mutant {
	case v1M06:
		return slices.ContainsFunc(a, func(r v1ApprovalRecord) bool { return r.Grant && r.EnvID == e && r.Commit == c }) &&
			!slices.ContainsFunc(a, func(r v1ApprovalRecord) bool { return !r.Grant && r.EnvID == e && r.Commit == c })
	case v1M06b:
		live := false
		for _, r := range a {
			if r.EnvID == e && r.Commit == c {
				live = r.Grant
			}
		}
		return live
	}
	return v1LiveIn(a, e, c)
}

func (x *v1Machine) approvedNow(e, c string) bool {
	switch x.cfg.mutant {
	case v1M01:
		return true
	case v1M02:
		return x.liveIn(x.m.approvals, e, c)
	}
	return x.liveIn(x.m.approvals, e, c) && x.m.approvedGH[e][c]
}

// allowed is Allowed(e, c) as the Revalidator reads it.
func (x *v1Machine) allowed(e, c string) bool {
	if x.cfg.mutant == v1M19 && !x.cfg.untrusted[e] {
		return true
	}
	return x.trusted(e) || x.approvedNow(e, c)
}

// revokedVersionRuns is RevokedVersionRuns(e) (A2-6): what runs was
// authorized by approval and the DB no longer holds a live grant of its
// commit. A DB read, no GHES call.
func (x *v1Machine) revokedVersionRuns(e string) bool {
	m := &x.m
	b, ok := m.builder(e)
	return m.exists(e) && ok && b.Trust == v1TrustUntrusted && !x.liveIn(m.approvals, e, m.host[e].Commit)
}

func (x *v1Machine) needsRevalidation(e string) bool {
	if x.cfg.mutant == v1M19 && !x.cfg.untrusted[e] {
		return false
	}
	return x.m.exists(e) && x.m.builderSucceeded(e) && x.m.builderIsLatest(e)
}

// expirable is Expirable(e): what runs is older than the TTL, or the
// latest intent is a deploy parked for an approval since it was created at
// least the TTL ago (G leftover: a parked fork does not wait forever).
func (x *v1Machine) expirable(e string) bool {
	m := &x.m
	if x.cfg.ttl <= 0 {
		return false
	}
	if l, ok := m.latest(e); ok && l.Type == JobDeploy && l.Status == v1StatusPending && x.cfg.mutant != v1M23 {
		return x.now().UnixMilli()-l.CreatedAt >= (time.Duration(x.cfg.ttl) * v1Tick).Milliseconds()
	}
	return m.intact(e) && m.builderSucceeded(e) && m.builderIsLatest(e) &&
		m.clock-m.deployedAt[e] >= x.cfg.ttl
}

func (x *v1Machine) expirableEnvs() []string {
	var envs []string
	for _, e := range x.envs {
		if x.expirable(e) {
			envs = append(envs, e)
		}
	}
	return envs
}

// internal appends one internal job just above the latest seq of its
// environment (the Internal macro, A2-2) and returns it.
func (x *v1Machine) internal(e string, typ JobType, commit string, origin v1Origin) v1Job {
	m := &x.m
	now := x.now()
	seq := m.maxSeq(e) + 1
	switch {
	case x.cfg.mutant == v1M13 && m.maxSeq(e) > 0:
		seq = m.maxSeq(e)
	case x.cfg.mutant == v1M21:
		seq = max(m.maxSeq(e), uuidV1Ticks(now)) + 1
	}
	j := v1Job{
		ID: m.nextID, EnvID: e, Type: typ, Origin: origin, Seq: seq, Status: StatusQueued,
		Trust: v1TrustUnclassified, CreatedAt: now.UnixMilli(), Commit: commit,
	}
	m.jobs[j.ID] = j
	m.nextID++
	m.maxTs[e] = max(m.maxTs[e], seq)
	x.log("internal %s job %d of %s at %s (%s)", typ, j.ID, e, short(commit), origin)
	return j
}

// emit is the Emit macro: GitHub stamps one delivery and sends it.
func (x *v1Machine) emit(kind v1Kind, e, c string) {
	x.m.clock++
	id := fmt.Sprintf("d-%04d", len(x.emitted)+1)
	x.emitted = append(x.emitted, v1Emission{
		ID: id, Payload: payloadHash("v1 body of " + id), Kind: kind, EnvID: e, Commit: c,
		Seq: x.m.clock * v1SeqPerTick,
	})
	x.inflight = append(x.inflight, len(x.emitted)-1)
	x.log("github emits %s %s %s of %s", id, kind, short(c), e)
}

func sampleEnv(t *rapid.T, envs []string, label string) string {
	if len(envs) == 0 {
		t.Skip("no environment for " + label)
	}
	return rapid.SampledFrom(envs).Draw(t, label)
}

func (x *v1Machine) envsWhere(pred func(string) bool) []string {
	var envs []string
	for _, e := range x.envs {
		if pred(e) {
			envs = append(envs, e)
		}
	}
	return envs
}

// ---------------------------------------------------------------------------
// GitHub: human and external actions, never forced.
// ---------------------------------------------------------------------------

// Open is opened or reopened (the head stays when reopened).
func (x *v1Machine) Open(t *rapid.T) {
	e := sampleEnv(t, x.envsWhere(func(e string) bool { return !x.m.open[e] }), "open")
	c := x.m.head[e]
	if c == "" {
		c = rapid.SampledFrom(v1Commits).Draw(t, "commit")
	}
	x.m.open[e], x.m.head[e] = true, c
	x.emit(v1KindDeploy, e, c)
}

// Push is synchronize; the same commit again is a force-push back.
func (x *v1Machine) Push(t *rapid.T) {
	e := sampleEnv(t, x.envsWhere(func(e string) bool { return x.m.open[e] }), "push")
	c := rapid.SampledFrom(v1Commits).Draw(t, "commit")
	x.m.head[e] = c
	x.emit(v1KindDeploy, e, c)
}

// Close is closed.
func (x *v1Machine) Close(t *rapid.T) {
	e := sampleEnv(t, x.envsWhere(func(e string) bool { return x.m.open[e] }), "close")
	x.m.open[e] = false
	x.emit(v1KindTeardown, e, x.m.head[e])
}

// Approve: an approver approves the head (review, or label under D-V1-3).
func (x *v1Machine) Approve(t *rapid.T) {
	e := sampleEnv(t, x.envsWhere(func(e string) bool { return x.m.open[e] }), "approve")
	c := x.m.head[e]
	x.m.approvedGH[e][c] = true
	x.emit(v1KindGrant, e, c)
}

// Dismiss: dismissal, change request or label removal of a live approval.
func (x *v1Machine) Dismiss(t *rapid.T) {
	e := sampleEnv(t, x.envsWhere(func(e string) bool { return len(x.m.approvedGH[e]) > 0 }), "dismiss")
	c := rapid.SampledFrom(slices.Sorted(maps.Keys(x.m.approvedGH[e]))).Draw(t, "commit")
	delete(x.m.approvedGH[e], c)
	x.emit(v1KindRevoke, e, c)
}

// Redeliver: GitHub sends a delivery again (same ID, body and seq).
func (x *v1Machine) Redeliver(t *rapid.T) {
	var idle []int
	for i := range x.emitted {
		if !slices.Contains(x.inflight, i) {
			idle = append(idle, i)
		}
	}
	if len(idle) == 0 {
		t.Skip("nothing to redeliver")
	}
	x.inflight = append(x.inflight, rapid.SampledFrom(idle).Draw(t, "redelivery"))
}

// ForgedRedelivery: a captured body, of any kind, resent under a new
// delivery ID (the header is unsigned). The signed body binds the time
// (V1-I7), so the seq is the original's: a replay while the delivery is
// recorded; once pruned, a deploy or teardown is stale, a grant older than
// what revoked it, a revocation harmless.
func (x *v1Machine) ForgedRedelivery(t *rapid.T) {
	webhooks := make([]int, len(x.emitted))
	for i := range x.emitted {
		webhooks[i] = i
	}
	if len(webhooks) == 0 {
		t.Skip("no delivery yet")
	}
	d := x.emitted[rapid.SampledFrom(webhooks).Draw(t, "captured")]
	x.forged++
	d.ID = fmt.Sprintf("forged-%04d", x.forged)
	x.receive(t, d)
}

// PermissionLoss: a silent loss of write access, no webhook (D-V1-5). For
// an untrusted environment the approver loses it, for a trusted one the
// opener does.
func (x *v1Machine) PermissionLoss(t *rapid.T) {
	e := sampleEnv(t, x.envs, "permission loss")
	if x.cfg.untrusted[e] {
		x.m.approvedGH[e] = map[string]bool{}
	} else {
		x.m.openerOK[e] = false
	}
}

// Tick: time passes without an event.
func (x *v1Machine) Tick(t *rapid.T) {
	x.m.clock++
}

// ---------------------------------------------------------------------------
// Api: one store transaction per delivery.
// ---------------------------------------------------------------------------

// ReceiveWebhook takes any delivery in flight: the network reorders freely.
func (x *v1Machine) ReceiveWebhook(t *rapid.T) {
	if len(x.inflight) == 0 {
		t.Skip("nothing in flight")
	}
	i := rapid.IntRange(0, len(x.inflight)-1).Draw(t, "delivery")
	d := x.emitted[x.inflight[i]]
	x.inflight = slices.Delete(x.inflight, i, i+1)
	x.receive(t, d)
}

func (x *v1Machine) receive(t *rapid.T, d v1Emission) {
	x.log("receive %s %s %s of %s", d.ID, d.Kind, short(d.Commit), d.EnvID)
	switch d.Kind {
	case v1KindDeploy, v1KindTeardown:
		x.receiveWebhookJob(t, d)
	case v1KindGrant:
		x.receiveGrant(t, d)
	case v1KindRevoke:
		x.receiveRevoke(t, d)
	}
}

// replayed is the replay rule over every recorded delivery, of any kind:
// the same ID, or the same signed body.
func (x *v1Machine) replayed(d v1Emission) bool {
	for _, recorded := range []map[string]v1DeliveryRecord{x.m.deliveries, x.m.approvalDeliveries} {
		if _, ok := recorded[d.ID]; ok {
			return true
		}
		for _, r := range recorded {
			if r.Payload == d.Payload {
				return true
			}
		}
	}
	return false
}

// recordApprovalDelivery replay-checks a grant or revoke delivery and
// records it; false for a replay, which changes nothing.
func (x *v1Machine) recordApprovalDelivery(d v1Emission, now time.Time) bool {
	if x.replayed(d) {
		x.log("  replay")
		return false
	}
	x.m.approvalDeliveries[d.ID] = v1DeliveryRecord{EnvID: d.EnvID, Seq: d.Seq, Verdict: VerdictAccepted, Payload: d.Payload, ReceivedAt: now.UnixMilli()}
	return true
}

func (x *v1Machine) receiveWebhookJob(t *rapid.T, d v1Emission) {
	m := &x.m
	now := x.now()
	want, wantID := VerdictReplay, int64(0)
	if !x.replayed(d) {
		want = VerdictAccepted
		if d.Seq <= m.maxSeq(d.EnvID) {
			want = VerdictStale // D1, against max(jobs, watermark)
		}
		m.deliveries[d.ID] = v1DeliveryRecord{EnvID: d.EnvID, Seq: d.Seq, Verdict: want, Payload: d.Payload, ReceivedAt: now.UnixMilli()}
	}
	x.log("  verdict %s", want)
	if want == VerdictAccepted {
		typ := JobDeploy
		if d.Kind == v1KindTeardown {
			typ = JobTeardown
		}
		superseded := false
		for _, j := range m.jobs {
			superseded = superseded || (j.EnvID == d.EnvID && j.Commit != d.Commit)
		}
		wantID = m.nextID
		m.jobs[wantID] = v1Job{
			ID: wantID, EnvID: d.EnvID, Type: typ, Origin: v1OriginWebhook, Seq: d.Seq, Status: StatusQueued,
			Trust: v1TrustUnclassified, CreatedAt: now.UnixMilli(), Commit: d.Commit,
		}
		m.nextID++
		m.maxTs[d.EnvID] = d.Seq
		if typ == JobDeploy {
			// New head: the approvals of every other commit are revoked;
			// the deploy itself supersedes the old version.
			for _, c := range v1Commits {
				if c != d.Commit {
					m.approvals = append(m.approvals, v1ApprovalRecord{EnvID: d.EnvID, Commit: c, Seq: d.Seq})
				}
			}
			if x.cfg.mutant == v1M10 && superseded {
				x.internal(d.EnvID, JobTeardown, d.Commit, v1OriginRevocation)
			}
		}
	}
	if x.st != nil {
		verdict, jobID := x.st.enqueue(t, d, now)
		if verdict != want || jobID != wantID {
			t.Fatalf("enqueue %+v = %s/%d, model %s/%d", d, verdict, jobID, want, wantID)
		}
	}
}

func (x *v1Machine) receiveGrant(t *rapid.T, d v1Emission) {
	m := &x.m
	now := x.now()
	e, c := d.EnvID, d.Commit
	g := v1Grant{ID: d.ID, Payload: d.Payload, EnvID: e, Commit: c, Seq: d.Seq, Trusted: x.trusted(e), OpenHead: m.open[e] && m.head[e] == c}
	want, wantID := VerdictReplay, int64(0)
	if x.recordApprovalDelivery(d, now) {
		want = VerdictAccepted
		m.approvals = append(m.approvals, v1ApprovalRecord{Grant: true, EnvID: e, Commit: c, Seq: d.Seq})
	}
	if want == VerdictAccepted && !g.Trusted && x.liveIn(m.approvals, e, c) {
		// The latest intent is the parked deploy of this commit: unpark
		// it. Otherwise, if the commit is still the open head and no
		// deploy of it is the latest intent, queue one (A1-3).
		l, ok := m.latest(e)
		unpark := ok && l.Status == v1StatusPending && (l.Commit == c || x.cfg.mutant == v1M03)
		switch {
		case unpark:
			l.Status = StatusQueued
			m.jobs[l.ID] = l
			wantID = l.ID
			x.log("  unpark job %d", l.ID)
		case g.OpenHead && !m.headIntentPresent(e, c) && x.cfg.mutant != v1M11:
			wantID = x.internal(e, JobDeploy, c, v1OriginApproval).ID
		}
	}
	if x.st != nil {
		if verdict, jobID := x.st.approve(t, g, now); verdict != want || jobID != wantID {
			t.Fatalf("approve %+v = %s/%d, model %s/%d", g, verdict, jobID, want, wantID)
		}
	}
}

func (x *v1Machine) receiveRevoke(t *rapid.T, d v1Emission) {
	m := &x.m
	now := x.now()
	e, c := d.EnvID, d.Commit
	r := v1Revocation{ID: d.ID, Payload: d.Payload, EnvID: e, Commit: c, Seq: d.Seq, Trusted: x.trusted(e)}
	want := VerdictReplay
	if x.recordApprovalDelivery(d, now) {
		want = VerdictAccepted
		m.approvals = append(m.approvals, v1ApprovalRecord{EnvID: e, Commit: c, Seq: d.Seq})
	}
	// The teardown judges the latest intent (A2-1): when it deploys another
	// commit, that intent already removes c (ExecuteDeploy replaces it, Park
	// destroys it), and a teardown above it would skip the new head.
	affected := m.headIntentPresent(e, c)
	if x.cfg.mutant == v1M20 {
		affected = m.runningCommit(e, c) || m.activeDeployOf(e, c)
	}
	var wantID int64
	if want == VerdictAccepted && !r.Trusted && !x.liveIn(m.approvals, e, c) && affected && x.cfg.mutant != v1M05 {
		wantID = x.internal(e, JobTeardown, c, v1OriginRevocation).ID
	}
	if x.st != nil {
		if verdict, jobID := x.st.revoke(t, r, now); verdict != want || jobID != wantID {
			t.Fatalf("revoke %+v = %s/%d, model %s/%d", r, verdict, jobID, want, wantID)
		}
	}
}

// ---------------------------------------------------------------------------
// Reconciler workers.
// ---------------------------------------------------------------------------

// AcquireJob on an idle worker.
func (x *v1Machine) AcquireJob(t *rapid.T) {
	x.acquire(t, x.pickWorker(t, false))
}

func (x *v1Machine) pickWorker(t *rapid.T, busy bool) int {
	var candidates []int
	for w := range x.m.workers {
		if (x.m.workers[w].Next != stepIdle) == busy {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		t.Skip("no such worker")
	}
	return rapid.SampledFrom(candidates).Draw(t, "worker")
}

// modelNext is AcquireJob's choice: among environments with no IN_PROGRESS
// job whose newest QUEUED job is due, the lowest such job ID; 0 if none. A
// PENDING_APPROVAL job is neither acquirable nor a lock.
func (x *v1Machine) modelNext() int64 {
	now := x.now().UnixMilli()
	var best int64
	for _, e := range x.envs {
		var newest *v1Job
		locked := false
		unlocked := x.cfg.mutant == v1M18 && x.cfg.untrusted[e] // V1-M18: no lock
		for _, j := range x.m.jobsOf(e) {
			if j.Status == StatusInProgress && !unlocked {
				locked = true
			}
			if j.Status == StatusQueued && (newest == nil || j.Seq > newest.Seq) {
				newest = &j
			}
		}
		if locked || newest == nil || newest.NotBefore > now {
			continue
		}
		if best == 0 || newest.ID < best {
			best = newest.ID
		}
	}
	return best
}

func (x *v1Machine) acquire(t *rapid.T, w int) bool {
	m := &x.m
	now := x.now()
	id := x.modelNext()
	if x.st != nil {
		lease, ok := x.st.acquire(t, now)
		if ok != (id != 0) || (ok && lease.JobID != id) {
			t.Fatalf("acquire = job %d (%v), model leases %d", lease.JobID, ok, id)
		}
		if ok {
			j := m.jobs[id]
			want := v1Lease{JobID: id, EnvID: j.EnvID, Type: j.Type, Seq: j.Seq, Epoch: m.epoch, Attempts: j.Attempts, Commit: j.Commit}
			if lease != want {
				t.Fatalf("lease %+v, model %+v", lease, want)
			}
		}
	}
	if id == 0 {
		return false
	}
	target := m.jobs[id]
	// The newest intent is leased; older queued and parked intents are
	// skipped.
	for _, j := range m.jobsOf(target.EnvID) {
		if j.ID != id && (j.Status == StatusQueued || (j.Status == v1StatusPending && j.Seq < target.Seq)) {
			j.Status, j.FinishedAt = StatusSkipped, now.UnixMilli()
			m.jobs[j.ID] = j
		}
	}
	target.Status, target.LeaseEpoch = StatusInProgress, m.epoch
	m.jobs[id] = target
	x.log("worker %d leases %s job %d of %s at %s", w, target.Type, id, target.EnvID, short(target.Commit))
	next := stepExecuteTeardown
	if target.Type == JobDeploy {
		next = stepAuthorize
		if x.cfg.mutant == v1M12 && target.Trust != v1TrustUnclassified {
			next = stepExecuteDeploy
		}
	}
	m.workers[w] = v1Worker{JobID: id, Next: next}
	return true
}

// Step advances a busy worker by one step. The GHES or Docker call may fail.
func (x *v1Machine) Step(t *rapid.T) {
	w := x.pickWorker(t, true)
	x.step(t, w, callOK(t))
}

// callOK draws the outcome of one Docker or GHES call: a fault one time in
// seven. With even odds, a deploy (five calls) would almost never reach
// SUCCESS. Shrinking goes toward success.
func callOK(t *rapid.T) bool {
	return rapid.SampledFrom([]bool{true, true, true, true, true, true, false}).Draw(t, "call ok")
}

func (x *v1Machine) step(t *rapid.T, w int, ok bool) {
	m := &x.m
	wk := &m.workers[w]
	j := m.jobs[wk.JobID]
	e := j.EnvID
	now := x.now()
	switch wk.Next {
	case stepAuthorize:
		x.authorize(t, w, ok)
	case stepExecuteDeploy:
		if !ok {
			x.failDeploy(t, w)
			return
		}
		// Remove the previous version, fetch, network, build, stage.
		m.host[e] = v1HostEnv{NetworkBound: true, SecretsMounted: true, JobID: j.ID, Seq: j.Seq, Commit: j.Commit}
		wk.Next = stepStartContainer
	case stepStartContainer:
		if !ok {
			x.failDeploy(t, w)
			return
		}
		h := m.host[e]
		h.Running = true
		m.host[e] = h
		wk.Next = stepPublishRoute
	case stepPublishRoute:
		if !ok {
			x.failDeploy(t, w)
			return
		}
		h := m.host[e]
		h.Routed = true
		m.host[e] = h
		wk.Next = stepCommitDeploy
	case stepCommitDeploy:
		if x.st != nil && x.st.finish(t, j.ID, StatusSuccess, now) {
			t.Fatalf("commit deploy %d refused", j.ID)
		}
		j.Status, j.FinishedAt = StatusSuccess, now.UnixMilli()
		m.jobs[j.ID] = j
		m.deployedAt[e] = m.clock
		*wk = v1Worker{}
		x.log("worker %d: deploy %d SUCCESS, %s runs %s", w, j.ID, e, short(j.Commit))
	case stepExecuteTeardown:
		if !ok {
			// Transient failure: back to QUEUED with backoff, never FAILED.
			notBefore := now.Add(backoff(j.Attempts))
			if x.st != nil {
				if !x.st.finish(t, j.ID, StatusFailed, now) {
					t.Fatalf("teardown %d finished as FAILED", j.ID)
				}
				if x.st.requeue(t, j.ID, notBefore) {
					t.Fatalf("requeue of teardown %d refused", j.ID)
				}
			}
			j.Status, j.Attempts, j.NotBefore = StatusQueued, j.Attempts+1, notBefore.UnixMilli()
			m.jobs[j.ID] = j
			*wk = v1Worker{}
			return
		}
		delete(m.host, e)
		wk.Next = stepCommitTeardown
	case stepCommitTeardown:
		if x.st != nil && x.st.finish(t, j.ID, StatusSuccess, now) {
			t.Fatalf("commit teardown %d refused", j.ID)
		}
		j.Status, j.FinishedAt = StatusSuccess, now.UnixMilli()
		m.jobs[j.ID] = j
		*wk = v1Worker{}
		x.log("worker %d: teardown %d SUCCESS", w, j.ID)
	default:
		t.Fatalf("worker %d has no step", w)
	}
}

// authorize is AuthorizeDeploy. ok false is GHES unavailable.
func (x *v1Machine) authorize(t *rapid.T, w int, ok bool) {
	m := &x.m
	wk := &m.workers[w]
	j := m.jobs[wk.JobID]
	e, c := j.EnvID, j.Commit
	now := x.now()

	classify := func(trust v1Trust) {
		if x.st != nil && x.st.classify(t, j.ID, trust) {
			t.Fatalf("classify job %d as %s refused", j.ID, trust)
		}
		j.Trust = trust
		m.jobs[j.ID] = j
		m.authzEpoch[j.ID] = m.epoch
		x.log("worker %d authorizes job %d: %s", w, j.ID, trust)
		wk.Next = stepExecuteDeploy
	}

	switch {
	case !ok && x.cfg.mutant == v1M09:
		trust := v1TrustTrusted
		if x.cfg.untrusted[e] {
			trust = v1TrustUntrusted
		}
		classify(trust)
	case !ok:
		// GHES unavailable: back to QUEUED. A version authorized by
		// approval whose grant the DB no longer holds live is removed
		// first (A2-6): this deploy supersedes it and cannot run until GHES
		// answers. Nothing else changes on the host.
		if b, found := m.builder(e); x.st != nil && m.exists(e) && found && b.Trust == v1TrustUntrusted {
			if got, want := x.st.approvalLive(t, e, b.Commit), x.liveIn(m.approvals, e, b.Commit); got != want {
				t.Fatalf("approval of %s at %s live = %v, model %v", e, short(b.Commit), got, want)
			}
		}
		if x.cfg.mutant != v1M22 && x.revokedVersionRuns(e) {
			delete(m.host, e)
			x.log("worker %d: GHES unavailable, revoked version of %s removed", w, e)
		}
		notBefore := now.Add(backoff(j.Attempts))
		if x.st != nil && x.st.requeue(t, j.ID, notBefore) {
			t.Fatalf("requeue of unclassified deploy %d refused", j.ID)
		}
		j.Status, j.Attempts, j.NotBefore = StatusQueued, j.Attempts+1, notBefore.UnixMilli()
		m.jobs[j.ID] = j
		*wk = v1Worker{}
		x.log("worker %d: GHES unavailable, job %d requeued", w, j.ID)
	case x.trusted(e):
		classify(v1TrustTrusted)
	case x.approvedNow(e, c):
		classify(v1TrustUntrusted)
	default:
		// Park: the superseded version is removed, the intent waits.
		if x.st != nil {
			// Fail closed: without a live approval in the DB, the store
			// refuses to record the deploy as approved.
			if !x.st.approvalLive(t, e, c) && !x.st.classify(t, j.ID, v1TrustUntrusted) {
				t.Fatalf("job %d classified untrusted without a live approval of %s", j.ID, c)
			}
			x.st.park(t, j.ID)
		}
		if x.cfg.mutant != v1M04 {
			delete(m.host, e)
		}
		j.Status = v1StatusPending
		m.jobs[j.ID] = j
		*wk = v1Worker{}
		x.log("worker %d parks job %d", w, j.ID)
	}
}

// failDeploy rolls the environment back to absent and fails the job; a
// classified deploy is never requeued.
func (x *v1Machine) failDeploy(t *rapid.T, w int) {
	m := &x.m
	j := m.jobs[m.workers[w].JobID]
	now := x.now()
	if x.st != nil {
		if !x.st.requeue(t, j.ID, now) {
			t.Fatalf("classified deploy %d requeued", j.ID)
		}
		if x.st.finish(t, j.ID, StatusFailed, now) {
			t.Fatalf("fail deploy %d refused", j.ID)
		}
	}
	delete(m.host, j.EnvID)
	j.Status, j.FinishedAt = StatusFailed, now.UnixMilli()
	m.jobs[j.ID] = j
	m.workers[w] = v1Worker{}
	x.log("worker %d: deploy %d FAILED", w, j.ID)
}

// ---------------------------------------------------------------------------
// Revalidator, Expirer, Pruner.
// ---------------------------------------------------------------------------

// Revalidate re-checks one running environment, trusted or not (D-V1-5).
func (x *v1Machine) Revalidate(t *rapid.T) {
	if x.cfg.mutant == v1M07 {
		t.Skip("V1-M07: the Revalidator is not fair and never runs")
	}
	e := sampleEnv(t, x.envsWhere(x.needsRevalidation), "revalidate")
	ok := callOK(t)
	if ok && x.m.revalFails[e] == 0 && x.allowed(e, x.m.host[e].Commit) {
		t.Skip("nothing to re-validate")
	}
	x.revalidate(t, e, ok)
}

func (x *v1Machine) revalidate(t *rapid.T, e string, ok bool) {
	m := &x.m
	c := m.host[e].Commit
	now := x.now()
	if !ok {
		// GHES unavailable; after Grace in a row, fail closed.
		if x.cfg.mutant == v1M08 || m.revalFails[e]+1 < x.cfg.grace {
			m.revalFails[e]++
			return
		}
		m.revalFails[e] = 0
		wantID := x.internal(e, JobTeardown, c, v1OriginRevalidation).ID
		if x.st != nil {
			if jobID := x.st.enqueueInternal(t, e, v1OriginRevalidation, false, now); jobID != wantID {
				t.Fatalf("fail-closed teardown of %s = job %d, model %d", e, jobID, wantID)
			}
		}
		return
	}
	if x.st != nil {
		if got, want := x.st.approvalLive(t, e, c), x.liveIn(m.approvals, e, c); got != want {
			t.Fatalf("approval of %s at %s live = %v, model %v", e, c, got, want)
		}
	}
	m.revalFails[e] = 0
	if x.allowed(e, c) {
		return
	}
	// GitHub truth now voids every grant it sent so far: the revocation
	// takes the current stamp.
	if x.liveIn(m.approvals, e, c) {
		m.approvals = append(m.approvals, v1ApprovalRecord{EnvID: e, Commit: c, Seq: uuidV1Ticks(now)})
	}
	j := x.internal(e, JobTeardown, c, v1OriginRevalidation)
	if x.st != nil {
		if jobID := x.st.enqueueInternal(t, e, v1OriginRevalidation, true, now); jobID != j.ID {
			t.Fatalf("revalidation teardown of %s = job %d, model %d", e, jobID, j.ID)
		}
	}
}

// Expire: an environment past its TTL leaves through the queue.
func (x *v1Machine) Expire(t *rapid.T) {
	if x.cfg.mutant == v1M17 {
		t.Skip("V1-M17: the Expirer is not fair and never runs")
	}
	x.expire(t, sampleEnv(t, x.expirableEnvs(), "expire"))
}

func (x *v1Machine) expire(t *rapid.T, e string) {
	now := x.now()
	l, _ := x.m.latest(e)
	wantID := x.internal(e, JobTeardown, l.Commit, v1OriginTTL).ID
	if x.st != nil {
		if jobID := x.st.enqueueInternal(t, e, v1OriginTTL, false, now); jobID != wantID {
			t.Fatalf("ttl teardown of %s = job %d, model %d", e, jobID, wantID)
		}
	}
}

// Prune deletes terminal jobs and deliveries past a drawn retention: an
// over-approximation of "older than the retention", as in the model.
func (x *v1Machine) Prune(t *rapid.T) {
	m := &x.m
	req := v1PruneRequest{
		Now:            x.now(),
		Retention:      time.Duration(rapid.Int64Range(0, 20).Draw(t, "retention ticks")) * v1Tick,
		DeliveryMaxAge: v1DeliveryMaxAge,
		Batch:          rapid.IntRange(1, 3).Draw(t, "batch"),
	}
	for _, e := range slices.Sorted(maps.Keys(m.host)) {
		if h := m.host[e]; h.exists() && h.JobID != 0 {
			req.Builders = append(req.Builders, h.JobID)
		}
	}

	jobCutoff := req.Now.Add(-req.Retention).UnixMilli()
	var jobs, deliveries int64
	for _, j := range m.sortedJobs() {
		l, _ := m.latest(j.EnvID)
		keepLatest := x.cfg.mutant != v1M14 && x.cfg.mutant != v1M15b
		h := m.host[j.EnvID]
		if !j.terminal() || j.FinishedAt >= jobCutoff || (keepLatest && j.ID == l.ID) || (h.exists() && h.JobID != 0 && j.Seq >= h.Seq) {
			continue
		}
		if x.cfg.mutant != v1M15 && x.cfg.mutant != v1M15b {
			m.watermark[j.EnvID] = max(m.watermark[j.EnvID], j.Seq)
		}
		delete(m.jobs, j.ID)
		jobs++
	}
	deliveryCutoff := req.Now.Add(-max(req.Retention, req.DeliveryMaxAge+5*time.Minute)).UnixMilli()
	for _, id := range slices.Sorted(maps.Keys(m.deliveries)) {
		r := m.deliveries[id]
		if r.ReceivedAt >= deliveryCutoff || (r.Seq > m.maxSeq(r.EnvID) && x.cfg.mutant != v1M16) {
			continue
		}
		delete(m.deliveries, id)
		m.prunedDeliveries = append(m.prunedDeliveries, r)
		deliveries++
	}
	// The same rule for approval deliveries (one table in the store). A
	// pruned grant comes back stale (V1-I7 binds its seq): never newer than
	// the revocation that killed it.
	for _, id := range slices.Sorted(maps.Keys(m.approvalDeliveries)) {
		r := m.approvalDeliveries[id]
		if r.ReceivedAt >= deliveryCutoff || r.Seq > m.maxSeq(r.EnvID) {
			continue
		}
		delete(m.approvalDeliveries, id)
		deliveries++
	}
	if x.st != nil {
		gotJobs, gotDeliveries := x.st.prune(t, req)
		if gotJobs != jobs || gotDeliveries != deliveries {
			t.Fatalf("prune %+v deleted %d jobs, %d deliveries; model %d, %d", req, gotJobs, gotDeliveries, jobs, deliveries)
		}
	}
}

// ---------------------------------------------------------------------------
// Chaos and Supervisor.
// ---------------------------------------------------------------------------

// SimulateCrash kills the daemon (leases and memory lost) or reboots the
// host (staged secrets lost too), then restarts through the sweep.
func (x *v1Machine) SimulateCrash(t *rapid.T) {
	reboot := rapid.Bool().Draw(t, "host reboot")
	if x.st != nil {
		x.st.crash(t)
	}
	m := &x.m
	m.workers = [spbtWorkers]v1Worker{}
	x.log("crash (host reboot %v)", reboot)
	if reboot {
		for e, h := range m.host {
			h.SecretsMounted = false
			m.host[e] = h
		}
	}
	x.boot(t)
}

// boot is StartupSweep on the model, and on the store when there is one.
func (x *v1Machine) boot(t *rapid.T) {
	m := &x.m
	now := x.now()
	observedHost := maps.Clone(m.host)
	m.epoch++
	keep := map[string]bool{}
	var destroy []string
	for _, e := range slices.Sorted(maps.Keys(m.host)) {
		if x.keep(e) {
			keep[e] = true
		} else if m.host[e].exists() {
			destroy = append(destroy, e)
		}
	}
	latest := map[string]int64{}
	for _, e := range x.envs {
		if l, ok := m.latest(e); ok {
			latest[e] = l.ID
		}
	}
	for _, j := range m.sortedJobs() {
		switch {
		case j.Status == StatusInProgress && j.Type == JobDeploy:
			j.Status, j.FinishedAt = StatusFailed, now.UnixMilli()
		case j.Status == StatusInProgress && j.Type == JobTeardown:
			j.Status = StatusQueued
		case j.Status == StatusSuccess && j.Type == JobDeploy && latest[j.EnvID] == j.ID && !keep[j.EnvID]:
			// Re-armed: authorized again in this boot.
			j.Status, j.NotBefore, j.FinishedAt = StatusQueued, 0, 0
			if x.cfg.mutant != v1M12 {
				j.Trust = v1TrustUnclassified
				delete(m.authzEpoch, j.ID)
			}
		default:
			continue
		}
		m.jobs[j.ID] = j
	}
	for _, e := range destroy {
		delete(m.host, e)
	}
	x.log("sweep epoch %d destroys %v", m.epoch, destroy)
	for _, e := range x.envs {
		m.revalFails[e] = 0
	}

	if x.st == nil {
		return
	}
	var observed []Observation
	for _, e := range slices.Sorted(maps.Keys(observedHost)) {
		h := observedHost[e]
		observed = append(observed, Observation{EnvID: e, Running: h.Running, NetworkBound: h.NetworkBound,
			SecretsMounted: h.SecretsMounted, Routed: h.Routed, JobID: h.JobID})
	}
	got := x.st.boot(t, now, observed)
	if got.Epoch != m.epoch || !slices.Equal(got.Destroy, destroy) {
		t.Fatalf("sweep = epoch %d, destroy %v; model epoch %d, destroy %v", got.Epoch, got.Destroy, m.epoch, destroy)
	}
}

// keep is Keep(e): intact, built by a SUCCESS deploy, and every newer job
// QUEUED or an interrupted teardown.
func (x *v1Machine) keep(e string) bool {
	m := &x.m
	if !m.intact(e) {
		return false
	}
	b, ok := m.builder(e)
	if !ok || b.Status != StatusSuccess {
		return false
	}
	for _, k := range m.jobsOf(e) {
		if k.Seq > b.Seq && k.Status != StatusQueued && (k.Status != StatusInProgress || k.Type != JobTeardown) {
			return false
		}
	}
	return true
}
