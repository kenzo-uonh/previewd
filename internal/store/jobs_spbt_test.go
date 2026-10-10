package store

// Stateful property-based test of the job queue (Phase 3 of
// docs/specs/formal_verification_plan.md).
//
// The reference model below is written from docs/formal/previewd.tla, not
// from jobs.go: ReceiveWebhook with replay protection (delivery ID and
// payload) and the D1 stale rule, AcquireJob, ExecuteDeploy ->
// StartContainer -> PublishRoute -> CommitDeploy, ExecuteTeardown ->
// CommitTeardown with requeue, SimulateCrash (daemon crash or host reboot)
// followed by StartupSweep (D2, D3). The test plays the reconciler: it drives
// the real Store on a real SQLite file (modernc, WAL) and a mocked Docker
// host, and after every command checks that the database equals the model
// and that the model's invariants hold on the database and the host. After
// the random sequence it drains the queue fault-free and checks the
// liveness properties.
//
// F2 (V1 spec, phase F; V1-I6): a twin store receives every operation the
// store receives, plus Prune at random points; the store itself is never
// pruned. After each Prune, every possible next delivery (a fresh one at
// each seq of each environment, and a redelivery of each delivery ever
// recorded) gets the same verdict from both, the only difference allowed
// being a forgotten delivery's redelivery: stale in the pruned twin where
// the store says replay, and never accepted. Every mirrored operation
// returns the same result from both, so pruning changes nothing the queue
// does. A captured body resent under a fresh delivery ID reaches the store
// only within V1-I7's window (the handler refuses it outside), which
// pruning never reaches.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
	"pgregory.net/rapid"
)

var spbtEnvs = []string{"pr-1-0a0a0a0a0a", "pr-2-0b0b0b0b0b", "pr-3-0c0c0c0c0c"}

const (
	spbtWorkers = 2
	spbtMaxSeq  = 12
	// spbtDeliveryMaxAge stands for PREVIEWD_DELIVERY_MAX_AGE: the V1-I7
	// window of the handler and Prune's delivery horizon.
	spbtDeliveryMaxAge = time.Minute
)

// isBusy reports SQLITE_BUSY (any extended code), the error the queue must
// never surface.
func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_BUSY
}

// fakeEnv is the mocked host's view of one environment: Docker resources,
// staged secrets, route document.
type fakeEnv struct {
	Running, NetworkBound, SecretsMounted, Routed bool
	JobID                                         int64 // builder; 0 for a stray
}

func (f fakeEnv) exists() bool {
	return f.Running || f.NetworkBound || f.SecretsMounted || f.Routed
}

func (f fakeEnv) intact() bool {
	return f.Running && f.NetworkBound && f.SecretsMounted && f.Routed
}

type step int

const (
	stepIdle step = iota
	stepExecuteDeploy
	stepStartContainer
	stepPublishRoute
	stepCommitDeploy
	stepExecuteTeardown
	stepCommitTeardown
)

type worker struct {
	lease Lease
	next  step
}

type modelDelivery struct {
	EnvID      string
	Seq        int64
	Verdict    Verdict
	Type       JobType
	Payload    string
	Source     Source
	ReceivedAt time.Time // the signed time V1-I7 binds a resent body to
}

type previewdMachine struct {
	ctx  context.Context
	dir  string
	path string

	store *Store
	now   time.Time

	// F2: pruned is the twin that Prune runs on. rerecorded lists the
	// deliveries it forgot and then recorded again, stale, on a GitHub
	// redelivery; store still holds them with their first verdict.
	pruned     *Store
	rerecorded map[string]bool
	pruneStats PruneStats // summed over the run's Prune commands
	// forgottenProbes counts redeliveries of forgotten deliveries judged
	// by checkNextVerdicts.
	forgottenProbes int

	// Reference model.
	jobs       []Job // index = ID-1
	deliveries map[string]modelDelivery
	payloads   map[string]bool
	epoch      int64

	// Mocked reconciler backend.
	host    map[string]fakeEnv
	workers [spbtWorkers]worker
	stale   []Lease // leases of workers killed by a crash
	nextID  int
}

func (m *previewdMachine) must(t *rapid.T, err error, what string) {
	t.Helper()
	if isBusy(err) {
		t.Fatalf("%s: SQLITE_BUSY surfaced: %v", what, err)
	}
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func newPreviewdMachine(t *rapid.T, base string) *previewdMachine {
	dir, err := os.MkdirTemp(base, "spbt-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	m := &previewdMachine{
		ctx:        context.Background(),
		dir:        dir,
		path:       dir + "/previewd.sqlite",
		now:        time.UnixMilli(1_800_000_000_000),
		deliveries: map[string]modelDelivery{},
		payloads:   map[string]bool{},
		host:       map[string]fakeEnv{},
		rerecorded: map[string]bool{},
	}
	// Init: each environment may hold a leftover from an earlier install
	// that no job tracks.
	for _, e := range spbtEnvs {
		if rapid.Bool().Draw(t, "stray "+e) {
			m.host[e] = fakeEnv{Running: true, NetworkBound: true, SecretsMounted: true, Routed: true}
		}
	}
	m.boot(t)
	return m
}

// stores is the store and its pruned twin: every operation but Prune runs
// on both.
func (m *previewdMachine) stores() []*Store {
	return []*Store{m.store, m.pruned}
}

// mustBoth runs fn on the store and on its twin; both must succeed.
func (m *previewdMachine) mustBoth(t *rapid.T, what string, fn func(*Store) error) {
	t.Helper()
	m.must(t, fn(m.store), what)
	m.must(t, fn(m.pruned), what+" (pruned twin)")
}

func (m *previewdMachine) cleanup(t *rapid.T) {
	for _, s := range []*Store{m.store, m.pruned} {
		if s == nil {
			continue
		}
		if err := s.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	}
	if err := os.RemoveAll(m.dir); err != nil {
		t.Errorf("remove temp dir: %v", err)
	}
}

// boot opens the store and its twin and runs the startup sweep against the
// model's: both sweeps must return the same result.
func (m *previewdMachine) boot(t *rapid.T) {
	s, err := NewStore(m.ctx, m.path)
	m.must(t, err, "open store")
	m.store = s
	p, err := NewStore(m.ctx, m.dir+"/pruned.sqlite")
	m.must(t, err, "open pruned twin")
	m.pruned = p

	for _, s := range m.stores() {
		if _, _, err := s.Acquire(m.ctx, m.now); !errors.Is(err, ErrNotSwept) {
			t.Fatalf("acquire before the sweep: got %v, want ErrNotSwept", err)
		}
	}

	var observed []Observation
	for _, e := range slices.Sorted(maps.Keys(m.host)) {
		h := m.host[e]
		observed = append(observed, Observation{EnvID: e, Running: h.Running, NetworkBound: h.NetworkBound, SecretsMounted: h.SecretsMounted, Routed: h.Routed, JobID: h.JobID})
	}
	got, err := s.StartupSweep(m.ctx, m.now, observed)
	m.must(t, err, "startup sweep")
	twin, err := p.StartupSweep(m.ctx, m.now, observed)
	m.must(t, err, "startup sweep (pruned twin)")
	if twin.Epoch != got.Epoch || !slices.Equal(twin.Destroy, got.Destroy) {
		t.Fatalf("sweep of the pruned twin = %+v, store = %+v", twin, got)
	}

	want := m.modelSweep()
	if got.Epoch != m.epoch {
		t.Fatalf("sweep epoch = %d, want %d", got.Epoch, m.epoch)
	}
	if !slices.Equal(got.Destroy, want) {
		t.Fatalf("sweep destroys %v, model destroys %v", got.Destroy, want)
	}
	for _, e := range got.Destroy {
		delete(m.host, e)
	}
}

// modelSweep applies StartupSweep to the model and returns what to destroy.
func (m *previewdMachine) modelSweep() []string {
	m.epoch++
	keep := map[string]bool{}
	var destroy []string
	for _, e := range slices.Sorted(maps.Keys(m.host)) {
		h := m.host[e]
		if m.modelKeep(e, h) {
			keep[e] = true
		} else if h.exists() {
			destroy = append(destroy, e)
		}
	}
	latest := m.modelLatest()
	for i := range m.jobs {
		j := &m.jobs[i]
		switch {
		case j.Status == StatusInProgress && j.Type == JobDeploy:
			j.Status, j.FinishedAt, j.Failure = StatusFailed, m.now.UnixMilli(), FailureInterrupted
		case j.Status == StatusInProgress && j.Type == JobTeardown:
			j.Status = StatusQueued
		case j.Status == StatusSuccess && j.Type == JobDeploy && latest[j.EnvID] == j.ID && !keep[j.EnvID]:
			j.Status, j.NotBefore, j.FinishedAt, j.Trust = StatusQueued, 0, 0, TrustUnclassified
		}
	}
	return destroy
}

// modelKeep is Keep(e): intact, built by a SUCCESS deploy, and every newer
// job QUEUED or an interrupted teardown.
func (m *previewdMachine) modelKeep(e string, h fakeEnv) bool {
	if !h.intact() || h.JobID == 0 || h.JobID > int64(len(m.jobs)) {
		return false
	}
	b := m.jobs[h.JobID-1]
	if b.EnvID != e || b.Type != JobDeploy || b.Status != StatusSuccess {
		return false
	}
	for _, k := range m.jobs {
		if k.EnvID == e && k.Seq > b.Seq &&
			k.Status != StatusQueued && (k.Status != StatusInProgress || k.Type != JobTeardown) {
			return false
		}
	}
	return true
}

// modelLatest maps each environment to its job with the highest Seq.
func (m *previewdMachine) modelLatest() map[string]int64 {
	latest := map[string]int64{}
	for _, j := range m.jobs {
		if id, ok := latest[j.EnvID]; !ok || j.Seq > m.jobs[id-1].Seq {
			latest[j.EnvID] = j.ID
		}
	}
	return latest
}

// ReceiveWebhook: a fresh delivery, possibly out of order.
func (m *previewdMachine) ReceiveWebhook(t *rapid.T) {
	m.nextID++
	id := fmt.Sprintf("d-%04d", m.nextID)
	d := testDelivery(id,
		rapid.SampledFrom(spbtEnvs).Draw(t, "env"),
		rapid.SampledFrom([]JobType{JobDeploy, JobTeardown}).Draw(t, "type"),
		rapid.Int64Range(1, spbtMaxSeq).Draw(t, "seq"))
	d.Source.PRNumber = rapid.Int64Range(1, 9).Draw(t, "pr")
	d.Source.CommitSHA = fmt.Sprintf("%040x", rapid.Uint64().Draw(t, "commit"))
	d.ReceivedAt = m.now
	m.receive(t, d)
}

// ForgedRedelivery: a captured body resent under a new delivery ID and a
// later timestamp (the header is unsigned). The handler refuses it once its
// signed time is outside V1-I7's window; within it, replay protection by
// payload drops it, in the pruned twin too: Prune keeps every delivery
// longer than the window.
func (m *previewdMachine) ForgedRedelivery(t *rapid.T) {
	if len(m.deliveries) == 0 {
		t.Skip("no delivery yet")
	}
	orig := m.deliveries[rapid.SampledFrom(slices.Sorted(maps.Keys(m.deliveries))).Draw(t, "captured")]
	if m.now.Sub(orig.ReceivedAt) > spbtDeliveryMaxAge {
		return // V1-I7: refused (400) before the store
	}
	if m.forgotten(t, "", orig.Payload) {
		t.Fatalf("V1-I7 ordering: a body signed %s ago passes the window but the pruned twin forgot it", m.now.Sub(orig.ReceivedAt))
	}
	m.nextID++
	m.receive(t, Delivery{
		ID: fmt.Sprintf("d-%04d", m.nextID), PayloadSHA256: orig.Payload, EnvID: orig.EnvID,
		Type: orig.Type, Seq: spbtMaxSeq + 1, Source: orig.Source, ReceivedAt: m.now,
	})
}

// forgotten reports whether the pruned twin holds no delivery with this ID
// or this payload.
func (m *previewdMachine) forgotten(t *rapid.T, id, payload string) bool {
	var n int
	m.must(t, m.pruned.db.QueryRowContext(m.ctx, `SELECT count(*) FROM deliveries WHERE delivery_id = ? OR payload_sha256 = ?`, id, payload).Scan(&n),
		"pruned twin: replay keys")
	return n == 0
}

// enqueueBoth records d in the store and in its pruned twin and checks the
// twin's verdict against the store's (twinVerdict).
func (m *previewdMachine) enqueueBoth(t *rapid.T, d Delivery) (Verdict, int64) {
	forgotten := m.forgotten(t, d.ID, d.PayloadSHA256)
	verdict, jobID, err := m.store.Enqueue(m.ctx, d)
	m.must(t, err, "enqueue")
	pv, pid, err := m.pruned.Enqueue(m.ctx, d)
	m.must(t, err, "enqueue (pruned twin)")
	if m.twinVerdict(t, d, forgotten, verdict, jobID, pv, pid) {
		m.rerecorded[d.ID] = true
	}
	return verdict, jobID
}

// twinVerdict checks the pruned twin's verdict pv/pid on d against the
// store's v/id. They are equal, except for a redelivery of a delivery the
// twin forgot: stale there, replay in the store, and no job in either. It
// reports that exception.
func (m *previewdMachine) twinVerdict(t *rapid.T, d Delivery, forgotten bool, v Verdict, id int64, pv Verdict, pid int64) bool {
	t.Helper()
	if v == VerdictReplay && forgotten {
		if pv != VerdictStale || pid != 0 {
			t.Fatalf("V1-I6: redelivery %s (env %s, seq %d) of a pruned delivery = %s/%d in the twin, want stale", d.ID, d.EnvID, d.Seq, pv, pid)
		}
		return true
	}
	if pv != v || pid != id {
		t.Fatalf("V1-I6: delivery %s (env %s, seq %d) = %s/%d in the pruned twin, %s/%d in the store", d.ID, d.EnvID, d.Seq, pv, pid, v, id)
	}
	return false
}

func (m *previewdMachine) receive(t *rapid.T, d Delivery) {
	verdict, jobID := m.enqueueBoth(t, d)

	if _, seen := m.deliveries[d.ID]; seen || m.payloads[d.PayloadSHA256] {
		if verdict != VerdictReplay || jobID != 0 {
			t.Fatalf("replayed delivery %+v = %s/%d, want replay", d, verdict, jobID)
		}
		return
	}

	want, wantID := VerdictAccepted, int64(0)
	for _, j := range m.jobs {
		if j.EnvID == d.EnvID && j.Seq >= d.Seq {
			want = VerdictStale // D1: any newer job, whatever its status
		}
	}
	if want == VerdictAccepted {
		wantID = int64(len(m.jobs) + 1)
		m.jobs = append(m.jobs, Job{ID: wantID, EnvID: d.EnvID, Type: d.Type, Origin: OriginWebhook, Seq: d.Seq,
			Status: StatusQueued, Trust: TrustUnclassified, CreatedAt: d.ReceivedAt.UnixMilli(), Source: d.Source})
	}
	m.deliveries[d.ID] = modelDelivery{EnvID: d.EnvID, Seq: d.Seq, Verdict: want, Type: d.Type, Payload: d.PayloadSHA256, Source: d.Source, ReceivedAt: d.ReceivedAt}
	m.payloads[d.PayloadSHA256] = true
	if verdict != want || jobID != wantID {
		t.Fatalf("enqueue %+v = %s/%d, model %s/%d", d, verdict, jobID, want, wantID)
	}
}

// Redeliver: GitHub sends a delivery again; replay protection drops it.
func (m *previewdMachine) Redeliver(t *rapid.T) {
	if len(m.deliveries) == 0 {
		t.Skip("no delivery yet")
	}
	id := rapid.SampledFrom(slices.Sorted(maps.Keys(m.deliveries))).Draw(t, "delivery")
	d := m.deliveries[id]
	verdict, jobID := m.enqueueBoth(t, Delivery{ID: id, PayloadSHA256: d.Payload, EnvID: d.EnvID, Type: d.Type, Seq: d.Seq, Source: d.Source, ReceivedAt: m.now})
	if verdict != VerdictReplay || jobID != 0 {
		t.Fatalf("redelivery of %s = %s/%d, want replay", id, verdict, jobID)
	}
}

// AcquireJob on an idle worker.
func (m *previewdMachine) AcquireJob(t *rapid.T) {
	w := m.pickWorker(t, false)
	m.acquire(t, w)
}

func (m *previewdMachine) acquire(t *rapid.T, w int) bool {
	before, err := m.store.Jobs(m.ctx)
	m.must(t, err, "list jobs")
	lease, ok, err := m.store.Acquire(m.ctx, m.now)
	m.must(t, err, "acquire")
	twin, twinOK, err := m.pruned.Acquire(m.ctx, m.now)
	m.must(t, err, "acquire (pruned twin)")
	if twinOK != ok || twin != lease {
		t.Fatalf("pruned twin leased %+v (%v), store %+v (%v)", twin, twinOK, lease, ok)
	}

	wantID := m.modelNext()
	if !ok {
		if wantID != 0 {
			t.Fatalf("acquire found nothing, model leases job %d", wantID)
		}
		return false
	}
	if lease.JobID != wantID {
		t.Fatalf("acquire leased job %d, model leases %d", lease.JobID, wantID)
	}
	target := m.jobs[wantID-1]
	if lease.EnvID != target.EnvID || lease.Type != target.Type || lease.Seq != target.Seq || lease.Epoch != m.epoch ||
		lease.Attempts != target.Attempts || lease.Source != target.Source {
		t.Fatalf("lease %+v does not match model job %+v at epoch %d", lease, target, m.epoch)
	}
	// SafetyMonotonicStep: newer than every executed job of the environment.
	for _, k := range before {
		if k.EnvID == lease.EnvID && k.ID != lease.JobID &&
			(k.Status == StatusInProgress || k.Status == StatusSuccess || k.Status == StatusFailed) && k.Seq >= lease.Seq {
			t.Fatalf("job %d (seq %d) leased after executed job %d (seq %d)", lease.JobID, lease.Seq, k.ID, k.Seq)
		}
	}
	for i := range m.jobs {
		j := &m.jobs[i]
		if j.EnvID == lease.EnvID && j.Status == StatusQueued && j.ID != wantID {
			j.Status, j.FinishedAt = StatusSkipped, m.now.UnixMilli()
		}
	}
	m.jobs[wantID-1].Status = StatusInProgress
	m.jobs[wantID-1].LeaseEpoch = m.epoch

	m.workers[w] = worker{lease: lease, next: stepExecuteTeardown}
	if lease.Type == JobDeploy {
		// AuthorizeDeploy: the MVP has no approval gate, every PR is
		// trusted. A classified deploy is never requeued (failDeploy).
		m.mustBoth(t, "classify deploy", func(s *Store) error { return s.Classify(m.ctx, lease, Classification{Trust: TrustTrusted}) })
		m.jobs[wantID-1].Trust = TrustTrusted
		m.workers[w].next = stepExecuteDeploy
	}
	return true
}

// modelNext is AcquireJob's choice: among environments with no IN_PROGRESS
// job whose newest QUEUED job is due, the lowest such job ID; 0 if none.
func (m *previewdMachine) modelNext() int64 {
	var best int64
	for _, e := range spbtEnvs {
		var newest *Job
		locked := false
		for i := range m.jobs {
			j := &m.jobs[i]
			if j.EnvID != e {
				continue
			}
			if j.Status == StatusInProgress {
				locked = true
			}
			if j.Status == StatusQueued && (newest == nil || j.Seq > newest.Seq) {
				newest = j
			}
		}
		if locked || newest == nil || newest.NotBefore > m.now.UnixMilli() {
			continue
		}
		if best == 0 || newest.ID < best {
			best = newest.ID
		}
	}
	return best
}

// Step advances a busy worker by one model step; the Docker call may fail.
func (m *previewdMachine) Step(t *rapid.T) {
	w := m.pickWorker(t, true)
	m.step(t, w, rapid.Bool().Draw(t, "docker ok"))
}

func (m *previewdMachine) step(t *rapid.T, w int, ok bool) {
	wk := &m.workers[w]
	l := wk.lease
	switch wk.next {
	case stepExecuteDeploy:
		if !ok {
			m.failDeploy(t, w)
			return
		}
		// Destroy the previous version, create the network, stage secrets.
		m.host[l.EnvID] = fakeEnv{NetworkBound: true, SecretsMounted: true, JobID: l.JobID}
		wk.next = stepStartContainer
	case stepStartContainer:
		if !ok {
			m.failDeploy(t, w)
			return
		}
		h := m.host[l.EnvID]
		h.Running = true
		m.host[l.EnvID] = h
		wk.next = stepPublishRoute
	case stepPublishRoute:
		if !ok {
			m.failDeploy(t, w)
			return
		}
		h := m.host[l.EnvID]
		h.Routed = true
		m.host[l.EnvID] = h
		wk.next = stepCommitDeploy
	case stepCommitDeploy:
		m.mustBoth(t, "commit deploy", func(s *Store) error { return s.Finish(m.ctx, l, StatusSuccess, m.now) })
		m.jobs[l.JobID-1].Status, m.jobs[l.JobID-1].FinishedAt = StatusSuccess, m.now.UnixMilli()
		*wk = worker{}
	case stepExecuteTeardown:
		if !ok {
			// Transient failure: back to QUEUED with backoff, never FAILED.
			for _, s := range m.stores() {
				if err := s.Finish(m.ctx, l, StatusFailed, m.now); !errors.Is(err, ErrTeardownCannotFail) {
					t.Fatalf("finishing a teardown as FAILED: got %v, want ErrTeardownCannotFail", err)
				}
			}
			j := &m.jobs[l.JobID-1]
			notBefore := m.now.Add(backoff(j.Attempts))
			m.mustBoth(t, "requeue teardown", func(s *Store) error { return s.Requeue(m.ctx, l, notBefore) })
			j.Status, j.Attempts, j.NotBefore = StatusQueued, j.Attempts+1, notBefore.UnixMilli()
			*wk = worker{}
			return
		}
		delete(m.host, l.EnvID)
		wk.next = stepCommitTeardown
	case stepCommitTeardown:
		m.mustBoth(t, "commit teardown", func(s *Store) error { return s.Finish(m.ctx, l, StatusSuccess, m.now) })
		m.jobs[l.JobID-1].Status, m.jobs[l.JobID-1].FinishedAt = StatusSuccess, m.now.UnixMilli()
		*wk = worker{}
	default:
		t.Fatalf("worker %d has no step", w)
	}
}

func backoff(attempts int64) time.Duration {
	return min(time.Second<<min(attempts, 6), time.Minute)
}

// failDeploy rolls the environment back to absent and fails the job.
func (m *previewdMachine) failDeploy(t *rapid.T, w int) {
	l := m.workers[w].lease
	for _, s := range m.stores() {
		if err := s.Requeue(m.ctx, l, m.now); !errors.Is(err, ErrDeployCannotRetry) {
			t.Fatalf("requeueing a deploy: got %v, want ErrDeployCannotRetry", err)
		}
	}
	delete(m.host, l.EnvID)
	m.mustBoth(t, "fail deploy", func(s *Store) error { return s.Finish(m.ctx, l, StatusFailed, m.now) })
	m.jobs[l.JobID-1].Status, m.jobs[l.JobID-1].FinishedAt = StatusFailed, m.now.UnixMilli()
	m.workers[w] = worker{}
}

// SimulateCrash kills the daemon (leases and memory lost) or reboots the
// host (staged secrets lost too), then restarts: new connection pool,
// StartupSweep, destroy what it lists.
func (m *previewdMachine) SimulateCrash(t *rapid.T) {
	reboot := rapid.Bool().Draw(t, "host reboot")
	m.must(t, m.store.Close(), "close store")
	m.must(t, m.pruned.Close(), "close pruned twin")
	m.store, m.pruned = nil, nil
	for w := range m.workers {
		if m.workers[w].next != stepIdle {
			m.stale = append(m.stale, m.workers[w].lease)
		}
		m.workers[w] = worker{}
	}
	if reboot {
		for e, h := range m.host {
			h.SecretsMounted = false
			m.host[e] = h
		}
	}
	m.boot(t)
}

// StaleWorker: a lease from before the crash tries to commit. It must be
// refused without changing anything.
func (m *previewdMachine) StaleWorker(t *rapid.T) {
	if len(m.stale) == 0 {
		t.Skip("no stale lease")
	}
	i := rapid.IntRange(0, len(m.stale)-1).Draw(t, "stale lease")
	l := m.stale[i]
	m.stale = slices.Delete(m.stale, i, i+1)
	requeue := l.Type == JobTeardown && rapid.Bool().Draw(t, "requeue")
	for _, s := range m.stores() {
		var err error
		if requeue {
			err = s.Requeue(m.ctx, l, m.now)
		} else {
			err = s.Finish(m.ctx, l, StatusSuccess, m.now)
		}
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale lease %+v: got %v, want ErrLeaseLost", l, err)
		}
	}
}

// AdvanceClock lets backoffs expire, or (long) jobs and deliveries age
// past Prune's horizons.
func (m *previewdMachine) AdvanceClock(t *rapid.T) {
	limit := int64(70_000)
	if rapid.Bool().Draw(t, "long") {
		limit = int64(20 * time.Minute / time.Millisecond)
	}
	m.now = m.now.Add(time.Duration(rapid.Int64Range(0, limit).Draw(t, "ms")) * time.Millisecond)
}

// Prune runs on the pruned twin only, with a drawn retention and batch and
// the builders of what exists on the host, then checks the verdict of every
// possible next delivery against the store's (V1-I6).
func (m *previewdMachine) Prune(t *rapid.T) {
	m.prune(t, time.Duration(rapid.Int64Range(0, 180_000).Draw(t, "retention ms"))*time.Millisecond)
}

func (m *previewdMachine) prune(t *rapid.T, retention time.Duration) {
	req := PruneRequest{
		Now:            m.now,
		Retention:      retention,
		DeliveryMaxAge: spbtDeliveryMaxAge,
		Batch:          rapid.IntRange(1, 3).Draw(t, "batch"),
	}
	for _, e := range slices.Sorted(maps.Keys(m.host)) {
		if h := m.host[e]; h.exists() && h.JobID != 0 {
			req.Builders = append(req.Builders, h.JobID)
		}
	}
	stats, err := m.pruned.Prune(m.ctx, req)
	m.must(t, err, "prune")
	if stats.MaxBatch > int64(req.Batch) {
		t.Fatalf("prune deleted %d rows in one transaction, batch %d", stats.MaxBatch, req.Batch)
	}
	m.pruneStats.Jobs += stats.Jobs
	m.pruneStats.Deliveries += stats.Deliveries
	m.checkNextVerdicts(t)
}

// probe is the verdict s would give d, in a transaction rolled back.
func (m *previewdMachine) probe(t *rapid.T, s *Store, d Delivery) (Verdict, int64) {
	tx, err := s.db.BeginTx(m.ctx, nil)
	m.must(t, err, "probe: begin")
	v, id, err := enqueueTx(m.ctx, tx, d)
	m.must(t, err, "probe")
	m.must(t, tx.Rollback(), "probe: rollback")
	return v, id
}

// checkNextVerdicts asks both stores for the verdict of every possible next
// delivery: a fresh one at each seq of each environment (the stale rule),
// and a redelivery of each delivery ever recorded (replay protection).
func (m *previewdMachine) checkNextVerdicts(t *rapid.T) {
	for _, e := range spbtEnvs {
		for seq := int64(1); seq <= spbtMaxSeq+1; seq++ {
			d := testDelivery("probe", e, JobDeploy, seq)
			d.ReceivedAt = m.now
			v, id := m.probe(t, m.store, d)
			pv, pid := m.probe(t, m.pruned, d)
			m.twinVerdict(t, d, false, v, id, pv, pid)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(m.deliveries)) {
		r := m.deliveries[id]
		d := Delivery{ID: id, PayloadSHA256: r.Payload, EnvID: r.EnvID, Type: r.Type, Seq: r.Seq, Source: r.Source, ReceivedAt: m.now}
		forgotten := m.forgotten(t, d.ID, d.PayloadSHA256)
		if forgotten {
			m.forgottenProbes++
		}
		v, vid := m.probe(t, m.store, d)
		if v != VerdictReplay {
			t.Fatalf("redelivery of %s = %s in the store, want replay", id, v)
		}
		pv, pid := m.probe(t, m.pruned, d)
		m.twinVerdict(t, d, forgotten, v, vid, pv, pid)
	}
}

func (m *previewdMachine) pickWorker(t *rapid.T, busy bool) int {
	var candidates []int
	for w := range m.workers {
		if (m.workers[w].next != stepIdle) == busy {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		t.Skip("no such worker")
	}
	return rapid.SampledFrom(candidates).Draw(t, "worker")
}

// Check runs after every command.
func (m *previewdMachine) Check(t *rapid.T) {
	jobs, err := m.store.Jobs(m.ctx)
	m.must(t, err, "list jobs")

	// 1. State equivalence: every row, every field.
	if !slices.Equal(jobs, m.jobs) {
		t.Fatalf("jobs table diverged from the model\n db:    %+v\n model: %+v", jobs, m.jobs)
	}
	m.checkDeliveries(t)
	m.checkPrunedTwin(t, jobs)

	// 2. Lock integrity, asked of SQLite itself.
	var maxInProgress int
	m.must(t, m.store.db.QueryRowContext(m.ctx,
		`SELECT coalesce(max(n), 0) FROM (SELECT count(*) AS n FROM jobs WHERE status = 'IN_PROGRESS' GROUP BY preview_id)`).Scan(&maxInProgress),
		"lock integrity query")
	if maxInProgress > 1 {
		t.Fatalf("%d IN_PROGRESS jobs for one environment", maxInProgress)
	}

	executed := func(s JobStatus) bool { return s == StatusInProgress || s == StatusSuccess || s == StatusFailed }
	for _, j := range jobs {
		for _, k := range jobs {
			// 3. Monotonicity: once a newer intent executed, no older one
			// is pending or running.
			if j.EnvID == k.EnvID && j.Seq < k.Seq && executed(k.Status) &&
				(j.Status == StatusQueued || j.Status == StatusInProgress) {
				t.Fatalf("job %d (seq %d) is %s while newer job %d (seq %d) is %s", j.ID, j.Seq, j.Status, k.ID, k.Seq, k.Status)
			}
			if j.ID != k.ID && j.EnvID == k.EnvID && j.Seq == k.Seq {
				t.Fatalf("jobs %d and %d share seq %d", j.ID, k.ID, j.Seq)
			}
		}
		if j.Type == JobTeardown && j.Status == StatusFailed {
			t.Fatalf("teardown %d is FAILED", j.ID)
		}
	}

	for e, h := range m.host {
		if !h.exists() {
			continue
		}
		// A route document never points at a container that is not running.
		if h.Routed && !h.Running {
			t.Fatalf("%s has a route document but no running container", e)
		}
		// 4. No orphaned resources (route documents included): the builder
		// is IN_PROGRESS or SUCCESS and no newer teardown succeeded.
		if h.JobID == 0 || h.JobID > int64(len(jobs)) {
			t.Fatalf("%s exists on the host but no job built it", e)
		}
		b := jobs[h.JobID-1]
		if b.EnvID != e || b.Type != JobDeploy || (b.Status != StatusInProgress && b.Status != StatusSuccess) {
			t.Fatalf("%s exists on the host, builder %+v is not a live deploy", e, b)
		}
		for _, k := range jobs {
			if k.EnvID != e {
				continue
			}
			if k.Type == JobTeardown && k.Status == StatusSuccess && k.Seq > b.Seq {
				t.Fatalf("%s exists after teardown %d succeeded", e, k.ID)
			}
			// A running environment is never older than a completed intent.
			if h.Running && (k.Status == StatusSuccess || k.Status == StatusFailed) && k.Seq > b.Seq {
				t.Fatalf("%s runs job %d (seq %d) behind completed job %d (seq %d)", e, b.ID, b.Seq, k.ID, k.Seq)
			}
		}
	}

	// 5. Leases: each busy worker holds a distinct IN_PROGRESS job of the
	// current epoch.
	held := map[int64]bool{}
	for w, wk := range m.workers {
		if wk.next == stepIdle {
			continue
		}
		j := jobs[wk.lease.JobID-1]
		if j.Status != StatusInProgress || j.LeaseEpoch != m.epoch || held[j.ID] {
			t.Fatalf("worker %d lease %+v does not match job %+v", w, wk.lease, j)
		}
		held[j.ID] = true
	}
}

// checkPrunedTwin: the pruned twin holds a subset of the store's rows,
// unchanged, and every row V1-I6 protects: each non-terminal job, the
// latest job of each environment, the builder of each environment on the
// host and every job newer than it (the sweep's Keep reads them). MaxSeq
// of each environment is the same in both.
func (m *previewdMachine) checkPrunedTwin(t *rapid.T, jobs []Job) {
	twin, err := m.pruned.Jobs(m.ctx)
	m.must(t, err, "list jobs (pruned twin)")
	kept := map[int64]bool{}
	for _, j := range twin {
		if j.ID < 1 || j.ID > int64(len(jobs)) || jobs[j.ID-1] != j {
			t.Fatalf("pruned twin holds job %+v, the store does not", j)
		}
		kept[j.ID] = true
	}
	latest := m.modelLatest()
	for _, j := range jobs {
		terminal := j.Status == StatusSuccess || j.Status == StatusFailed || j.Status == StatusSkipped
		h := m.host[j.EnvID]
		readBySweep := h.exists() && h.JobID != 0 && h.JobID <= int64(len(jobs)) && j.Seq >= jobs[h.JobID-1].Seq
		if !kept[j.ID] && (!terminal || latest[j.EnvID] == j.ID || readBySweep) {
			t.Fatalf("V1-I6: Prune removed job %+v (latest of its environment %d, host builder %d)", j, latest[j.EnvID], h.JobID)
		}
	}
	for _, e := range spbtEnvs {
		var want, got int64
		m.must(t, m.store.db.QueryRowContext(m.ctx, `SELECT coalesce(max(seq), 0) FROM jobs WHERE preview_id = ?`, e).Scan(&want), "max seq")
		m.must(t, m.pruned.db.QueryRowContext(m.ctx, `
			SELECT max(coalesce((SELECT max(seq) FROM jobs WHERE preview_id = ?1), 0),
				coalesce((SELECT seq FROM watermarks WHERE preview_id = ?1), 0))`, e).Scan(&got), "max seq (pruned twin)")
		if got != want {
			t.Fatalf("V1-I6: MaxSeq(%s) = %d in the pruned twin, %d in the store", e, got, want)
		}
	}

	rows, err := m.pruned.db.QueryContext(m.ctx, `SELECT delivery_id, preview_id, seq, verdict, payload_sha256 FROM deliveries`)
	m.must(t, err, "list deliveries (pruned twin)")
	for rows.Next() {
		var id, env, verdict, payload string
		var seq int64
		m.must(t, rows.Scan(&id, &env, &seq, &verdict, &payload), "scan delivery (pruned twin)")
		d, ok := m.deliveries[id]
		want := d.Verdict
		if m.rerecorded[id] {
			want = VerdictStale
		}
		if !ok || env != d.EnvID || seq != d.Seq || payload != d.Payload || Verdict(verdict) != want {
			t.Fatalf("pruned twin holds delivery %s (%s, %d, %s), model %+v", id, env, seq, verdict, d)
		}
	}
	m.must(t, rows.Err(), "list deliveries (pruned twin)")
	m.must(t, rows.Close(), "close deliveries (pruned twin)")
}

func (m *previewdMachine) checkDeliveries(t *rapid.T) {
	rows, err := m.store.db.QueryContext(m.ctx, `SELECT delivery_id, preview_id, seq, verdict, payload_sha256 FROM deliveries ORDER BY delivery_id`)
	m.must(t, err, "list deliveries")
	got := map[string]modelDelivery{}
	for rows.Next() {
		var id, env, verdict, payload string
		var seq int64
		m.must(t, rows.Scan(&id, &env, &seq, &verdict, &payload), "scan delivery")
		got[id] = modelDelivery{EnvID: env, Seq: seq, Verdict: Verdict(verdict), Payload: payload}
	}
	m.must(t, rows.Err(), "list deliveries")
	m.must(t, rows.Close(), "close deliveries")
	if len(got) != len(m.deliveries) {
		t.Fatalf("%d deliveries recorded, model has %d", len(got), len(m.deliveries))
	}
	for id, d := range m.deliveries {
		g, ok := got[id]
		if !ok || g.EnvID != d.EnvID || g.Seq != d.Seq || g.Verdict != d.Verdict || g.Payload != d.Payload {
			t.Fatalf("delivery %s = %+v, model %+v", id, g, d)
		}
	}
}

// drain stops the webhook stream, crashes and faults, and runs the workers
// until nothing is left: LivenessEventualCompletion and
// LivenessEventualConsistency.
func (m *previewdMachine) drain(t *rapid.T) {
	m.stale = nil
	for range 10 * (len(m.jobs) + spbtWorkers + 1) {
		m.now = m.now.Add(time.Hour) // every backoff is due
		progressed := false
		for w := range m.workers {
			if m.workers[w].next != stepIdle {
				m.step(t, w, true)
				progressed = true
			} else if m.acquire(t, w) {
				progressed = true
			}
			m.Check(t)
		}
		if !progressed {
			break
		}
	}

	// The drain aged everything past the horizons: a last Prune forgets all
	// it may, and the verdicts are compared once more.
	m.prune(t, 0)

	latest := m.modelLatest()
	for _, j := range m.jobs {
		if j.Status == StatusQueued || j.Status == StatusInProgress {
			t.Fatalf("job %+v never completed", j)
		}
	}
	for _, e := range spbtEnvs {
		h := m.host[e]
		id, ok := latest[e]
		if ok && m.jobs[id-1].Type == JobDeploy && m.jobs[id-1].Status == StatusSuccess {
			if !h.intact() || h.JobID != id {
				t.Fatalf("%s: latest intent is deploy %d, host has %+v", e, id, h)
			}
		} else if h.exists() {
			t.Fatalf("%s: latest intent is not a successful deploy, host still has %+v", e, h)
		}
	}
}

// weightedActions is the rapid.StateMachine action set, with the reconciler
// commands listed more than once: rapid picks actions uniformly, and deep
// paths (a deploy that completes, then a newer one leased, then a crash) need
// several steps in a row.
func weightedActions(m *previewdMachine) map[string]func(*rapid.T) {
	actions := rapid.StateMachineActions(m)
	for i := range 2 {
		actions[fmt.Sprintf("Step#%d", i+2)] = m.Step
	}
	actions["AcquireJob#2"] = m.AcquireJob
	actions["Step#4"] = m.Step
	actions["ReceiveWebhook#2"] = m.ReceiveWebhook
	actions["Prune#2"] = m.Prune
	return actions
}

func TestJobStore_StateMachine(t *testing.T) {
	base := t.TempDir()
	var runs, prunedJobs, prunedDeliveries, rerecorded int
	rapid.Check(t, func(t *rapid.T) {
		m := newPreviewdMachine(t, base)
		defer m.cleanup(t)
		t.Repeat(weightedActions(m))
		m.drain(t)
		runs++
		prunedJobs += int(m.pruneStats.Jobs)
		prunedDeliveries += int(m.pruneStats.Deliveries)
		rerecorded += len(m.rerecorded) + m.forgottenProbes
	})
	// F2 is not vacuous: over the default 100 runs, Prune deleted jobs and
	// deliveries, and redeliveries of forgotten deliveries were judged.
	if runs >= 100 && (prunedJobs == 0 || prunedDeliveries == 0 || rerecorded == 0) {
		t.Fatalf("over %d runs Prune deleted %d jobs and %d deliveries, %d forgotten deliveries came back: the twin compared nothing",
			runs, prunedJobs, prunedDeliveries, rerecorded)
	}
	t.Logf("%d runs: Prune deleted %d jobs and %d deliveries; %d forgotten deliveries redelivered", runs, prunedJobs, prunedDeliveries, rerecorded)
}
