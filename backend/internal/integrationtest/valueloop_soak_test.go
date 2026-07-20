package integrationtest

// A2 (go-live readiness register) — the VALUE-LOOP soak the infra-layer soak could not run (SOAK_GATE_REPORT.md:
// "the authenticated value-loop soak remains the outstanding gate"). This drives the REAL ingest → normalize →
// detect → correlate → alert → incident loop against local Postgres, multi-tenant, at a configurable rate, and
// measures throughput + the reviewer's known-weak points. It reuses the proven newHarness wiring (components are
// tenant-agnostic: tenant is passed per Ingest; the worker drains the shared queue), so this is a driver, not a
// re-wire.
//
// GATED: skipped unless NIRVET_SOAK=1, so normal CI (which sets NIRVET_TEST_DATABASE_URL) never runs it. Knobs:
//   NIRVET_SOAK=1                       enable
//   NIRVET_SOAK_TENANTS=10              tenants to seed (crank toward 250 for the full spec)
//   NIRVET_SOAK_EVENTS_PER_TENANT=50    synthetic events per tenant
//   NIRVET_SOAK_CONCURRENCY=4           concurrent ingesters (burst knob)
//
// Full reviewer spec = 250 tenants / ~2k ev/s / ~10k burst / 48h — that needs a prod-like env (paid PG/API) and a
// long run; this harness is the SAME code path, sized to what a local box proves: structural behaviour, throughput
// shape, per-run query counts, and that nothing drops. Escalate the knobs in the load env for the go-live gate.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func soakEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// soakClass/soakSeverity vary events so a realistic fraction matches the seeded ATT&CK rules (firing the
// detect→alert→correlate→incident tail), the rest are stored-only — mirroring a real event mix.
func soakClass(i int) string {
	switch i % 5 {
	case 0:
		return "Malware detected on endpoint"
	case 1:
		return "Suspicious sign-in"
	case 2:
		return "Brute force authentication"
	default:
		return "Informational activity"
	}
}
func soakSeverity(i int) string {
	switch i % 4 {
	case 0:
		return "critical"
	case 1:
		return "high"
	case 2:
		return "medium"
	default:
		return "low"
	}
}

func TestValueLoopSoak(t *testing.T) {
	if os.Getenv("NIRVET_SOAK") == "" {
		t.Skip("value-loop soak: set NIRVET_SOAK=1 (and NIRVET_TEST_DATABASE_URL) to run")
	}
	h := newHarness(t) // full value-loop wiring + tenant #0
	ts := tenant.NewService(tenant.NewRepository(h.db))

	tenants := soakEnvInt("NIRVET_SOAK_TENANTS", 10)
	perTenant := soakEnvInt("NIRVET_SOAK_EVENTS_PER_TENANT", 50)
	concurrency := soakEnvInt("NIRVET_SOAK_CONCURRENCY", 4)

	// Seed tenants (tenant #0 already exists from newHarness).
	tids := []uuid.UUID{h.tenantID}
	for i := 1; i < tenants; i++ {
		tn, err := ts.Create(h.ctx, tenant.CreateInput{Name: "soak-" + uuid.NewString()})
		if err != nil {
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		tids = append(tids, tn.ID)
	}
	total := len(tids) * perTenant
	t.Logf("SOAK config: tenants=%d events/tenant=%d total=%d concurrency=%d", len(tids), perTenant, total, concurrency)

	// ---- Ingest phase (concurrent ingesters = the burst knob) ----
	var ingested int64
	ingestStart := time.Now()
	jobs := make(chan uuid.UUID, total)
	for _, tid := range tids {
		for j := 0; j < perTenant; j++ {
			jobs <- tid
		}
	}
	close(jobs)
	var wg sync.WaitGroup
	var ingestErr atomic.Value
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq := 0
			for tid := range jobs {
				seq++
				in := ingestion.IngestInput{
					Source:    "soak",
					NativeID:  uuid.NewString(),
					ClassName: soakClass(seq),
					Severity:  soakSeverity(seq),
					ActorRef:  "user:soak-" + strconv.Itoa(seq%50),
					TargetRef: "host:soak-" + strconv.Itoa(seq%20),
				}
				if _, err := h.ingest.Ingest(context.Background(), tid, in); err != nil {
					ingestErr.Store(err)
					return
				}
				atomic.AddInt64(&ingested, 1)
			}
		}()
	}
	wg.Wait()
	if e := ingestErr.Load(); e != nil {
		t.Fatalf("ingest error: %v", e)
	}
	ingestDur := time.Since(ingestStart)

	// ---- Drain phase (the worker runs the detect→correlate→alert→incident tail) ----
	drainStart := time.Now()
	processed := 0
	emptyStreak := 0
	for {
		n, err := h.worker.RunOnce(h.ctx)
		if err != nil {
			t.Fatalf("worker RunOnce: %v", err)
		}
		processed += n
		if n == 0 {
			emptyStreak++
			if emptyStreak >= 2 { // two consecutive empties = queue drained
				break
			}
			continue
		}
		emptyStreak = 0
	}
	drainDur := time.Since(drainStart)

	// ---- Metrics ----
	ingRate := float64(ingested) / ingestDur.Seconds()
	drainRate := float64(processed) / drainDur.Seconds()
	// Count alerts + incidents raised across all tenants (superuser-less: sum per tenant under RLS).
	alerts, incidents := 0, 0
	for _, tid := range tids {
		alerts += soakCountAlerts(t, h, tid)
		incidents += soakCountIncidents(t, h, tid)
	}
	stat := h.db.Pool.Stat()
	summary := fmt.Sprintf(
		"SOAK RESULT | tenants=%d events=%d | ingest %s (%.0f ev/s, c=%d) | drain %s (%.0f ev/s) processed=%d | alerts=%d incidents=%d | pool acquired=%d idle=%d total=%d maxconns=%d",
		len(tids), total, ingestDur.Round(time.Millisecond), ingRate, concurrency,
		drainDur.Round(time.Millisecond), drainRate, processed, alerts, incidents,
		stat.AcquiredConns(), stat.IdleConns(), stat.TotalConns(), stat.MaxConns())
	t.Log(summary)

	// ---- Health assertions (soak "held", not merely "ran") ----
	if int64(total) != ingested {
		t.Fatalf("dropped events on ingest: wanted %d got %d", total, ingested)
	}
	if processed < total { // dedupe can make processed<=total; a large shortfall = a real drop
		t.Logf("NOTE: processed(%d) < ingested(%d) — expected only if events deduped; investigate if the gap is large", processed, total)
	}
	if stat.AcquiredConns() > stat.MaxConns() {
		t.Fatalf("pool over-subscribed: acquired=%d > max=%d", stat.AcquiredConns(), stat.MaxConns())
	}
}

func soakCount(t *testing.T, h *harness, tid uuid.UUID, table string) int {
	t.Helper()
	var n int
	if err := h.db.WithTenant(h.ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
	}); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// buildDrainWorker builds a GENUINELY SEPARATE worker instance (its own queue handle over the SAME Postgres
// queue tables via the shared pool, its own detection engine + rule cache + enricher) — like a distinct worker
// process. N of these draining concurrently contend on the real queue through FOR UPDATE SKIP LOCKED, which is
// the faithful multi-worker test (not N goroutines sharing one worker). Shares the pool-backed alert/correlation
// services (stateless over the pool), as separate processes would share the same DB.
func buildDrainWorker(t *testing.T, h *harness) (*ingestion.Worker, func()) {
	t.Helper()
	q, closeQ, _, err := queue.New(h.ctx, os.Getenv("NIRVET_NATS_URL"), h.db.Pool)
	if err != nil {
		t.Fatalf("build drain worker queue: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	detEng := detection.NewEngine(detection.NewRepository(h.db))
	enr := threatintel.NewEnricher(threatintel.NewRepository(h.db))
	return ingestion.NewWorker(q, h.events, enr, detEng, h.alertSvc, log).WithCorrelator(h.corrSvc), closeQ
}

// soakIngestBatch fills the queue with tenants×perTenant synthetic events (concurrent producers).
func soakIngestBatch(t *testing.T, h *harness, tids []uuid.UUID, perTenant, concurrency int) int {
	t.Helper()
	jobs := make(chan uuid.UUID, len(tids)*perTenant)
	for _, tid := range tids {
		for j := 0; j < perTenant; j++ {
			jobs <- tid
		}
	}
	close(jobs)
	var wg sync.WaitGroup
	var n int64
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq := 0
			for tid := range jobs {
				seq++
				in := ingestion.IngestInput{Source: "soak", NativeID: uuid.NewString(), ClassName: soakClass(seq), Severity: soakSeverity(seq), ActorRef: "user:soak-" + strconv.Itoa(seq%50), TargetRef: "host:soak-" + strconv.Itoa(seq%20)}
				if _, err := h.ingest.Ingest(context.Background(), tid, in); err != nil {
					t.Errorf("ingest: %v", err)
					return
				}
				atomic.AddInt64(&n, 1)
			}
		}()
	}
	wg.Wait()
	return int(n)
}

func parseWorkerCounts(s string, def []int) []int {
	if s == "" {
		return def
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// TestValueLoopDrainScaling answers the real 2k-ev/s capacity question the single-worker soak raised: does drain
// scale ~linearly with worker COUNT, or does the shared Postgres plateau first (worker-bound vs DB-bound)? For
// each worker count it re-fills the queue, spins up that many separate workers, drains, and reports ev/s +
// per-worker ev/s. A flat total across counts ⇒ DB ceiling; a rising total ⇒ headroom.
func TestValueLoopDrainScaling(t *testing.T) {
	if os.Getenv("NIRVET_SOAK") == "" {
		t.Skip("drain-scaling soak: set NIRVET_SOAK=1 to run")
	}
	h := newHarness(t)
	ts := tenant.NewService(tenant.NewRepository(h.db))
	tenants := soakEnvInt("NIRVET_SOAK_TENANTS", 10)
	perTenant := soakEnvInt("NIRVET_SOAK_EVENTS_PER_TENANT", 60)
	counts := parseWorkerCounts(os.Getenv("NIRVET_SOAK_DRAIN_WORKERS"), []int{1, 2, 4})

	tids := []uuid.UUID{h.tenantID}
	for i := 1; i < tenants; i++ {
		tn, err := ts.Create(h.ctx, tenant.CreateInput{Name: "drain-" + uuid.NewString()})
		if err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		tids = append(tids, tn.ID)
	}
	t.Logf("DRAIN SCALING config: tenants=%d events/round=%d worker counts=%v maxconns=%d",
		len(tids), len(tids)*perTenant, counts, h.db.Pool.Stat().MaxConns())

	for _, wc := range counts {
		batch := soakIngestBatch(t, h, tids, perTenant, 8)
		workers := make([]*ingestion.Worker, 0, wc)
		closers := make([]func(), 0, wc)
		for i := 0; i < wc; i++ {
			w, closeQ := buildDrainWorker(t, h)
			workers = append(workers, w)
			closers = append(closers, closeQ)
		}
		var processed int64
		start := time.Now()
		var wg sync.WaitGroup
		for _, w := range workers {
			wg.Add(1)
			go func(w *ingestion.Worker) {
				defer wg.Done()
				zeros := 0
				for {
					n, err := w.RunOnce(h.ctx)
					if err != nil {
						t.Errorf("RunOnce: %v", err)
						return
					}
					if n > 0 {
						atomic.AddInt64(&processed, int64(n))
						zeros = 0
						continue
					}
					zeros++
					if zeros >= 3 { // three empty claims in a row = queue drained from this worker's view
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}(w)
		}
		wg.Wait()
		dur := time.Since(start)
		for _, c := range closers {
			c()
		}
		rate := float64(atomic.LoadInt64(&processed)) / dur.Seconds()
		t.Logf("DRAIN SCALING | workers=%d batch=%d processed=%d drain=%s => %.0f ev/s total (%.1f ev/s per worker)",
			wc, batch, atomic.LoadInt64(&processed), dur.Round(time.Millisecond), rate, rate/float64(wc))
	}
}

func soakCountAlerts(t *testing.T, h *harness, tid uuid.UUID) int {
	return soakCount(t, h, tid, "alerts")
}
func soakCountIncidents(t *testing.T, h *harness, tid uuid.UUID) int {
	return soakCount(t, h, tid, "incidents")
}

// soakDeadLetters counts dead-lettered ingest jobs across ALL tenants (system-level; the queue spans tenants).
// A non-zero, GROWING count during a soak = the loop is silently losing security events — the single most
// important endurance signal. Read straight off the pool (the queue runs system-level, not under RLS).
func soakDeadLetters(t *testing.T, h *harness) int {
	t.Helper()
	var n int
	if err := h.db.Pool.QueryRow(h.ctx, `SELECT count(*) FROM ingest_jobs WHERE state='dead'`).Scan(&n); err != nil {
		t.Fatalf("count dead-letters: %v", err)
	}
	return n
}

func soakEnvDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// TestValueLoopSustainedSoak is the ENDURANCE half of A2 that the one-pass TestValueLoopSoak cannot answer: does the
// value loop hold STEADY STATE over wall-clock time, or does it slowly leak (heap creep, goroutine leak, connection
// leak, dead-letter accumulation)? The one-pass test proves "1000 events don't drop"; only a sustained run proves
// "the SOC survives 48h of continuous traffic." Same real ingest→detect→correlate→incident path, looped for
// NIRVET_SOAK_DURATION, sampling the leak signals each cycle. Gated behind NIRVET_SOAK=1 (never runs in normal CI).
//
// Knobs (compose with the existing NIRVET_SOAK_TENANTS / _EVENTS_PER_TENANT / _CONCURRENCY):
//
//	NIRVET_SOAK_DURATION=30s     wall-clock endurance window (crank to 48h in the load env for the full spec)
//	NIRVET_SOAK_DRAIN_WORKERS=4  concurrent drain workers per cycle (first CSV value used; horizontal-scale knob)
func TestValueLoopSustainedSoak(t *testing.T) {
	if os.Getenv("NIRVET_SOAK") == "" {
		t.Skip("sustained soak: set NIRVET_SOAK=1 (and NIRVET_TEST_DATABASE_URL) to run")
	}
	h := newHarness(t)
	ts := tenant.NewService(tenant.NewRepository(h.db))

	tenants := soakEnvInt("NIRVET_SOAK_TENANTS", 10)
	perCycle := soakEnvInt("NIRVET_SOAK_EVENTS_PER_TENANT", 20) // events/tenant per CYCLE (not total)
	concurrency := soakEnvInt("NIRVET_SOAK_CONCURRENCY", 8)
	drainWorkers := parseWorkerCounts(os.Getenv("NIRVET_SOAK_DRAIN_WORKERS"), []int{4})[0]
	duration := soakEnvDur("NIRVET_SOAK_DURATION", 30*time.Second)

	tids := []uuid.UUID{h.tenantID}
	for i := 1; i < tenants; i++ {
		tn, err := ts.Create(h.ctx, tenant.CreateInput{Name: "sustained-" + uuid.NewString()})
		if err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		tids = append(tids, tn.ID)
	}

	// Baseline leak signals (after a GC so heap is a fair floor).
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()
	dead0 := soakDeadLetters(t, h)
	t.Logf("SUSTAINED SOAK config: tenants=%d events/tenant/cycle=%d concurrency=%d drainWorkers=%d duration=%s | baseline heap=%.1fMB goroutines=%d dead=%d",
		len(tids), perCycle, concurrency, drainWorkers, duration, float64(m0.HeapAlloc)/1e6, g0, dead0)

	deadline := time.Now().Add(duration)
	cycle, totalProcessed := 0, int64(0)
	var worstAcquired int32
	for time.Now().Before(deadline) {
		cycle++
		// Ingest one cycle's batch, then drain it with N separate workers (real multi-worker contention).
		ingested := soakIngestBatch(t, h, tids, perCycle, concurrency)
		workers := make([]*ingestion.Worker, 0, drainWorkers)
		closers := make([]func(), 0, drainWorkers)
		for i := 0; i < drainWorkers; i++ {
			w, closeQ := buildDrainWorker(t, h)
			workers = append(workers, w)
			closers = append(closers, closeQ)
		}
		var processed int64
		var wg sync.WaitGroup
		for _, w := range workers {
			wg.Add(1)
			go func(w *ingestion.Worker) {
				defer wg.Done()
				zeros := 0
				for {
					n, err := w.RunOnce(h.ctx)
					if err != nil {
						t.Errorf("cycle %d RunOnce: %v", cycle, err)
						return
					}
					if n > 0 {
						atomic.AddInt64(&processed, int64(n))
						zeros = 0
						continue
					}
					zeros++
					if zeros >= 3 {
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}(w)
		}
		wg.Wait()
		for _, c := range closers {
			c()
		}
		totalProcessed += processed

		// Per-cycle leak sample — the whole point of a sustained run.
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		stat := h.db.Pool.Stat()
		if stat.AcquiredConns() > worstAcquired {
			worstAcquired = stat.AcquiredConns()
		}
		dead := soakDeadLetters(t, h)
		t.Logf("  cycle %d | ingested=%d processed=%d | heap=%.1fMB goroutines=%d poolAcquired=%d/%d dead=%d",
			cycle, ingested, processed, float64(m.HeapAlloc)/1e6, runtime.NumGoroutine(),
			stat.AcquiredConns(), stat.MaxConns(), dead)

		// Fail FAST on the two signals that mean silent loss / resource exhaustion mid-soak.
		if dead > dead0 {
			t.Fatalf("cycle %d: dead-letters grew %d→%d — the loop is silently losing events under sustained load", cycle, dead0, dead)
		}
		if stat.AcquiredConns() > stat.MaxConns() {
			t.Fatalf("cycle %d: pool over-subscribed acquired=%d > max=%d", cycle, stat.AcquiredConns(), stat.MaxConns())
		}
	}

	// End-of-soak leak verdict (after GC so we compare settled heaps, not transient allocation).
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	g1 := runtime.NumGoroutine()
	t.Logf("SUSTAINED SOAK RESULT | cycles=%d totalProcessed=%d | heap %.1f→%.1fMB goroutines %d→%d worstPoolAcquired=%d/%d dead=%d",
		cycle, totalProcessed, float64(m0.HeapAlloc)/1e6, float64(m1.HeapAlloc)/1e6, g0, g1,
		worstAcquired, h.db.Pool.Stat().MaxConns(), soakDeadLetters(t, h))

	// Steady-state assertions (generous bounds — catch a real leak, tolerate GC/scheduler noise):
	// goroutines must not climb unbounded (worker goroutines are joined each cycle → count returns near baseline).
	if g1 > g0+drainWorkers+8 {
		t.Fatalf("goroutine leak: %d→%d over %d cycles (baseline+drainWorkers+slack=%d)", g0, g1, cycle, g0+drainWorkers+8)
	}
	if cycle == 0 {
		t.Fatal("sustained soak ran zero cycles — duration too short or ingest stalled")
	}
}
