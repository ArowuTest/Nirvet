package soar_test

// §6.11 slice C round #34 — the dedicated adversarial round for the FIRST real vendor Actioner. Drives
// the REAL Defender isolate/release Actioners (internal/connector) through the REAL two-phase supervisor
// against a stateful mock MDE + a migrated Postgres. Each test reproduces one gate invariant (C-1..C-8);
// the headline is C-3: a crash while the isolate is still Pending must NOT double-POST.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// defCreds is the CredDecryptor: returns a valid connector.Credentials JSON bundle (the mock MDE ignores
// the actual values — it only checks the bearer token it issues).
type defCreds struct{}

func (defCreds) ConnectorCreds(context.Context, uuid.UUID, string) ([]byte, error) {
	return json.Marshal(connector.Credentials{ClientID: "cid", ClientSecret: "sec", AzureTenant: "az"})
}

// mdeMock is a stateful Microsoft Defender for Endpoint API. It captures the requestorComment from OUR own
// isolate POST and echoes it as a Pending Isolate machineAction (so a resume's PreCheck sees the in-flight
// action AND its correlator — the C-3 + H-1b signals). foreignComment, if set before the run, makes the
// machine appear isolated by a FOREIGN actor (a Pending Isolate carrying a non-nirvet comment) independent
// of any POST of ours — the case that was previously unrepresentable. failIsolate makes isolate 500 (C-6).
type mdeMock struct {
	srv          *httptest.Server
	isolateCalls int32
	unisolCalls  int32
	failIsolate  bool
	mu           sync.Mutex
	ownComment   string // requestorComment captured from our isolate POST
	foreign      string // non-empty => a foreign Pending Isolate exists regardless of our POSTs
}

func newMDEMock(t *testing.T) *mdeMock {
	t.Helper()
	m := &mdeMock{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"mde-token","expires_in":3600}`))
	})
	mux.HandleFunc("/api/machines", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"id":"m-guid-1","computerDnsName":"WIN-EDR-3"}]}`))
	})
	mux.HandleFunc("/api/machineactions", func(w http.ResponseWriter, r *http.Request) {
		// Only the Isolate query has a prior action in these tests; the Unisolate query is always empty so
		// reverse's release PreCheck proceeds to POST.
		if !strings.Contains(r.URL.Query().Get("$filter"), "'Isolate'") {
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		m.mu.Lock()
		comment := m.foreign // a foreign isolation shadows our own if both somehow present
		if comment == "" {
			comment = m.ownComment
		}
		m.mu.Unlock()
		if comment == "" {
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{{"id": "prior-iso", "type": "Isolate", "status": "Pending", "requestorComment": comment}},
		})
	})
	mux.HandleFunc("/api/machines/m-guid-1/isolate", func(w http.ResponseWriter, r *http.Request) {
		if m.failIsolate {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body struct {
			Comment string `json:"Comment"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.ownComment = body.Comment
		m.mu.Unlock()
		atomic.AddInt32(&m.isolateCalls, 1)
		_, _ = w.Write([]byte(`{"id":"iso-act-1","type":"Isolate","status":"Pending"}`))
	})
	mux.HandleFunc("/api/machines/m-guid-1/unisolate", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&m.unisolCalls, 1)
		_, _ = w.Write([]byte(`{"id":"unl-act-1","type":"Unisolate","status":"Pending"}`))
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// setupDefender wires the real Defender Actioners into a real supervisor pointed at the mock MDE.
func setupDefender(t *testing.T) (*soar.Supervisor, *soar.Repository, *database.DB, uuid.UUID, *mdeMock) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := soar.NewRepository(db)
	t.Cleanup(func() { _ = repo.SetPlatformFlags(context.Background(), soar.PlatformFlags{}) })
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "def-" + uuid.NewString()})

	mock := newMDEMock(t)
	d := connector.NewDefenderActioner(mock.srv.URL+"/token", mock.srv.URL, "", mock.srv.Client())
	reg := soar.NewActionerRegistry()
	for _, a := range d.Actioners() {
		reg.Register(a)
	}
	sup := soar.NewSupervisor(repo, reg, defCreds{}, nil)
	return sup, repo, db, tn.ID, mock
}

func isoAct() soar.ActionCatalog {
	return soar.ActionCatalog{ActionKey: "isolate_endpoint", ConnectorKey: "defender", RiskClass: soar.RiskHigh, Executor: soar.ExecutorConnector, Enabled: true}
}

// C-1: destructive_enabled OFF → withheld, no isolate POST.
func TestDefenderRound_DisabledWithholds(t *testing.T) {
	sup, _, _, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, isoAct(), "host:WIN-EDR-3", nil)
	if err != nil || st != soar.StatusWithheld {
		t.Fatalf("disabled must withhold, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 0 {
		t.Fatalf("withheld must not isolate, got %d POSTs", n)
	}
}

// C-2: dry-run → simulated, no isolate POST.
func TestDefenderRound_DryRunNoEffect(t *testing.T) {
	sup, repo, _, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: false, DryRun: true, MaxClass3PerHour: 5})
	st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, isoAct(), "host:WIN-EDR-3", nil)
	if err != nil || st != soar.StatusSimulated {
		t.Fatalf("dry-run must simulate, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 0 {
		t.Fatalf("dry-run must not isolate, got %d POSTs", n)
	}
}

// C-3 (HEADLINE): a crash after the isolate POST but before Phase-C commit → resume Phase B → PreCheck
// sees the still-Pending Isolate → does NOT POST again. The machine is isolated exactly once.
func TestDefenderRound_CrashWhilePendingNoDoublePost(t *testing.T) {
	sup, repo, db, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID := uuid.New()

	// First execution: isolate POSTs once and records executed.
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("first isolate should execute, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 1 {
		t.Fatalf("first isolate should POST once, got %d", n)
	}

	// Simulate the crash: revert the row to 'executing' (Phase C never committed). MDE still shows the
	// isolate as Pending (mock state), exactly as a real async action mid-flight would.
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET status='executing' WHERE run_id=$1 AND step_index=0`, runID)
		return e
	}); err != nil {
		t.Fatalf("simulate crash: %v", err)
	}

	// Resume: PreCheck sees the Pending Isolate → NO second POST.
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume should execute, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 1 {
		t.Fatalf("C-3 VIOLATED: crash-while-Pending double-POSTed isolate (%d calls, want 1)", n)
	}
}

// C-4: reverse honors prior_state.changed — an isolate that changed state is undone via unisolate.
func TestDefenderRound_ReverseUnisolates(t *testing.T) {
	sup, repo, _, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate should execute, got %s err=%v", st, err)
	}
	res, err := sup.ReverseRun(ctx, tid, actor, runID)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if len(res) != 1 || res[0].Status != "reversed" {
		t.Fatalf("expected one reversed action, got %+v", res)
	}
	if n := atomic.LoadInt32(&mock.unisolCalls); n != 1 {
		t.Fatalf("reverse must unisolate once, got %d", n)
	}
}

// H-1 (round #34 regression): a crash AFTER the isolate POST but before Phase-C commit must NOT strand the
// endpoint isolated-with-no-release. Resume → PreCheck avoids the double-POST (C-3) AND the step stays
// reversible → ReverseRun unisolates. Before the seam fix, reverse silently skipped (changed=false).
func TestDefenderRound_ReverseAfterCrashResume(t *testing.T) {
	sup, repo, db, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID := uuid.New()

	// Isolate takes effect (1 POST), then simulate the crash: revert to 'executing' (Phase C never committed).
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate should execute, got %s err=%v", st, err)
	}
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET status='executing' WHERE run_id=$1 AND step_index=0`, runID)
		return e
	}); err != nil {
		t.Fatalf("simulate crash: %v", err)
	}

	// Resume: no double-POST (C-3) — the machine is isolated exactly once.
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume should execute, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 1 {
		t.Fatalf("resume must not double-POST, got %d", n)
	}

	// The endpoint is isolated by OUR action → reverse MUST release it (H-1: not a silent skipped_noop).
	res, err := sup.ReverseRun(ctx, tid, actor, runID)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if len(res) != 1 || res[0].Status != "reversed" {
		t.Fatalf("H-1: crash-resumed isolate must be reversible, got %+v", res)
	}
	if n := atomic.LoadInt32(&mock.unisolCalls); n != 1 {
		t.Fatalf("H-1: reverse must unisolate the crash-resumed isolation once, got %d", n)
	}
}

// H-1b (round #34 re-verify, THE FAIL-OPEN MIRROR): a machine already isolated by a FOREIGN actor, with a
// crash in our claim→commit window, must NOT be released by reverse. Our fresh isolate step no-ops on the
// foreign isolation (changed=false, correlator absent) → crash → resume → still foreign (correlator absent)
// → reverse MUST skip. Before the correlator fix, the `resumed`-flag override flipped changed=true and
// reverse released a containment we never created. `foreign` is set independent of any POST of ours.
func TestDefenderRound_ForeignIsolationNotReversed(t *testing.T) {
	sup, repo, db, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	mock.mu.Lock()
	mock.foreign = "Defender automated investigation isolate" // NO nirvet correlator → foreign
	mock.mu.Unlock()
	runID := uuid.New()

	// Fresh isolate: PreCheck finds the foreign isolation → no POST, changed=false.
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate should no-op on foreign isolation, got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 0 {
		t.Fatalf("must not POST when a foreign isolation already exists, got %d", n)
	}
	// Crash in the claim→commit window, then resume.
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET status='executing' WHERE run_id=$1 AND step_index=0`, runID)
		return e
	}); err != nil {
		t.Fatalf("simulate crash: %v", err)
	}
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume should re-affirm no-op, got %s err=%v", st, err)
	}

	// Reverse MUST NOT release a foreign containment.
	res, err := sup.ReverseRun(ctx, tid, actor, runID)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if n := atomic.LoadInt32(&mock.unisolCalls); n != 0 {
		t.Fatalf("H-1b FAIL-OPEN: reverse released a FOREIGN isolation (%d unisolate POSTs, want 0); res=%+v", n, res)
	}
	if len(res) == 1 && res[0].Status == "reversed" {
		t.Fatalf("H-1b: foreign isolation must be skipped_noop, not reversed: %+v", res)
	}
}

// C-6: an MDE API error → the step fails (not stuck executing), and no phantom effect is recorded.
func TestDefenderRound_APIErrorFails(t *testing.T) {
	sup, repo, _, tid, mock := setupDefender(t)
	mock.failIsolate = true
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	st, note, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, isoAct(), "host:WIN-EDR-3", nil)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}
	if st != soar.StatusFailed {
		t.Fatalf("MDE error must fail the step, got %s note=%q", st, note)
	}
}

// C-7: kill-switch engaged after a claim (crash mid-flight) → abort at Phase B, no isolate POST.
func TestDefenderRound_KillSwitchMidFlight(t *testing.T) {
	sup, repo, db, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID := uuid.New()
	// Seed a claimed-but-unexecuted row (crash right after Phase A), then flip the global kill-switch.
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO soar_action_execution (tenant_id, run_id, step_index, action_key, connector_key, target, risk_class, status)
			 VALUES ($1,$2,0,'isolate_endpoint','defender','host:WIN-EDR-3','high','executing')`, tid, runID)
		return e
	}); err != nil {
		t.Fatalf("seed executing: %v", err)
	}
	_ = repo.SetPlatformFlags(ctx, soar.PlatformFlags{KillSwitch: true})
	st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil)
	if err != nil || st != soar.StatusFailed {
		t.Fatalf("kill-switch mid-flight must abort (failed), got %s err=%v", st, err)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 0 {
		t.Fatalf("kill-switch must not isolate, got %d POSTs", n)
	}
}

// C-8: per-class hourly rate cap on Class-3 → the over-budget action is withheld, no isolate POST.
func TestDefenderRound_RateCapWithholds(t *testing.T) {
	sup, repo, _, tid, mock := setupDefender(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 1})
	if st, _, _ := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, isoAct(), "host:WIN-EDR-3", nil); st != soar.StatusExecuted {
		t.Fatalf("first should execute, got %s", st)
	}
	if st, _, _ := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, isoAct(), "host:WIN-EDR-3", nil); st != soar.StatusWithheld {
		t.Fatalf("second should be rate-withheld, got %s", st)
	}
	if n := atomic.LoadInt32(&mock.isolateCalls); n != 1 {
		t.Fatalf("only the budgeted isolate fires, got %d POSTs", n)
	}
}
