package soar_test

// §6.11 Entra vendor E-4 — the dedicated adversarial round: the REAL Entra disable/enable Actioners + the REAL
// D5 protected-identity guard, driven through the REAL supervisor against a stateful mock Graph + a migrated
// Postgres. Headline probes: terminal-state fail-safe (foreign-already-disabled → reverse never re-enables;
// own-crash → stranded-disabled, not re-enabled) and the D5 guard (deny-list / Global-Admin / last-of-role /
// self → withheld+escalate+alert, no PATCH).

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

// entraCreds is the CredDecryptor: a fixed bundle whose client_id doubles as the "self" identity for L3.
type entraCreds struct{}

func (entraCreds) ConnectorCreds(context.Context, uuid.UUID, string) ([]byte, error) {
	return json.Marshal(connector.Credentials{ClientID: "app-self", ClientSecret: "s", AzureTenant: "az"})
}

// graphMock is a stateful Microsoft Graph: u-1's accountEnabled toggles on PATCH; roles + role-members are
// seeded per test for the D5 guard.
type graphMock struct {
	srv        *httptest.Server
	mu         sync.Mutex
	enabled    bool
	patchCalls int32
	roles      []map[string]string
	members    map[string][]map[string]any
}

func newGraphMock(t *testing.T, enabled bool, roles []map[string]string, members map[string][]map[string]any) *graphMock {
	t.Helper()
	m := &graphMock{enabled: enabled, roles: roles, members: members}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	})
	mux.HandleFunc("/users/u-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var body struct {
				AccountEnabled bool `json:"accountEnabled"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.enabled = body.AccountEnabled
			m.mu.Unlock()
			atomic.AddInt32(&m.patchCalls, 1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		m.mu.Lock()
		en := m.enabled
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u-1", "accountEnabled": en})
	})
	mux.HandleFunc("/users/u-1/transitiveMemberOf/microsoft.graph.directoryRole", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": m.roles})
	})
	for id, mem := range members {
		mm := mem
		mux.HandleFunc("/directoryRoles/"+id+"/members/microsoft.graph.user", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": mm})
		})
	}
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func disableAct() soar.ActionCatalog {
	return soar.ActionCatalog{ActionKey: "disable_user", ConnectorKey: "entra-id", RiskClass: soar.RiskHigh, Executor: soar.ExecutorConnector, Enabled: true}
}

func setupEntra(t *testing.T, enabled bool, roles []map[string]string, members map[string][]map[string]any) (*soar.Supervisor, *soar.Repository, *database.DB, uuid.UUID, *graphMock, *mockAlerter) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := soar.NewRepository(db)
	t.Cleanup(func() { _ = repo.SetPlatformFlags(context.Background(), soar.PlatformFlags{}) })
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "entra-" + uuid.NewString()})
	_ = repo.SetSoarSettings(context.Background(), tn.ID, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})

	m := newGraphMock(t, enabled, roles, members)
	reg := soar.NewActionerRegistry()
	for _, a := range connector.NewEntraActioner(m.srv.URL+"/token", m.srv.URL, "", m.srv.Client()).Actioners() {
		reg.Register(a)
	}
	guard := connector.NewEntraProtectedGuard(repo, m.srv.URL+"/token", m.srv.URL, "", m.srv.Client())
	al := &mockAlerter{}
	sup := soar.NewSupervisor(repo, reg, entraCreds{}, nil).WithGuard(guard).WithAlerter(al)
	return sup, repo, db, tn.ID, m, al
}

func entraActor(tid uuid.UUID) auth.Principal {
	return auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
}

// Happy path: enabled user, no roles → guard allows → disable PATCHes → changed=true; the account is now off.
func TestEntraRound_DisableHappyPath(t *testing.T) {
	sup, _, _, tid, m, al := setupEntra(t, true, nil, nil)
	ctx := context.Background()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, entraActor(tid), uuid.New(), 0, disableAct(), "user:u-1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("disable should execute, got %s %v", st, err)
	}
	if n := atomic.LoadInt32(&m.patchCalls); n != 1 {
		t.Fatalf("expected 1 disable PATCH, got %d", n)
	}
	if al.failed(tid) != 0 {
		t.Fatal("no alert on a clean disable")
	}
}

// Foreign-already-disabled: PreCheck sees disabled → no PATCH, changed=false → reverse NEVER re-enables.
func TestEntraRound_ForeignDisabledNotReEnabled(t *testing.T) {
	sup, _, _, tid, m, _ := setupEntra(t, false, nil, nil) // already disabled by a foreign actor
	ctx := context.Background()
	actor := entraActor(tid)
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, disableAct(), "user:u-1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("disable no-op should execute, got %s %v", st, err)
	}
	if n := atomic.LoadInt32(&m.patchCalls); n != 0 {
		t.Fatalf("must not PATCH an already-disabled account, got %d", n)
	}
	if _, err := sup.ReverseRun(ctx, tid, actor, runID); err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if n := atomic.LoadInt32(&m.patchCalls); n != 0 {
		t.Fatalf("reverse must NOT re-enable a foreign disable, got %d PATCH", n)
	}
}

// Own-crash fail-safe: disable (PATCH), crash, resume reads disabled → changed=false → reverse does NOT
// re-enable (stranded disabled = the safe direction; the reconciler surfaces it).
func TestEntraRound_OwnCrashFailSafe(t *testing.T) {
	sup, _, db, tid, m, _ := setupEntra(t, true, nil, nil)
	ctx := context.Background()
	actor := entraActor(tid)
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, disableAct(), "user:u-1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("disable should execute, got %s %v", st, err)
	}
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET status='executing' WHERE run_id=$1 AND step_index=0`, runID)
		return e
	}); err != nil {
		t.Fatalf("crash: %v", err)
	}
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, disableAct(), "user:u-1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume should execute, got %s %v", st, err)
	}
	patchAfterResume := atomic.LoadInt32(&m.patchCalls) // 1 (the original disable); resume PreCheck sees disabled, no re-PATCH
	if patchAfterResume != 1 {
		t.Fatalf("resume must not re-PATCH, got %d", patchAfterResume)
	}
	if _, err := sup.ReverseRun(ctx, tid, actor, runID); err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if n := atomic.LoadInt32(&m.patchCalls); n != 1 {
		t.Fatalf("fail-safe: an own-crash disable stays disabled (reverse must NOT re-enable), got %d PATCH", n)
	}
}

// Clean reverse: disable (changed=true, no crash) → reverse re-enables.
func TestEntraRound_CleanReverseReEnables(t *testing.T) {
	sup, _, _, tid, m, _ := setupEntra(t, true, nil, nil)
	ctx := context.Background()
	actor := entraActor(tid)
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, disableAct(), "user:u-1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("disable should execute, got %s %v", st, err)
	}
	res, err := sup.ReverseRun(ctx, tid, actor, runID)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if len(res) != 1 || res[0].Status != "reversed" {
		t.Fatalf("clean disable must reverse, got %+v", res)
	}
	if n := atomic.LoadInt32(&m.patchCalls); n != 2 { // disable + enable
		t.Fatalf("reverse must re-enable (2 PATCH total), got %d", n)
	}
	m.mu.Lock()
	en := m.enabled
	m.mu.Unlock()
	if !en {
		t.Fatal("account should be re-enabled after reverse")
	}
}

// D5 guard: each protected case → withheld+escalate+alert, no PATCH.
func TestEntraRound_D5Guards(t *testing.T) {
	ctx := context.Background()
	ga := []map[string]string{{"id": "role-ga", "displayName": "Global Administrator", "roleTemplateId": "t"}}
	gaMembersTwo := map[string][]map[string]any{"role-ga": {{"id": "u-1", "accountEnabled": true}, {"id": "u-2", "accountEnabled": true}}}
	customRole := []map[string]string{{"id": "role-x", "displayName": "Custom Admin", "roleTemplateId": "t"}}
	customSolo := map[string][]map[string]any{"role-x": {{"id": "u-1", "accountEnabled": true}}}

	cases := []struct {
		name   string
		target string
		roles  []map[string]string
		mem    map[string][]map[string]any
		deny   string // seed a deny-list identity
	}{
		{"self", "user:app-self", nil, nil, ""},
		{"deny_list", "user:u-1", nil, nil, "u-1"},
		{"global_admin", "user:u-1", ga, gaMembersTwo, ""},
		{"last_of_role", "user:u-1", customRole, customSolo, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sup, repo, db, tid, m, al := setupEntra(t, true, tc.roles, tc.mem)
			if tc.deny != "" {
				if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
					_, e := tx.Exec(ctx, `INSERT INTO protected_identities (tenant_id, identity_ref, reason) VALUES ($1,$2,'test')`, tid, tc.deny)
					return e
				}); err != nil {
					t.Fatalf("seed deny: %v", err)
				}
			}
			_ = repo
			st, note, err := sup.ExecuteConnectorStep(ctx, tid, entraActor(tid), uuid.New(), 0, disableAct(), tc.target, nil)
			if err != nil || st != soar.StatusAwaitingCustomer {
				t.Fatalf("%s must withhold+escalate, got %s note=%q err=%v", tc.name, st, note, err)
			}
			if n := atomic.LoadInt32(&m.patchCalls); n != 0 {
				t.Fatalf("%s must NOT PATCH a protected identity, got %d", tc.name, n)
			}
			if al.failed(tid) != 1 {
				t.Fatalf("%s must alert (withheld), got %d", tc.name, al.failed(tid))
			}
			if !strings.Contains(note, "protected") {
				t.Fatalf("%s note should say protected: %q", tc.name, note)
			}
		})
	}
}
