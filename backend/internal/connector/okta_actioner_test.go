package connector

// §6.11 G1 Okta actioner — unit tests against a loopback mock (injected http.Client, so no SafeClient/SSRF
// weakening; same pattern as the Defender/Entra slice-B tests). Proves the reviewer's 3 must-adds + the
// terminal-state fail-safe + the Actioner contract flags.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// oktaMock is a minimal Okta API: a user's status is mutable via lifecycle; it records calls made.
type oktaMock struct {
	status     string
	suspended  int
	unsuspend  int
	revoked    int
	lastUserID string
}

func newOktaServer(t *testing.T, m *oktaMock, userID string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		switch {
		case strings.HasSuffix(path, "/lifecycle/suspend") && r.Method == http.MethodPost:
			// Okta 400s a suspend on a non-ACTIVE user — assert the actioner never calls us in that case.
			if m.status != "ACTIVE" {
				t.Errorf("suspend called on non-ACTIVE user (status=%s) — PreCheck should have prevented it", m.status)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.suspended++
			m.status = "SUSPENDED"
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(path, "/lifecycle/unsuspend") && r.Method == http.MethodPost:
			if m.status != "SUSPENDED" {
				t.Errorf("unsuspend called on non-SUSPENDED user (status=%s)", m.status)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.unsuspend++
			m.status = "ACTIVE"
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(path, "/sessions") && r.Method == http.MethodDelete:
			m.revoked++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			m.lastUserID = strings.TrimSuffix(path, "/")
			_ = json.NewEncoder(w).Encode(oktaUser{ID: userID, Status: m.status})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func oktaActionerFor(srv *httptest.Server) *OktaActioner {
	// Inject the org URL + token + the httptest client → SafeClient is not used (loopback allowed in tests).
	return NewOktaActioner(srv.URL, "test-token", srv.Client())
}

func fnFor(t *testing.T, a *OktaActioner, action string) func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
	t.Helper()
	for _, ac := range a.Actioners() {
		if ac.Action == action {
			return ac.Fn
		}
	}
	t.Fatalf("action %q not registered", action)
	return nil
}

func TestOktaActioner_ContractFlags(t *testing.T) {
	a := NewOktaActioner("x", "y", nil)
	by := map[string]soar.Actioner{}
	for _, ac := range a.Actioners() {
		by[ac.Action] = ac
	}
	// MA-1: revoke_sessions MUST be Idempotent or canAutoRun refuses it.
	if !by["okta_revoke_sessions"].Idempotent {
		t.Error("okta_revoke_sessions must declare Idempotent:true (MA-1) or the engine never auto-runs it")
	}
	// suspend/unsuspend: reversible with a matching inverse (Class-3 auto-run requires it).
	if !by["okta_suspend_user"].Reversible || by["okta_suspend_user"].Inverse != "okta_unsuspend_user" {
		t.Error("okta_suspend_user must be Reversible with Inverse okta_unsuspend_user")
	}
	if !by["okta_suspend_user"].PreCheck {
		t.Error("okta_suspend_user must PreCheck (terminal-state)")
	}
	if by["okta_unsuspend_user"].Inverse != "okta_suspend_user" {
		t.Error("okta_unsuspend_user inverse must be okta_suspend_user")
	}
}

func TestOktaActioner_SuspendActive(t *testing.T) {
	m := &oktaMock{status: "ACTIVE"}
	srv := newOktaServer(t, m, "00uABC")
	fn := fnFor(t, oktaActionerFor(srv), "okta_suspend_user")
	creds, _ := json.Marshal(Credentials{})
	ref, prior, err := fn(context.Background(), creds, "user:jdoe", nil)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if m.suspended != 1 {
		t.Fatalf("expected 1 suspend call, got %d", m.suspended)
	}
	if prior["changed"] != true {
		t.Fatalf("changed must be true on a real suspend, got %v", prior["changed"])
	}
	// MA-2: action_id must be the BARE vendor id (== ref), never prefixed.
	if prior["action_id"] != "00uABC" || ref != "00uABC" {
		t.Fatalf("action_id/ref must be the bare user id 00uABC, got action_id=%v ref=%q", prior["action_id"], ref)
	}
}

func TestOktaActioner_SuspendAlreadyAccessDenied_GoalMet(t *testing.T) {
	// MA-3: suspending an already-SUSPENDED/DEPROVISIONED user is goal-met — no call, changed=false, no error.
	for _, st := range []string{"SUSPENDED", "DEPROVISIONED", "LOCKED_OUT"} {
		m := &oktaMock{status: st}
		srv := newOktaServer(t, m, "00uZ")
		fn := fnFor(t, oktaActionerFor(srv), "okta_suspend_user")
		creds, _ := json.Marshal(Credentials{})
		_, prior, err := fn(context.Background(), creds, "user:x", nil)
		if err != nil {
			t.Fatalf("status %s: suspend must not error (goal met), got %v", st, err)
		}
		if m.suspended != 0 {
			t.Fatalf("status %s: must NOT call suspend (goal already met), got %d calls", st, m.suspended)
		}
		if prior["changed"] != false {
			t.Fatalf("status %s: changed must be false (we caused no effect)", st)
		}
		if prior["action_id"] != "00uZ" {
			t.Fatalf("status %s: action_id must be the bare id even when goal-met", st)
		}
	}
}

func TestOktaActioner_SuspendStagedNotApplicable(t *testing.T) {
	// STAGED/PROVISIONED (never activated): no sessions to contain, suspend would 400 → treat as goal-met, no call.
	for _, st := range []string{"STAGED", "PROVISIONED"} {
		m := &oktaMock{status: st}
		srv := newOktaServer(t, m, "00uS")
		fn := fnFor(t, oktaActionerFor(srv), "okta_suspend_user")
		creds, _ := json.Marshal(Credentials{})
		_, prior, err := fn(context.Background(), creds, "user:x", nil)
		if err != nil {
			t.Fatalf("status %s: must not error, got %v", st, err)
		}
		if m.suspended != 0 || prior["changed"] != false {
			t.Fatalf("status %s: must not call suspend; changed must be false", st)
		}
	}
}

func TestOktaActioner_UnsuspendOnlyFromSuspended(t *testing.T) {
	// Reverse from SUSPENDED → transitions. Reverse from any other state → no-op (never resurrect).
	m := &oktaMock{status: "SUSPENDED"}
	srv := newOktaServer(t, m, "00uR")
	fn := fnFor(t, oktaActionerFor(srv), "okta_unsuspend_user")
	creds, _ := json.Marshal(Credentials{})
	if _, prior, err := fn(context.Background(), creds, "user:x", nil); err != nil || prior["changed"] != true {
		t.Fatalf("unsuspend from SUSPENDED must transition (changed=true), err=%v prior=%v", err, prior)
	}
	if m.unsuspend != 1 {
		t.Fatalf("expected 1 unsuspend, got %d", m.unsuspend)
	}
	// Now DEPROVISIONED — reverse must NOT resurrect.
	m2 := &oktaMock{status: "DEPROVISIONED"}
	srv2 := newOktaServer(t, m2, "00uR2")
	fn2 := fnFor(t, oktaActionerFor(srv2), "okta_unsuspend_user")
	if _, prior, err := fn2(context.Background(), creds, "user:x", nil); err != nil || prior["changed"] != false {
		t.Fatalf("unsuspend from DEPROVISIONED must be a no-op (changed=false), err=%v prior=%v", err, prior)
	}
	if m2.unsuspend != 0 {
		t.Fatalf("must NOT unsuspend a DEPROVISIONED user, got %d calls", m2.unsuspend)
	}
}

func TestOktaActioner_RevokeSessionsIdempotent(t *testing.T) {
	m := &oktaMock{status: "ACTIVE"}
	srv := newOktaServer(t, m, "00uV")
	fn := fnFor(t, oktaActionerFor(srv), "okta_revoke_sessions")
	creds, _ := json.Marshal(Credentials{})
	for i := 0; i < 2; i++ { // idempotent: two calls both succeed
		_, prior, err := fn(context.Background(), creds, "user:x", nil)
		if err != nil {
			t.Fatalf("revoke #%d: %v", i, err)
		}
		if prior["action_id"] != "00uV" {
			t.Fatalf("revoke: action_id must be the bare id")
		}
	}
	if m.revoked != 2 {
		t.Fatalf("expected 2 revoke calls, got %d", m.revoked)
	}
}
