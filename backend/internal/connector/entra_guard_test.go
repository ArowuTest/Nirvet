package connector

// §6.11 D5 E-2 — the Entra protected-identity guard: L1 deny-list, L2 protected-role + last-of-role, L3 self,
// vendor-aware no-op, and Graph-error → fail-closed (returns err so the supervisor withholds). Pure unit test.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type mockCfg struct {
	deny  []string
	roles []string
}

func (m mockCfg) ProtectedIdentities(context.Context, uuid.UUID) ([]string, error) {
	return m.deny, nil
}
func (m mockCfg) ProtectedRoles(context.Context, uuid.UUID) ([]string, error) { return m.roles, nil }

// guardGraph serves the Graph reads the guard needs, parameterized per test.
func guardGraph(t *testing.T, enabled bool, roles []map[string]string, membersByRole map[string][]map[string]any, failRoles bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"t","expires_in":3600}`)
	})
	mux.HandleFunc("/users/u-1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u-1", "accountEnabled": enabled})
	})
	mux.HandleFunc("/users/u-1/transitiveMemberOf/microsoft.graph.directoryRole", func(w http.ResponseWriter, r *http.Request) {
		if failRoles {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": roles})
	})
	for roleID, members := range membersByRole {
		m := members
		mux.HandleFunc("/directoryRoles/"+roleID+"/members/microsoft.graph.user", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": m})
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func guardCreds(clientID string) []byte {
	b, _ := json.Marshal(Credentials{ClientID: clientID, ClientSecret: "s", AzureTenant: "az"})
	return b
}

func TestEntraGuard_Layers(t *testing.T) {
	ctx := context.Background()
	tid := uuid.New()

	// Non-entra connector → no-op (the guard only covers identity actions).
	g := NewEntraProtectedGuard(mockCfg{}, "", "https://graph.microsoft.com", "", nil)
	if p, _, err := g.CheckProtected(ctx, tid, "defender", "isolate_endpoint", "host:h", guardCreds("app")); p || err != nil {
		t.Fatalf("non-entra must no-op, got protected=%v err=%v", p, err)
	}

	// L3 self by target string (no Graph call needed).
	g = NewEntraProtectedGuard(mockCfg{}, "x", "y", "", nil)
	if p, reason, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:app-self", guardCreds("app-self")); !p || err != nil || !strings.Contains(reason, "self") {
		t.Fatalf("self must be protected: p=%v reason=%q err=%v", p, reason, err)
	}

	// Two enabled members of the role → not last-of-role. Cases below vary the config/state.
	twoMembers := map[string][]map[string]any{"role-ga": {{"id": "u-1", "accountEnabled": true}, {"id": "u-2", "accountEnabled": true}}}
	gaRole := []map[string]string{{"id": "role-ga", "displayName": "Global Administrator", "roleTemplateId": "tmpl"}}

	// L1 deny-list (by UPN target).
	srv := guardGraph(t, true, nil, nil, false)
	g = NewEntraProtectedGuard(mockCfg{deny: []string{"u-1"}}, srv.URL+"/token", srv.URL, "", srv.Client())
	if p, reason, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:u-1", guardCreds("app")); !p || err != nil || !strings.Contains(reason, "deny-list") {
		t.Fatalf("deny-list must be protected: p=%v reason=%q err=%v", p, reason, err)
	}

	// L2 protected role (holds Global Administrator, which is in the protected set) — two members so NOT last-of-role.
	srv = guardGraph(t, true, gaRole, twoMembers, false)
	g = NewEntraProtectedGuard(mockCfg{roles: []string{"global administrator"}}, srv.URL+"/token", srv.URL, "", srv.Client())
	if p, reason, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:u-1", guardCreds("app")); !p || err != nil || !strings.Contains(reason, "protected directory role") {
		t.Fatalf("protected role must be protected: p=%v reason=%q err=%v", p, reason, err)
	}

	// L2 last-of-role: holds a role NOT in the protected set but is its sole enabled member.
	oneMember := map[string][]map[string]any{"role-x": {{"id": "u-1", "accountEnabled": true}, {"id": "u-9", "accountEnabled": false}}}
	xRole := []map[string]string{{"id": "role-x", "displayName": "Custom Admin", "roleTemplateId": "tmpl"}}
	srv = guardGraph(t, true, xRole, oneMember, false)
	g = NewEntraProtectedGuard(mockCfg{roles: []string{"global administrator"}}, srv.URL+"/token", srv.URL, "", srv.Client())
	if p, reason, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:u-1", guardCreds("app")); !p || err != nil || !strings.Contains(reason, "last enabled member") {
		t.Fatalf("last-of-role must be protected: p=%v reason=%q err=%v", p, reason, err)
	}

	// Clean: enabled, no roles, not denied → NOT protected.
	srv = guardGraph(t, true, nil, nil, false)
	g = NewEntraProtectedGuard(mockCfg{roles: []string{"global administrator"}}, srv.URL+"/token", srv.URL, "", srv.Client())
	if p, _, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:u-1", guardCreds("app")); p || err != nil {
		t.Fatalf("clean user must not be protected: p=%v err=%v", p, err)
	}

	// Graph error (roles read fails) → returns err so the SUPERVISOR fails closed.
	srv = guardGraph(t, true, nil, nil, true)
	g = NewEntraProtectedGuard(mockCfg{}, srv.URL+"/token", srv.URL, "", srv.Client())
	if p, _, err := g.CheckProtected(ctx, tid, "entra-id", "disable_user", "user:u-1", guardCreds("app")); err == nil {
		t.Fatalf("a Graph error must return err (fail-closed), got protected=%v err=nil", p)
	} else if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected cancellation")
	}
}
