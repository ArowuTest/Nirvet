package connector

// §6.11 second vendor E-1 — Entra Graph client against a mock Graph server + the base-URL allowlist. Pure
// unit test (no DB); loopback httptest reached via an injected plain client (prod uses netsafe.SafeClient).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateGraphBaseURL(t *testing.T) {
	for _, u := range []string{"https://graph.microsoft.com", "https://graph.microsoft.com/v1.0", "https://graph.microsoft.us"} {
		if err := ValidateGraphBaseURL(u); err != nil {
			t.Errorf("expected %q allowed, got %v", u, err)
		}
	}
	for _, u := range []string{
		"https://evil.com",
		"https://graph.microsoft.com.evil.com", // suffix-spoof must not match
		"http://graph.microsoft.com",           // must be https
		"https://127.0.0.1",
		"",
	} {
		if err := ValidateGraphBaseURL(u); err == nil {
			t.Errorf("expected %q rejected", u)
		}
	}
}

func mockGraphIdentity(t *testing.T, enabled bool, roles []map[string]string, roleMembers []map[string]any) (*httptest.Server, *int) {
	t.Helper()
	patchCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"graph-token","expires_in":3600}`)
	})
	mux.HandleFunc("/users/u-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patchCalls++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u-1", "accountEnabled": enabled})
	})
	mux.HandleFunc("/users/u-1/transitiveMemberOf/microsoft.graph.directoryRole", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": roles})
	})
	mux.HandleFunc("/directoryRoles/role-ga/members/microsoft.graph.user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": roleMembers})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &patchCalls
}

func TestEntraClient_ResolveDisableRolesCount(t *testing.T) {
	ctx := context.Background()
	roles := []map[string]string{{"id": "role-ga", "displayName": "Global Administrator", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"}}
	members := []map[string]any{{"id": "u-1", "accountEnabled": true}, {"id": "u-2", "accountEnabled": true}, {"id": "u-3", "accountEnabled": false}}
	srv, patchCalls := mockGraphIdentity(t, true, roles, members)
	c := newEntraClient(srv.URL+"/token", srv.URL, "", "cid", "secret", srv.Client())

	u, found, err := c.resolveUser(ctx, "u-1")
	if err != nil || !found || u.ID != "u-1" || !u.AccountEnabled {
		t.Fatalf("resolveUser: u=%+v found=%v err=%v", u, found, err)
	}
	got, err := c.userDirectoryRoles(ctx, "u-1")
	if err != nil || len(got) != 1 || got[0].DisplayName != "Global Administrator" {
		t.Fatalf("userDirectoryRoles: %+v err=%v", got, err)
	}
	// last-of-role: two enabled members of Global Administrator.
	n, err := c.roleEnabledMemberCount(ctx, "role-ga")
	if err != nil || n != 2 {
		t.Fatalf("roleEnabledMemberCount: n=%d err=%v", n, err)
	}
	if err := c.setAccountEnabled(ctx, "u-1", false); err != nil {
		t.Fatalf("setAccountEnabled: %v", err)
	}
	if *patchCalls != 1 {
		t.Fatalf("expected 1 PATCH, got %d", *patchCalls)
	}
}

func TestEntraClient_ResolveNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"graph-token","expires_in":3600}`)
	})
	mux.HandleFunc("/users/nobody", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newEntraClient(srv.URL+"/token", srv.URL, "", "cid", "secret", srv.Client())
	if _, found, err := c.resolveUser(context.Background(), "nobody"); err != nil || found {
		t.Fatalf("expected not found, got found=%v err=%v", found, err)
	}
}
