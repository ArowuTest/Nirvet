package connector

// Unit tests for the Graph alert-pull client's SSRF hardening (no DB): C-1 token-URL tenant escaping and C-3
// @odata.nextLink host-pinning. The mock is a loopback httptest server reached via an injected plain client
// (prod uses netsafe.SafeClient).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// C-1: the directory (tenant) id is path-escaped in the AAD token endpoint, so a value containing '/' can't
// reshape the URL path.
func TestMSLoginTokenURL_Escapes(t *testing.T) {
	got := msLoginTokenURL("con/../toso?x#y")
	// PathEscape encodes '/', '?', '#' — none may appear literally between the host and /oauth2.
	seg := strings.TrimPrefix(got, "https://login.microsoftonline.com/")
	tenantPart := strings.TrimSuffix(seg, "/oauth2/v2.0/token")
	if strings.ContainsAny(tenantPart, "/?#") {
		t.Fatalf("tenant segment not fully escaped: %q (full=%q)", tenantPart, got)
	}
	if !strings.HasPrefix(got, "https://login.microsoftonline.com/") || !strings.HasSuffix(got, "/oauth2/v2.0/token") {
		t.Fatalf("unexpected token URL shape: %q", got)
	}
}

// C-3: an @odata.nextLink pointing at a host other than the configured graph endpoint must be refused (the
// bearer token would otherwise be sent off-host). A same-host nextLink is followed normally.
func TestGraphClient_NextLinkHostPin(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"graph-token","expires_in":3600}`)
	}

	t.Run("off-host nextLink refused", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/token", tokenHandler)
		mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
			// First (and only) page: hand back an attacker-controlled nextLink on a DIFFERENT host.
			_, _ = io.WriteString(w, `{"value":[{"id":"a-1","title":"t"}],"@odata.nextLink":"https://graph.evil.example/next"}`)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		c := newGraphClient(srv.URL+"/token", srv.URL, "cid", "secret", srv.Client())
		out, err := c.fetchAlerts(context.Background(), "")
		if err == nil || !strings.Contains(err.Error(), "unexpected host") {
			t.Fatalf("expected off-host nextLink to be refused, got out=%d err=%v", len(out), err)
		}
		// The first page's alerts are still returned before the refusal (best-effort).
		if len(out) != 1 {
			t.Fatalf("expected page-0 alert preserved, got %d", len(out))
		}
	})

	t.Run("same-host nextLink followed", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/token", tokenHandler)
		page := 0
		mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
			page++
			if page == 1 {
				// Absolute same-host nextLink (scheme+host of this very request) → must be followed.
				_, _ = io.WriteString(w, `{"value":[{"id":"a-1"}],"@odata.nextLink":"http://`+r.Host+`/security/alerts_v2?page=2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"value":[{"id":"a-2"}]}`)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		c := newGraphClient(srv.URL+"/token", srv.URL, "cid", "secret", srv.Client())
		out, err := c.fetchAlerts(context.Background(), "")
		if err != nil {
			t.Fatalf("same-host paging should succeed: %v", err)
		}
		if len(out) != 2 {
			t.Fatalf("expected 2 alerts across 2 same-host pages, got %d", len(out))
		}
	})
}

// LAUNCH #1: the three new identity streams fetch + parse via the shared fetchPaged primitive (host-pin already
// covered above via alerts). Each asserts the endpoint is hit and the typed fields land.
func TestGraphClient_IdentityStreams(t *testing.T) {
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"graph-token","expires_in":3600}`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/auditLogs/signIns", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[{"id":"si-1","userPrincipalName":"alice@x","ipAddress":"203.0.113.9","status":{"errorCode":50126,"failureReason":"bad password"},"location":{"countryOrRegion":"RU"}}]}`)
	})
	mux.HandleFunc("/auditLogs/directoryAudits", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[{"id":"da-1","activityDisplayName":"Add member to role","category":"RoleManagement","result":"success","initiatedBy":{"user":{"userPrincipalName":"admin@x"}},"targetResources":[{"userPrincipalName":"victim@x"}]}]}`)
	})
	mux.HandleFunc("/identityProtection/riskyUsers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[{"id":"ru-1","userPrincipalName":"carol@x","riskLevel":"high","riskState":"atRisk"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newGraphClient(srv.URL+"/token", srv.URL, "cid", "secret", srv.Client())
	ctx := context.Background()

	sis, err := c.fetchSignIns(ctx, "")
	if err != nil || len(sis) != 1 || sis[0].UserPrincipalName != "alice@x" || sis[0].Status.ErrorCode != 50126 {
		t.Fatalf("fetchSignIns: err=%v out=%+v", err, sis)
	}
	das, err := c.fetchDirectoryAudits(ctx, "")
	if err != nil || len(das) != 1 || das[0].InitiatedBy.User.UserPrincipalName != "admin@x" || len(das[0].TargetResources) != 1 {
		t.Fatalf("fetchDirectoryAudits: err=%v out=%+v", err, das)
	}
	rus, err := c.fetchRiskyUsers(ctx, "")
	if err != nil || len(rus) != 1 || rus[0].RiskLevel != "high" {
		t.Fatalf("fetchRiskyUsers: err=%v out=%+v", err, rus)
	}
}

// connectorStreams: default is alerts-only (back-compat); unknown names dropped; valid names kept.
func TestConnectorStreams(t *testing.T) {
	if got := connectorStreams(nil); len(got) != 1 || got[0] != "alerts" {
		t.Errorf("nil config: got %v want [alerts]", got)
	}
	if got := connectorStreams(map[string]any{"streams": []any{"signins", "audit", "bogus"}}); len(got) != 2 || got[0] != "signins" || got[1] != "audit" {
		t.Errorf("allowlist: got %v want [signins audit]", got)
	}
	if got := connectorStreams(map[string]any{"streams": []any{"bogus"}}); len(got) != 1 || got[0] != "alerts" {
		t.Errorf("all-unknown falls back to [alerts]: got %v", got)
	}
}
