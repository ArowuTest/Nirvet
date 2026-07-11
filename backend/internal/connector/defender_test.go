package connector

// §6.11 slice C C-2 — Defender action client against a mock MDE server + the D-1 base-URL allowlist.
// Pure unit test (no DB): the mock is a loopback httptest server reached via an injected plain client
// (prod uses netsafe.SafeClient).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockMDE serves the token endpoint + the machine/isolate/unisolate/machineactions calls the client uses.
func mockMDE(t *testing.T, actionStatus string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
	})
	mux.HandleFunc("/api/machines", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mde-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"value":[{"id":"m-guid-1","computerDnsName":"WIN-EDR-3"}]}`)
	})
	mux.HandleFunc("/api/machineactions", func(w http.ResponseWriter, r *http.Request) {
		if actionStatus == "" {
			_, _ = io.WriteString(w, `{"value":[]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{{"id": "prior-act-1", "type": "Isolate", "status": actionStatus}},
		})
	})
	mux.HandleFunc("/api/machines/m-guid-1/isolate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"iso-act-1","type":"Isolate","status":"Pending"}`)
	})
	mux.HandleFunc("/api/machines/m-guid-1/unisolate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"unl-act-1","type":"Unisolate","status":"Pending"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDefenderClient_LookupIsolateReverse(t *testing.T) {
	srv := mockMDE(t, "") // no prior action
	ctx := context.Background()
	c := newDefenderClient(srv.URL+"/token", srv.URL, "test-scope", "cid", "secret", srv.Client())

	id, err := c.resolveMachineID(ctx, "WIN-EDR-3")
	if err != nil || id != "m-guid-1" {
		t.Fatalf("resolveMachineID: id=%q err=%v", id, err)
	}
	// No prior machineAction → PreCheck sees nothing.
	if _, found, err := c.latestMachineAction(ctx, id, "Isolate"); err != nil || found {
		t.Fatalf("latestMachineAction expected none: found=%v err=%v", found, err)
	}
	act, err := c.isolate(ctx, id, "nirvet containment")
	if err != nil || act != "iso-act-1" {
		t.Fatalf("isolate: act=%q err=%v", act, err)
	}
	rev, err := c.unisolate(ctx, id, "nirvet release")
	if err != nil || rev != "unl-act-1" {
		t.Fatalf("unisolate: act=%q err=%v", rev, err)
	}
}

// M-1 (round #34): a hostname containing a single quote must be escaped (doubled) so it cannot break out
// of the OData string literal and mis-target the machine lookup.
func TestDefenderClient_ODataQuoteEscaped(t *testing.T) {
	if got := odataQuote("x' or computerDnsName ne 'z"); got != "x'' or computerDnsName ne ''z" {
		t.Fatalf("odataQuote did not double quotes: %q", got)
	}
	var gotFilter string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
	})
	mux.HandleFunc("/api/machines", func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("$filter") // decoded OData filter
		_, _ = io.WriteString(w, `{"value":[{"id":"m-guid-1"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newDefenderClient(srv.URL+"/token", srv.URL, "", "cid", "secret", srv.Client())
	if _, err := c.resolveMachineID(context.Background(), "evil' or '1'='1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(gotFilter, "computerDnsName eq 'evil'' or ''1''=''1'") {
		t.Fatalf("crafted quote not escaped in filter: %q", gotFilter)
	}
}

func TestDefenderClient_PreCheckSeesPending(t *testing.T) {
	// The crash-while-Pending signal (C-3): a prior Isolate in Pending must be visible to PreCheck.
	srv := mockMDE(t, "Pending")
	ctx := context.Background()
	c := newDefenderClient(srv.URL+"/token", srv.URL, "", "cid", "secret", srv.Client())

	act, found, err := c.latestMachineAction(ctx, "m-guid-1", "Isolate")
	if err != nil || !found {
		t.Fatalf("expected a prior action, found=%v err=%v", found, err)
	}
	if act.Status != "Pending" || !strings.EqualFold(act.Type, "Isolate") {
		t.Fatalf("unexpected prior action: %+v", act)
	}
}
