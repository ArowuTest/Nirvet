package connector

// §6.11 slice C C-3 — the Defender Actioner Fn: PreCheck-then-POST, prior_state.changed, and the C-3
// resume-safety property in isolation (a prior Isolate in Pending → NO second isolate POST). Pure unit
// test (no DB) against a stateful mock MDE that counts isolate POSTs.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// statefulMDE serves the MDE endpoints and counts isolate POSTs. If priorIsolate!=\"\", the
// machineactions query reports a prior Isolate with that status (simulating an in-flight/complete action).
type statefulMDE struct {
	srv          *httptest.Server
	isolateCalls int32
	priorIsolate string
}

func newStatefulMDE(t *testing.T, priorIsolate string) *statefulMDE {
	t.Helper()
	m := &statefulMDE{priorIsolate: priorIsolate}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
	})
	mux.HandleFunc("/api/machines", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[{"id":"m-guid-1","computerDnsName":"WIN-EDR-3"}]}`)
	})
	mux.HandleFunc("/api/machineactions", func(w http.ResponseWriter, r *http.Request) {
		if m.priorIsolate == "" {
			_, _ = io.WriteString(w, `{"value":[]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{{"id": "prior-act-1", "type": "Isolate", "status": m.priorIsolate}},
		})
	})
	mux.HandleFunc("/api/machines/m-guid-1/isolate", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&m.isolateCalls, 1)
		_, _ = io.WriteString(w, `{"id":"iso-act-1","type":"Isolate","status":"Pending"}`)
	})
	mux.HandleFunc("/api/machines/m-guid-1/unisolate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"unl-act-1","type":"Unisolate","status":"Pending"}`)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func defenderCreds(t *testing.T) []byte {
	t.Helper()
	b, _ := json.Marshal(Credentials{ClientID: "cid", ClientSecret: "secret", AzureTenant: "az"})
	return b
}

func actionerByAction(d *DefenderActioner, action string) func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
	for _, a := range d.Actioners() {
		if a.Action == action {
			return a.Fn
		}
	}
	return nil
}

func TestDefenderActioner_IsolateThenPrecheckSkips(t *testing.T) {
	ctx := context.Background()
	creds := defenderCreds(t)

	// No prior action → PreCheck clears → isolate POSTs once, changed=true.
	m := newStatefulMDE(t, "")
	d := NewDefenderActioner(m.srv.URL+"/token", m.srv.URL, "", m.srv.Client())
	isolate := actionerByAction(d, "isolate_endpoint")

	ref, prior, err := isolate(ctx, creds, "host:WIN-EDR-3", nil)
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if ref != "iso-act-1" || prior["changed"] != true {
		t.Fatalf("expected fresh isolate: ref=%q prior=%v", ref, prior)
	}
	if got := atomic.LoadInt32(&m.isolateCalls); got != 1 {
		t.Fatalf("expected exactly 1 isolate POST, got %d", got)
	}

	// C-3 in isolation: a prior Isolate in Pending → PreCheck treats as already-requested → NO POST.
	m2 := newStatefulMDE(t, "Pending")
	d2 := NewDefenderActioner(m2.srv.URL+"/token", m2.srv.URL, "", m2.srv.Client())
	isolate2 := actionerByAction(d2, "isolate_endpoint")

	ref2, prior2, err := isolate2(ctx, creds, "host:WIN-EDR-3", nil)
	if err != nil {
		t.Fatalf("isolate (precheck): %v", err)
	}
	if prior2["changed"] != false {
		t.Fatalf("expected changed=false when already isolating, got %v", prior2)
	}
	if got := atomic.LoadInt32(&m2.isolateCalls); got != 0 {
		t.Fatalf("crash-while-Pending guard: expected 0 isolate POSTs, got %d (ref=%q)", got, ref2)
	}
}

func TestDefenderActioner_Release(t *testing.T) {
	ctx := context.Background()
	m := newStatefulMDE(t, "")
	d := NewDefenderActioner(m.srv.URL+"/token", m.srv.URL, "", m.srv.Client())
	release := actionerByAction(d, "release_endpoint")
	if release == nil {
		t.Fatal("release_endpoint actioner not registered")
	}
	ref, prior, err := release(ctx, defenderCreds(t), "machine:m-guid-1", map[string]any{"reverse_of": "isolate_endpoint"})
	if err != nil || ref != "unl-act-1" || prior["changed"] != true {
		t.Fatalf("release: ref=%q prior=%v err=%v", ref, prior, err)
	}
}
