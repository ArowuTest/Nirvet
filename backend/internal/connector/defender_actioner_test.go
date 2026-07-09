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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArowuTest/nirvet/internal/soar"
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

// H-1b (round #34 re-verify): an already-active isolation is attributed as OURS (reversible) only if its
// requestorComment carries this step's correlator; a foreign comment stays non-reversible. Neither case
// re-POSTs (C-3). This is the unit-level locus of the fail-open fix.
func TestDefenderActioner_ForeignVsOwnAttribution(t *testing.T) {
	run := func(priorComment, correlator string) (map[string]any, int32) {
		var isoCalls int32
		mux := http.NewServeMux()
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
		})
		mux.HandleFunc("/api/machines", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"value":[{"id":"m-guid-1","computerDnsName":"WIN-EDR-3"}]}`)
		})
		mux.HandleFunc("/api/machineactions", func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Query().Get("$filter"), "'Isolate'") {
				_, _ = io.WriteString(w, `{"value":[]}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{{"id": "prior", "type": "Isolate", "status": "Pending", "requestorComment": priorComment}},
			})
		})
		mux.HandleFunc("/api/machines/m-guid-1/isolate", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&isoCalls, 1)
			_, _ = io.WriteString(w, `{"id":"iso-act-1","type":"Isolate","status":"Pending"}`)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		d := NewDefenderActioner(srv.URL+"/token", srv.URL, "", srv.Client())
		iso := actionerByAction(d, "isolate_endpoint")
		params := map[string]any{}
		if correlator != "" {
			params[soar.ActionCorrelatorParam] = correlator
		}
		_, prior, err := iso(context.Background(), defenderCreds(t), "host:WIN-EDR-3", params)
		if err != nil {
			t.Fatalf("isolate: %v", err)
		}
		return prior, atomic.LoadInt32(&isoCalls)
	}

	// Own: the active isolation carries our correlator → reversible, no re-POST.
	own, ownPosts := run("Nirvet SOAR Isolate [nirvet:R123:0]", "R123:0")
	if own["changed"] != true || ownPosts != 0 {
		t.Fatalf("own action must be changed=true with no re-POST: changed=%v posts=%d", own["changed"], ownPosts)
	}
	// Foreign: a different comment → NOT reversible, no re-POST (C-3 still holds).
	foreign, foreignPosts := run("Defender automated investigation", "R123:0")
	if foreign["changed"] != false || foreignPosts != 0 {
		t.Fatalf("foreign action must be changed=false with no re-POST: changed=%v posts=%d", foreign["changed"], foreignPosts)
	}
	// Round-#34 LOW: a delimited token means step :1 must NOT match another step's :10 comment.
	collide, _ := run("Nirvet SOAR Isolate [nirvet:R123:10]", "R123:1")
	if collide["changed"] != false {
		t.Fatalf("delimited token must prevent :1 matching :10, got changed=%v", collide["changed"])
	}
	// And the exact delimited token DOES match its own step.
	own10, _ := run("Nirvet SOAR Isolate [nirvet:R123:10]", "R123:10")
	if own10["changed"] != true {
		t.Fatalf("exact correlator token must match, got changed=%v", own10["changed"])
	}
}

// R-2: confirm() maps MDE machineAction terminal state → (done, success), and treats a 404/aged-out
// action as unconfirmable (done=false, "NotFound") rather than a false failure (D-d).
func TestDefenderActioner_Confirm(t *testing.T) {
	cases := []struct {
		status     string
		code       int
		done, succ bool
		want       string
	}{
		{"Succeeded", 200, true, true, "Succeeded"},
		{"Failed", 200, true, false, "Failed"},
		{"Cancelled", 200, true, false, "Cancelled"},
		{"TimeOut", 200, true, false, "TimeOut"},
		{"Pending", 200, false, false, "Pending"},
		{"InProgress", 200, false, false, "InProgress"},
		{"", 404, false, false, "NotFound"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
			})
			mux.HandleFunc("/api/machineactions/act-1", func(w http.ResponseWriter, r *http.Request) {
				if tc.code == 404 {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "act-1", "type": "Isolate", "status": tc.status})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			d := NewDefenderActioner(srv.URL+"/token", srv.URL, "", srv.Client())
			done, succ, status, err := d.confirm(context.Background(), defenderCreds(t), "act-1")
			if err != nil {
				t.Fatalf("confirm: %v", err)
			}
			if done != tc.done || succ != tc.succ || status != tc.want {
				t.Fatalf("status %q → done=%v succ=%v status=%q; want done=%v succ=%v status=%q",
					tc.status, done, succ, status, tc.done, tc.succ, tc.want)
			}
		})
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
