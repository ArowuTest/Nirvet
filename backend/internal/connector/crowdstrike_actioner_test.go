package connector

// §6.11 G1 #2 CrowdStrike actioner — unit tests against a loopback Falcon mock (injected client, no SSRF weakening).
// Proves: contract flags, the multi-state containment fail-safe (incl. CS-MA1 re-contain over lift_containment_pending),
// action_id = bare device id, async Confirm terminal states, and that block/allow/kill are NOT registered (deferred).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// csMock is a minimal Falcon API: OAuth token + device status (mutable) + device-actions that record calls.
type csMock struct {
	status    string
	contain   int
	lift      int
	deviceID  string
	failToken bool
}

func newCSServer(t *testing.T, m *csMock) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if m.failToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 1800})
	})
	mux.HandleFunc("/devices/queries/devices/v1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []string{m.deviceID}})
	})
	mux.HandleFunc("/devices/entities/devices/v2", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"status": m.status}}})
	})
	mux.HandleFunc("/devices/entities/devices-actions/v2", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("action_name") {
		case "contain":
			m.contain++
			m.status = "contained"
		case "lift_containment":
			m.lift++
			m.status = "normal"
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func csActionerFor(srv *httptest.Server) *CrowdStrikeActioner {
	return NewCrowdStrikeActioner(srv.URL, "id", "secret", srv.Client())
}

func csFn(t *testing.T, a *CrowdStrikeActioner, action string) (soar.Actioner, func(context.Context, []byte, string, map[string]any) (string, map[string]any, error)) {
	t.Helper()
	for _, ac := range a.Actioners() {
		if ac.Action == action {
			return ac, ac.Fn
		}
	}
	t.Fatalf("action %q not registered", action)
	return soar.Actioner{}, nil
}

func TestCrowdStrike_ContractFlags(t *testing.T) {
	a := NewCrowdStrikeActioner("x", "i", "s", nil)
	by := map[string]soar.Actioner{}
	for _, ac := range a.Actioners() {
		by[ac.Action] = ac
	}
	iso, ok := by["cs_isolate_host"]
	if !ok || !iso.PreCheck || !iso.Reversible || iso.Inverse != "cs_release_host" || iso.Confirm == nil {
		t.Fatalf("cs_isolate_host must be PreCheck+Reversible(Inverse cs_release_host)+Confirm, got %+v", iso)
	}
	rel, ok := by["cs_release_host"]
	if !ok || rel.Inverse != "cs_isolate_host" || rel.Confirm == nil {
		t.Fatalf("cs_release_host must invert cs_isolate_host with a Confirm")
	}
	// cs_block_hash / cs_allow_hash are now registered (the FleetWide IOC sub-slice); their flags are asserted in
	// TestCrowdStrike_IOC_ContractFlags. cs_kill_process stays DEFERRED (non-reversible / RTR) → MUST remain
	// unregistered so it can never sneak in as auto-runnable or misrouted.
	if _, present := by["cs_kill_process"]; present {
		t.Fatal("cs_kill_process must NOT be registered (deferred: non-reversible, needs RTR)")
	}
}

func TestCrowdStrike_IsolateNormal(t *testing.T) {
	m := &csMock{status: "normal", deviceID: "aid-123"}
	_, fn := csFn(t, csActionerFor(newCSServer(t, m)), "cs_isolate_host")
	creds, _ := json.Marshal(Credentials{})
	ref, prior, err := fn(context.Background(), creds, "host:web-1", nil)
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if m.contain != 1 || prior["changed"] != true {
		t.Fatalf("isolate on normal must contain + changed=true; contain=%d changed=%v", m.contain, prior["changed"])
	}
	if ref != "aid-123" || prior["action_id"] != "aid-123" { // MA-2: bare device id
		t.Fatalf("action_id/ref must be the bare device id aid-123, got ref=%q action_id=%v", ref, prior["action_id"])
	}
}

func TestCrowdStrike_IsolateAlreadyContained_GoalMet(t *testing.T) {
	// D2 fail-safe: already contained / in-flight contain → no call, changed=false (reverse won't lift).
	for _, st := range []string{"contained", "containment_pending"} {
		m := &csMock{status: st, deviceID: "aid-Z"}
		_, fn := csFn(t, csActionerFor(newCSServer(t, m)), "cs_isolate_host")
		creds, _ := json.Marshal(Credentials{})
		_, prior, err := fn(context.Background(), creds, "device:aid-Z", nil)
		if err != nil {
			t.Fatalf("status %s: %v", st, err)
		}
		if m.contain != 0 || prior["changed"] != false {
			t.Fatalf("status %s: must NOT contain again; changed must be false", st)
		}
	}
}

func TestCrowdStrike_CSMA1_IsolateOverLiftPending_ReContains(t *testing.T) {
	// CS-MA1: a host mid-release (lift_containment_pending) that an operator isolates MUST re-contain, not no-op.
	m := &csMock{status: "lift_containment_pending", deviceID: "aid-R"}
	_, fn := csFn(t, csActionerFor(newCSServer(t, m)), "cs_isolate_host")
	creds, _ := json.Marshal(Credentials{})
	_, prior, err := fn(context.Background(), creds, "device:aid-R", nil)
	if err != nil {
		t.Fatalf("isolate over lift_pending: %v", err)
	}
	if m.contain != 1 || prior["changed"] != true {
		t.Fatalf("CS-MA1: isolate over lift_containment_pending must RE-CONTAIN (changed=true, 1 contain call), got contain=%d changed=%v — a no-op here is a fail-OPEN", m.contain, prior["changed"])
	}
}

func TestCrowdStrike_ReleaseFromContained_AndSafeDirections(t *testing.T) {
	// release from contained → lift, changed=true.
	m := &csMock{status: "contained", deviceID: "aid-L"}
	_, fn := csFn(t, csActionerFor(newCSServer(t, m)), "cs_release_host")
	creds, _ := json.Marshal(Credentials{})
	if _, prior, err := fn(context.Background(), creds, "device:aid-L", nil); err != nil || prior["changed"] != true {
		t.Fatalf("release from contained must lift (changed=true), err=%v prior=%v", err, prior)
	}
	if m.lift != 1 {
		t.Fatalf("expected 1 lift, got %d", m.lift)
	}
	// CS-MA1 symmetric: release over containment_pending → no-op (leave heading-to-contained; safe for a release).
	m2 := &csMock{status: "containment_pending", deviceID: "aid-P"}
	_, fn2 := csFn(t, csActionerFor(newCSServer(t, m2)), "cs_release_host")
	if _, prior, err := fn2(context.Background(), creds, "device:aid-P", nil); err != nil || prior["changed"] != false {
		t.Fatalf("release over containment_pending must no-op (changed=false), err=%v prior=%v", err, prior)
	}
	if m2.lift != 0 {
		t.Fatalf("must NOT lift a host heading-to-contained, got %d", m2.lift)
	}
}

func TestCrowdStrike_ConfirmTerminalStates(t *testing.T) {
	m := &csMock{status: "contained", deviceID: "aid-C"}
	iso, _ := csFn(t, csActionerFor(newCSServer(t, m)), "cs_isolate_host")
	creds, _ := json.Marshal(Credentials{})
	done, success, _, err := iso.Confirm(context.Background(), creds, "aid-C")
	if err != nil || !done || !success {
		t.Fatalf("isolate Confirm on contained must be done+success, got done=%v success=%v err=%v", done, success, err)
	}
	// Pending → not terminal.
	m.status = "containment_pending"
	if done, _, _, _ := iso.Confirm(context.Background(), creds, "aid-C"); done {
		t.Fatalf("Confirm on containment_pending must be not-done")
	}
	// Wrong terminal (normal, for an isolate) → done but failed.
	m.status = "normal"
	if done, success, _, _ := iso.Confirm(context.Background(), creds, "aid-C"); !done || success {
		t.Fatalf("isolate Confirm on normal must be done+failed")
	}
}

// ---------------------------------------------------------------------------------------------------------
// IOC block/allow (the FleetWide consumer). Covers: terminal-state PreCheck on indicator existence, bare
// action_id, delete-what-we-made via prior_action_id, and the reverse-composition invariant (a FOREIGN
// indicator is recorded changed=false so ReverseRun — which gates on changed=true — never deletes it).

type iocMock struct {
	existing  string // indicator id present for the hash ("" = none)
	created   int
	deleted   int
	deletedID string
	delete404 bool
}

func newIOCServer(t *testing.T, m *iocMock) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 1800})
	})
	mux.HandleFunc("/iocs/queries/indicators/v1", func(w http.ResponseWriter, r *http.Request) {
		res := []string{}
		if m.existing != "" {
			res = append(res, m.existing)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": res})
	})
	mux.HandleFunc("/iocs/entities/indicators/v1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			m.created++
			m.existing = "ioc-new"
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"id": "ioc-new"}}})
		case http.MethodDelete:
			m.deleted++
			m.deletedID = r.URL.Query().Get("ids")
			if m.delete404 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const testHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 chars = sha256

func TestCrowdStrike_IOC_ContractFlags(t *testing.T) {
	by := map[string]soar.Actioner{}
	for _, ac := range NewCrowdStrikeActioner("x", "i", "s", nil).Actioners() {
		by[ac.Action] = ac
	}
	blk, ok := by["cs_block_hash"]
	if !ok || !blk.PreCheck || !blk.Reversible || blk.Inverse != "cs_allow_hash" {
		t.Fatalf("cs_block_hash must be PreCheck+Reversible(Inverse cs_allow_hash), got %+v", blk)
	}
	if blk.Confirm != nil {
		t.Error("cs_block_hash is synchronous (indicator created immediately) → Confirm must be nil")
	}
	if by["cs_allow_hash"].Inverse != "cs_block_hash" {
		t.Error("cs_allow_hash must invert cs_block_hash")
	}
}

func TestCrowdStrike_IOC_BlockCreatesWhenAbsent(t *testing.T) {
	m := &iocMock{}
	_, fn := csFn(t, csActionerFor(newIOCServer(t, m)), "cs_block_hash")
	creds, _ := json.Marshal(Credentials{})
	ref, prior, err := fn(context.Background(), creds, "sha256:"+testHash, nil)
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if m.created != 1 || prior["changed"] != true {
		t.Fatalf("block on absent indicator must create + changed=true; created=%d changed=%v", m.created, prior["changed"])
	}
	if ref != "ioc-new" || prior["action_id"] != "ioc-new" { // MA-2: bare indicator id
		t.Fatalf("action_id must be the bare indicator id, got ref=%q action_id=%v", ref, prior["action_id"])
	}
}

func TestCrowdStrike_IOC_ForeignIndicator_NotOursNotDeleted(t *testing.T) {
	// THE REVERSE-COMPOSITION INVARIANT. A pre-existing FOREIGN 'prevent' indicator → our block is goal-met with
	// changed=false. ReverseRun gates on changed=true, so the inverse is never invoked → we never delete a
	// fleet-wide block another admin created.
	m := &iocMock{existing: "ioc-foreign"}
	_, fn := csFn(t, csActionerFor(newIOCServer(t, m)), "cs_block_hash")
	creds, _ := json.Marshal(Credentials{})
	_, prior, err := fn(context.Background(), creds, "sha256:"+testHash, nil)
	if err != nil {
		t.Fatalf("block over foreign indicator must not error: %v", err)
	}
	if m.created != 0 {
		t.Fatalf("must NOT create a second indicator when one exists, got created=%d", m.created)
	}
	if prior["changed"] != false {
		t.Fatal("REVERSE-COMPOSITION BREAK: a foreign pre-existing indicator must record changed=false, so " +
			"ReverseRun's changed=true gate never deletes a block we did not create")
	}
}

func TestCrowdStrike_IOC_AllowDeletesExactlyOurIndicator(t *testing.T) {
	// O-3 delete-what-we-made: the reverse keys on prior_action_id (forwarded by ReverseRun from
	// prior_state.action_id) — NOT on whatever indicator currently matches the hash (which could be a foreign
	// one created after ours).
	m := &iocMock{existing: "ioc-someone-elses"}
	_, fn := csFn(t, csActionerFor(newIOCServer(t, m)), "cs_allow_hash")
	creds, _ := json.Marshal(Credentials{})
	_, prior, err := fn(context.Background(), creds, "sha256:"+testHash,
		map[string]any{"reverse_of": "cs_block_hash", "prior_action_id": "ioc-ours"})
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if m.deletedID != "ioc-ours" {
		t.Fatalf("delete-what-we-made VIOLATED: reverse deleted %q but our indicator was ioc-ours — keying on the "+
			"current hash match instead of prior_action_id would delete a foreign indicator", m.deletedID)
	}
	if prior["changed"] != true {
		t.Fatalf("a real delete must record changed=true, got %v", prior["changed"])
	}
}

func TestCrowdStrike_IOC_AllowAlreadyGoneIsNoop(t *testing.T) {
	m := &iocMock{existing: "ioc-x", delete404: true}
	_, fn := csFn(t, csActionerFor(newIOCServer(t, m)), "cs_allow_hash")
	creds, _ := json.Marshal(Credentials{})
	_, prior, err := fn(context.Background(), creds, "sha256:"+testHash, map[string]any{"prior_action_id": "ioc-x"})
	if err != nil {
		t.Fatalf("allow on an already-deleted indicator must not error: %v", err)
	}
	if prior["changed"] != false {
		t.Fatalf("already-gone indicator must be changed=false, got %v", prior["changed"])
	}
}
