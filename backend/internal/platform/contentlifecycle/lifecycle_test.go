package contentlifecycle

import (
	"errors"
	"testing"
	"time"
)

func lifecyclePack(version int64, scope, tenant string) VerifiedPack {
	return VerifiedPack{Manifest: Manifest{
		PublisherID: "test-publisher",
		ContentType: "detection_rules",
		Version: version,
		IssuedAt: time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		ContentSHA256: "fixture",
		Scope: scope,
		TenantID: tenant,
	}, Artifacts: []Artifact{{ID: "rule", Kind: "detection_rule", Data: []byte(`{"expression":"event.action == login"}`)}}}
}

func TestLifecycle_QuarantineApproveActivateRollbackDrill(t *testing.T) {
	l := NewLifecycle()
	t0 := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	v1 := lifecyclePack(1, "global", "")
	if err := l.Import(v1, "importer-a", t0); err != nil { t.Fatal(err) }
	if err := l.Approve(v1.Manifest, "approver-b", t0.Add(time.Minute)); err != nil { t.Fatal(err) }
	if err := l.Activate(v1.Manifest, "activator-c", t0.Add(2*time.Minute)); err != nil { t.Fatal(err) }

	v2 := lifecyclePack(2, "global", "")
	if err := l.Import(v2, "importer-a", t0.Add(3*time.Minute)); err != nil { t.Fatal(err) }
	if err := l.Approve(v2.Manifest, "approver-b", t0.Add(4*time.Minute)); err != nil { t.Fatal(err) }
	if err := l.Activate(v2.Manifest, "activator-c", t0.Add(5*time.Minute)); err != nil { t.Fatal(err) }
	active, ok := l.Active("global", "", "detection_rules")
	if !ok || active.Pack.Manifest.Version != 2 { t.Fatalf("want active v2, got %+v", active) }
	if err := l.Rollback(v2.Manifest, "operator-d", t0.Add(6*time.Minute)); err != nil { t.Fatal(err) }
	active, ok = l.Active("global", "", "detection_rules")
	if !ok || active.Pack.Manifest.Version != 1 { t.Fatalf("want rollback to v1, got %+v", active) }

	audit := l.Audit()
	if len(audit) != 7 { t.Fatalf("want 7 audit events, got %d", len(audit)) }
	if audit[0].Action != "import" || audit[len(audit)-1].Action != "rollback" { t.Fatalf("unexpected audit sequence: %+v", audit) }
}

func TestLifecycle_FourEyesRejectsImporterApproval(t *testing.T) {
	l := NewLifecycle()
	pack := lifecyclePack(1, "global", "")
	if err := l.Import(pack, "same-actor", time.Now()); err != nil { t.Fatal(err) }
	if err := l.Approve(pack.Manifest, "same-actor", time.Now()); !errors.Is(err, ErrFourEyesRequired) {
		t.Fatalf("want four-eyes failure, got %v", err)
	}
	if _, ok := l.Active("global", "", "detection_rules"); ok { t.Fatal("unapproved pack became active") }
}

func TestLifecycle_ReplayAndDowngradeRefused(t *testing.T) {
	l := NewLifecycle()
	v2 := lifecyclePack(2, "global", "")
	if err := l.Import(v2, "a", time.Now()); err != nil { t.Fatal(err) }
	if err := l.Approve(v2.Manifest, "b", time.Now()); err != nil { t.Fatal(err) }
	if err := l.Activate(v2.Manifest, "c", time.Now()); err != nil { t.Fatal(err) }
	if err := l.Import(v2, "a", time.Now()); !errors.Is(err, ErrReplay) { t.Fatalf("want replay, got %v", err) }
	v1 := lifecyclePack(1, "global", "")
	if err := l.Import(v1, "a", time.Now()); !errors.Is(err, ErrDowngrade) { t.Fatalf("want downgrade, got %v", err) }
}

func TestLifecycle_TenantScopesAreIsolated(t *testing.T) {
	l := NewLifecycle()
	a := lifecyclePack(1, "tenant", "tenant-a")
	b := lifecyclePack(1, "tenant", "tenant-b")
	for _, tc := range []struct{ p VerifiedPack; importer, approver string }{{a,"a1","a2"},{b,"b1","b2"}} {
		if err := l.Import(tc.p, tc.importer, time.Now()); err != nil { t.Fatal(err) }
		if err := l.Approve(tc.p.Manifest, tc.approver, time.Now()); err != nil { t.Fatal(err) }
		if err := l.Activate(tc.p.Manifest, "padmin", time.Now()); err != nil { t.Fatal(err) }
	}
	ar, aok := l.Active("tenant", "tenant-a", "detection_rules")
	br, bok := l.Active("tenant", "tenant-b", "detection_rules")
	if !aok || !bok || ar.Pack.Manifest.TenantID != "tenant-a" || br.Pack.Manifest.TenantID != "tenant-b" { t.Fatalf("tenant isolation failed: %+v %+v", ar, br) }
}
