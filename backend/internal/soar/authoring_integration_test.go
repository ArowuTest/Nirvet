package soar_test

// #187 slice A — playbook authoring adversarial landing round (DB-gated on NIRVET_TEST_DATABASE_URL). Covers the
// reviewer's list plus his two must-do conditions:
//   - author BFLA: a junior (T1) cannot author a containment playbook.
//   - uncatalogued action → 400 (author-time fail-closed; no silently-un-runnable step).
//   - CONDITION 1 (author-`risk` trap), authoring layer: an author labelling a destructive action risk="low" has
//     that risk OVERWRITTEN to the catalog class on persist — an author cannot store a down-labelled risk.
//   - CONDITION 1, run layer (reviewer's #1 test): the same mislabelled destructive step, under authority=approval
//     (which auto-runs low), STILL lands in pending_approval because the run gate uses the CATALOG class, not the
//     author's label.
//   - global-edit reject: a tenant cannot edit a shipped global playbook (404).
//   - RLS isolation: tenant B cannot update tenant A's playbook.
//   - versioning: update snapshots the prior body and bumps the version.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// statusIs reports whether err is an httpx.APIError carrying the given HTTP status.
func statusIs(err error, status int) bool {
	var ae *httpx.APIError
	return errors.As(err, &ae) && ae.Status == status
}

func authoringSetup(t *testing.T) (*soar.Service, *database.DB, uuid.UUID, context.Context) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tenantSvc := tenant.NewService(tenant.NewRepository(db))
	tn, err := tenantSvc.Create(ctx, tenant.CreateInput{Name: "author-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	svc := soar.NewService(soar.NewRepository(db)).WithAuthorizer(tenantSvc)
	return svc, db, tn.ID, ctx
}

func principal(tid uuid.UUID, role auth.Role) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role, Email: string(role) + "@t.co"}
}

func mgr(tid uuid.UUID) auth.Principal { return principal(tid, auth.RoleSOCManager) }

// stepIn is a convenience for building an authored step.
func stepIn(name, action string, risk soar.RiskClass, approval bool) soar.Step {
	return soar.Step{Name: name, Action: action, Risk: risk, RequiresApproval: approval}
}

func TestAuthoring_JuniorCannotAuthor(t *testing.T) {
	svc, _, tid, ctx := authoringSetup(t)
	_, err := svc.CreatePlaybook(ctx, principal(tid, auth.RoleAnalystT1), tid, soar.PlaybookInput{
		Name: "junk", Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if !statusIs(err, http.StatusForbidden) {
		t.Fatalf("a T1 analyst must not author a playbook; got %v", err)
	}
}

func TestAuthoring_UnknownActionRejected(t *testing.T) {
	svc, _, tid, ctx := authoringSetup(t)
	_, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name: "bad-action", Steps: []soar.Step{stepIn("nope", "totally_not_a_catalog_action", soar.RiskLow, false)},
	})
	if !statusIs(err, http.StatusBadRequest) {
		t.Fatalf("an uncatalogued action must 400 at author time; got %v", err)
	}
}

// CONDITION 1 — authoring layer: author labels a destructive action "low" + no approval; on persist the risk is
// overwritten to the catalog class (isolate_endpoint = high). The author cannot store a down-labelled risk.
func TestAuthoring_RiskRelabelDownIsIgnored(t *testing.T) {
	svc, _, tid, ctx := authoringSetup(t)
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "relabel",
		Steps: []soar.Step{stepIn("sneaky isolate", "isolate_endpoint", soar.RiskLow, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if pb.Steps[0].Risk != soar.RiskHigh {
		t.Fatalf("author's risk='low' must be overwritten to catalog 'high'; got %q", pb.Steps[0].Risk)
	}
	if pb.Steps[0].RequiresApproval {
		t.Fatalf("requires_approval is tighten-only; author set false, must stay false, got true")
	}
}

// CONDITION 1 — run layer (reviewer's headline test): the mislabelled destructive step, under authority=approval
// (which auto-runs low/informational), STILL requires approval because the run gate reads the CATALOG class.
func TestAuthoring_MislabeledDestructiveStillGated(t *testing.T) {
	svc, _, tid, ctx := authoringSetup(t)
	if err := svc.SetAuthority(ctx, principal(tid, auth.RolePlatformAdmin), tid, soar.AuthorityApproval); err != nil {
		t.Fatalf("set authority: %v", err)
	}
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "mislabel-run",
		Steps: []soar.Step{stepIn("isolate", "isolate_endpoint", soar.RiskLow, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	run, err := svc.Run(ctx, principal(tid, auth.RoleSOCManager), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != soar.RunPendingApproval {
		t.Fatalf("a destructive step mislabelled low must NOT auto-run under authority=approval; run status=%q", run.Status)
	}
	if len(run.Steps) != 1 || run.Steps[0].Status != soar.StatusAwaitingApproval {
		t.Fatalf("isolate step must be awaiting approval (catalog high governs, not author 'low'); got %+v", run.Steps)
	}
}

func TestAuthoring_CannotEditGlobalPlaybook(t *testing.T) {
	svc, db, tid, ctx := authoringSetup(t)
	// Find a seeded GLOBAL playbook id (tenant_id NULL). Global rows are readable under any tenant (RLS
	// USING clause allows tenant_id IS NULL).
	var globalID uuid.UUID
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM playbooks WHERE tenant_id IS NULL LIMIT 1`).Scan(&globalID)
	}); err != nil {
		t.Fatalf("no seeded global playbook found: %v", err)
	}
	_, err := svc.UpdatePlaybook(ctx, mgr(tid), tid, globalID, soar.PlaybookInput{
		Name: "hijack", Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if !statusIs(err, http.StatusNotFound) {
		t.Fatalf("editing a global playbook must be 404 (provider-managed); got %v", err)
	}
}

func TestAuthoring_TenantIsolation(t *testing.T) {
	svc, db, tidA, ctx := authoringSetup(t)
	pb, err := svc.CreatePlaybook(ctx, mgr(tidA), tidA, soar.PlaybookInput{
		Name: "A-owned", Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tnB, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "B-" + uuid.NewString()})
	_, err = svc.UpdatePlaybook(ctx, mgr(tnB.ID), tnB.ID, pb.ID, soar.PlaybookInput{
		Name: "steal", Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if !statusIs(err, http.StatusNotFound) {
		t.Fatalf("tenant B must not edit tenant A's playbook; got %v", err)
	}
}

func TestAuthoring_UpdateSnapshotsVersion(t *testing.T) {
	svc, db, tid, ctx := authoringSetup(t)
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name: "versioned", Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.UpdatePlaybook(ctx, mgr(tid), tid, pb.ID, soar.PlaybookInput{
		Name: "versioned v2", Steps: []soar.Step{stepIn("notify", "notify_analyst", soar.RiskLow, false)},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	var version, snaps int
	_ = db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT version FROM playbooks WHERE id=$1`, pb.ID).Scan(&version); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM playbook_versions WHERE playbook_id=$1`, pb.ID).Scan(&snaps)
	})
	if version != 2 {
		t.Fatalf("expected version 2 after one update, got %d", version)
	}
	if snaps < 2 {
		t.Fatalf("expected >=2 version snapshots (v1 create + pre/post update), got %d", snaps)
	}
}
