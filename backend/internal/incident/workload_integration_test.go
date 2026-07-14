package incident_test

// B4 manager workload aggregate — DB-gated integration test. Seeds open incidents across two owners plus an
// unassigned bucket (and one CLOSED incident that must be excluded), with past-due / near-due SLA timestamps, and
// asserts the per-owner counts, the derived sla_breached / sla_at_risk, the Unassigned bucket, and the LEFT-JOIN
// email resolution. Skips when no test DSN is configured (testsupport.RequireDSN).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestWorkloadByOwner(t *testing.T) {
	ctx := context.Background()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "wl-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	repo := incident.NewRepository(db)

	ownerA, ownerB := uuid.New(), uuid.New()
	now := time.Now()
	pastDue := now.Add(-time.Hour)       // breached
	soonDue := now.Add(15 * time.Minute) // at-risk (within the 30m window)

	mk := func(tx pgx.Tx, owner *uuid.UUID, sev string, ackDue, resDue, ackAt *time.Time) {
		inc := &incident.Incident{
			ID: uuid.New(), TenantID: tn.ID, Title: "t", Severity: sev, Category: "malware",
			Stage: incident.StageNew, OwnerID: owner, AckDueAt: ackDue, ResolveDueAt: resDue, AcknowledgedAt: ackAt,
		}
		if err := repo.CreateTx(ctx, tx, inc); err != nil {
			t.Fatalf("insert incident: %v", err)
		}
	}

	err = db.WithTenant(ctx, tn.ID, func(ctx context.Context, tx pgx.Tx) error {
		// user row so the LEFT JOIN resolves ownerA's email
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,'x','analyst_t2')`, ownerA, "a@corp.test"); err != nil {
			return err
		}
		mk(tx, &ownerA, "critical", nil, &pastDue, nil) // ownerA: breached (resolve past due)
		mk(tx, &ownerA, "high", nil, nil, nil)          // ownerA: plain open
		mk(tx, &ownerB, "medium", &soonDue, nil, nil)   // ownerB: at-risk (ack due in 15m, unacked)
		mk(tx, nil, "critical", nil, nil, nil)          // unassigned: open critical
		// closed incident (must be excluded from the open aggregate)
		closedID := uuid.New()
		if err := repo.CreateTx(ctx, tx, &incident.Incident{ID: closedID, TenantID: tn.ID, Title: "c", Severity: "low", Category: "malware", Stage: incident.StageNew, OwnerID: &ownerA}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE incidents SET closed_at = now() WHERE id = $1`, closedID)
		return err
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, err := repo.WorkloadByOwner(ctx, tn.ID)
	if err != nil {
		t.Fatalf("workload: %v", err)
	}

	byOwner := map[string]incident.WorkloadRow{}
	for _, r := range rows {
		key := "unassigned"
		if r.OwnerID != nil {
			key = r.OwnerID.String()
		}
		byOwner[key] = r
	}
	if len(byOwner) != 3 {
		t.Fatalf("want 3 buckets (A, B, unassigned), got %d: %+v", len(byOwner), rows)
	}

	a := byOwner[ownerA.String()]
	if a.OpenTotal != 2 || a.OpenCritical != 1 || a.OpenHigh != 1 || a.SLABreached != 1 {
		t.Fatalf("ownerA aggregate wrong: %+v", a)
	}
	if a.OwnerEmail != "a@corp.test" {
		t.Fatalf("ownerA email not resolved: %q", a.OwnerEmail)
	}

	b := byOwner[ownerB.String()]
	if b.OpenTotal != 1 || b.SLAAtRisk != 1 || b.SLABreached != 0 {
		t.Fatalf("ownerB aggregate wrong: %+v", b)
	}

	un := byOwner["unassigned"]
	if un.OwnerID != nil || un.OpenTotal != 1 || un.OpenCritical != 1 || un.OwnerEmail != "" {
		t.Fatalf("unassigned bucket wrong: %+v", un)
	}
}
