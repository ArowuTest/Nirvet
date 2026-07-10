package postureproj_test

// MA-4 population — the projector computes the tenant's posture from incident METADATA and records scalars.
// Proves the counts are correct AND that only metadata crosses (the projector selects no content field; the
// store has no content column — MA4-5 — so nothing content could land even if it tried).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/posture"
	"github.com/ArowuTest/nirvet/internal/postureproj"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func seedIncident(t *testing.T, db *database.DB, tid uuid.UUID, severity string, closedAt, ackedAt, ackDue, resolveDue *time.Time) {
	t.Helper()
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO incidents (id, title, severity, stage, closed_at, acknowledged_at, ack_due_at, resolve_due_at)
			 VALUES ($1, 'seed', $2, 'new', $3, $4, $5, $6)`,
			uuid.New(), severity, closedAt, ackedAt, ackDue, resolveDue)
		return e
	})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
}

func tp(d time.Duration) *time.Time { t := time.Now().Add(d); return &t }

func TestProjector_ComputesMetadataFromIncidents(t *testing.T) {
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()

	tid, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "proj-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	tA := tid.ID

	// inc1: critical, open, UNACKED, ack overdue (ack_due in the past); resolve far in the future.
	seedIncident(t, db, tA, "critical", nil, nil, tp(-2*time.Hour), tp(24*time.Hour))
	// inc2: high, open, acknowledged, SLA BREACHED (resolve_due in the past).
	seedIncident(t, db, tA, "high", nil, tp(-time.Hour), tp(-3*time.Hour), tp(-time.Minute))
	// inc3: medium, open, acknowledged, SLA AT RISK (resolve_due within the 1h window).
	seedIncident(t, db, tA, "medium", nil, tp(-time.Hour), nil, tp(30*time.Minute))
	// inc4: low, CLOSED — must not count as open.
	seedIncident(t, db, tA, "low", tp(-time.Minute), tp(-time.Hour), nil, nil)

	svc := posture.NewService(db)
	if err := postureproj.NewProjector(db, svc).Project(ctx, tA); err != nil {
		t.Fatalf("project: %v", err)
	}

	// Read the projected posture back through the vendor read path.
	admin := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: auth.RolePlatformAdmin}
	rows, err := svc.Fleet(ctx, admin)
	if err != nil {
		t.Fatalf("fleet read: %v", err)
	}
	var p *posture.Posture
	for i := range rows {
		if rows[i].TenantID == tA {
			p = &rows[i]
		}
	}
	if p == nil {
		t.Fatal("projected posture row not found for the tenant")
	}
	if p.OpenTotal != 3 {
		t.Fatalf("open_total: want 3 (inc1-3 open, inc4 closed), got %d", p.OpenTotal)
	}
	if p.OpenCritical != 1 || p.OpenHigh != 1 || p.OpenMedium != 1 || p.OpenLow != 0 {
		t.Fatalf("severity counts wrong: crit=%d high=%d med=%d low=%d", p.OpenCritical, p.OpenHigh, p.OpenMedium, p.OpenLow)
	}
	if p.Unacked != 1 || p.AckOverdue != 1 {
		t.Fatalf("ack state wrong: unacked=%d ack_overdue=%d (want 1,1 from inc1)", p.Unacked, p.AckOverdue)
	}
	if p.SLABreached != 1 || p.SLAAtRisk != 1 {
		t.Fatalf("sla state wrong: breached=%d at_risk=%d (want 1,1 from inc2,inc3)", p.SLABreached, p.SLAAtRisk)
	}
	if p.OldestOpenAt == nil || p.LastActivityAt == nil {
		t.Fatal("oldest_open_at / last_activity_at must be populated when incidents exist")
	}
	// escalated is a deferred metric in slice A (population wired in a follow-on) — must be 0, not garbage.
	if p.Escalated != 0 {
		t.Fatalf("escalated must be 0 in slice A (population deferred), got %d", p.Escalated)
	}
}
