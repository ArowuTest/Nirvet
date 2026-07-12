package incident

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Repository persists incidents and timeline entries (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// CreateTx inserts an incident within an existing transaction.
func (r *Repository) CreateTx(ctx context.Context, tx pgx.Tx, i *Incident) error {
	return tx.QueryRow(ctx,
		`INSERT INTO incidents (id, tenant_id, title, severity, category, stage, owner_id,
		                        acknowledged_at, ack_due_at, resolve_due_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`,
		i.ID, i.TenantID, i.Title, i.Severity, i.Category, i.Stage, i.OwnerID,
		i.AcknowledgedAt, i.AckDueAt, i.ResolveDueAt,
	).Scan(&i.CreatedAt)
}

// AddTimelineTx inserts a timeline entry within an existing transaction. An unset visibility defaults
// to internal (CASE-004) so nothing becomes customer-visible by accident.
func (r *Repository) AddTimelineTx(ctx context.Context, tx pgx.Tx, e *TimelineEntry) error {
	if e.Visibility == "" {
		e.Visibility = VisibilityInternal
	}
	return tx.QueryRow(ctx,
		`INSERT INTO incident_timeline (id, incident_id, author, kind, visibility, note)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING at`,
		e.ID, e.IncidentID, e.Author, e.Kind, e.Visibility, e.Note,
	).Scan(&e.At)
}

// Transition applies a stage change atomically: it moves the incident from `from`→`to` (only if it
// is still at `from` — optimistic concurrency, so two concurrent transitions can't both apply),
// writes the closure columns when a ClosureInput is supplied (CASE-009), appends the timeline entry,
// and records the audit row — all in one tenant tx (house rule: state + timeline + audit together).
// Returns applied=false when the row was not at `from` (changed concurrently / not found).
func (r *Repository) Transition(ctx context.Context, tenantID, id uuid.UUID, from, to Stage, closure *ClosureInput, entry *TimelineEntry, auditEntry audit.Entry) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// closed_at is set on entering 'closed', cleared on reopen (→investigating), preserved otherwise.
		var ct pgconn.CommandTag
		var e error
		if closure != nil {
			ct, e = tx.Exec(ctx,
				`UPDATE incidents SET stage=$3,
				   closed_at = CASE WHEN $3='closed' THEN now() WHEN $3='investigating' THEN NULL ELSE closed_at END,
				   disposition=$4, root_cause=$5, impact=$6, actions_taken=$7, lessons_learned=$8, customer_ack=$9
				 WHERE id=$1 AND stage=$2`,
				id, from, to, string(closure.Disposition), closure.RootCause, closure.Impact,
				closure.ActionsTaken, closure.LessonsLearned, closure.CustomerAck)
		} else {
			ct, e = tx.Exec(ctx,
				`UPDATE incidents SET stage=$3,
				   closed_at = CASE WHEN $3='closed' THEN now() WHEN $3='investigating' THEN NULL ELSE closed_at END
				 WHERE id=$1 AND stage=$2`, id, from, to)
		}
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return nil // not at `from` anymore — applied stays false
		}
		applied = true
		if e := r.AddTimelineTx(ctx, tx, entry); e != nil {
			return e
		}
		return audit.Record(ctx, tx, auditEntry)
	})
	return applied, err
}

// List returns incidents for a tenant.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	var out []Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at,
			        acknowledged_at, ack_due_at, resolve_due_at
			   FROM incidents ORDER BY created_at DESC LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Incident
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category,
				&i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt,
				&i.AcknowledgedAt, &i.AckDueAt, &i.ResolveDueAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// ListAtRisk returns open incidents that are already breaching, or due within the next
// 30 minutes, ordered by the nearest deadline first — the SLA "at-risk" queue (§6.8).
// Tenant-scoped via RLS.
func (r *Repository) ListAtRisk(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	var out []Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at,
			        acknowledged_at, ack_due_at, resolve_due_at
			   FROM incidents
			  WHERE closed_at IS NULL
			    AND (
			      (ack_due_at IS NOT NULL AND acknowledged_at IS NULL AND ack_due_at < now() + interval '30 minutes')
			      OR (resolve_due_at IS NOT NULL AND resolve_due_at < now() + interval '30 minutes')
			    )
			  ORDER BY COALESCE(resolve_due_at, ack_due_at) ASC
			  LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Incident
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category,
				&i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt,
				&i.AcknowledgedAt, &i.AckDueAt, &i.ResolveDueAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// GetByIDs returns incidents by id in one query (avoids the entity-graph N+1 —
// R2 M-E). Tenant-scoped via RLS; ids cast text[]->uuid[] for portable binding.
func (r *Repository) GetByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Incident, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	var out []Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at,
			        acknowledged_at, ack_due_at, resolve_due_at
			   FROM incidents WHERE id = ANY($1::uuid[])`, strs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Incident
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category,
				&i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt,
				&i.AcknowledgedAt, &i.AckDueAt, &i.ResolveDueAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one incident, including the closure-criteria fields (CASE-009) for the detail view.
func (r *Repository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Incident, error) {
	var i Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at,
			        acknowledged_at, ack_due_at, resolve_due_at,
			        disposition, root_cause, impact, actions_taken, lessons_learned, customer_ack,
			        parent_id, is_major
			   FROM incidents WHERE id=$1`, id,
		).Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category, &i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt,
			&i.AcknowledgedAt, &i.AckDueAt, &i.ResolveDueAt,
			&i.Disposition, &i.RootCause, &i.Impact, &i.ActionsTaken, &i.LessonsLearned, &i.CustomerAck,
			&i.ParentID, &i.IsMajor)
	})
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ListTimeline returns an incident's full timeline (internal + customer entries).
func (r *Repository) ListTimeline(ctx context.Context, tenantID, id uuid.UUID) ([]TimelineEntry, error) {
	return r.listTimeline(ctx, tenantID, id, "")
}

// ListCustomerTimeline returns ONLY the customer-visible entries (CASE-004) — the seam a customer
// portal reads, so analyst-only notes can never leak, enforced at query time.
func (r *Repository) ListCustomerTimeline(ctx context.Context, tenantID, id uuid.UUID) ([]TimelineEntry, error) {
	return r.listTimeline(ctx, tenantID, id, VisibilityCustomer)
}

func (r *Repository) listTimeline(ctx context.Context, tenantID, id uuid.UUID, visibility string) ([]TimelineEntry, error) {
	var out []TimelineEntry
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := `SELECT id, incident_id, at, author, kind, visibility, note FROM incident_timeline
		       WHERE incident_id=$1`
		args := []any{id}
		if visibility != "" {
			q += ` AND visibility=$2`
			args = append(args, visibility)
		}
		q += ` ORDER BY at ASC`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e TimelineEntry
			if err := rows.Scan(&e.ID, &e.IncidentID, &e.At, &e.Author, &e.Kind, &e.Visibility, &e.Note); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// AddNote appends a note to an incident's timeline.
func (r *Repository) AddNote(ctx context.Context, tenantID uuid.UUID, e *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return r.AddTimelineTx(ctx, tx, e)
	})
}

// Assign sets an incident's owner (analyst) and records a timeline entry. If the
// incident is still in an early stage it advances to 'investigating' so the case
// visibly moves once someone owns it. Runs atomically under the tenant context.
func (r *Repository) Assign(ctx context.Context, tenantID, id, ownerID uuid.UUID, e *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE incidents
			    SET owner_id = $2,
			        acknowledged_at = COALESCE(acknowledged_at, now()),
			        stage = CASE WHEN stage IN ('new','triage') THEN 'investigating' ELSE stage END
			  WHERE id = $1 AND stage <> 'closed'`, id, ownerID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return r.AddTimelineTx(ctx, tx, e)
	})
}

// SLABreach is an un-notified SLA deadline breach (ack or resolve) surfaced by the
// cross-tenant sweeper.
type SLABreach struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Title    string
	Severity string
	Category string // #188 incident category, for category-scoped escalation routing
	Kind     string // "ack" | "resolve"
}

// FindSLABreaches returns un-notified ack/resolve breaches across tenants as of now.
// It runs at the system level via the SECURITY DEFINER incidents_sla_breaches
// function because incidents has RLS FORCEd and the provider sweeper spans tenants.
func (r *Repository) FindSLABreaches(ctx context.Context, now time.Time, limit int) ([]SLABreach, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var out []SLABreach
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, breach_kind FROM incidents_sla_breaches($1, $2)`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b SLABreach
			if err := rows.Scan(&b.ID, &b.TenantID, &b.Title, &b.Severity, &b.Category, &b.Kind); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// ClaimBreachTx atomically claims a breach and, ONLY for the winning caller, records the
// timeline entry and runs onClaim (durably enqueues the notification) in the SAME tenant
// transaction. This keeps the R2 exactly-once dedupe (the conditional marker elects one
// winner) while making delivery durable: the outbox row commits with the claim, so a
// transient notifier failure can never drop the notification — the dispatcher retries it
// (R3 §6.5). A lost claim returns (false, nil); onClaim may be nil (no enqueuer wired).
func (r *Repository) ClaimBreachTx(ctx context.Context, tenantID, id uuid.UUID, kind string, note *TimelineEntry, onClaim func(ctx context.Context, tx pgx.Tx) error) (bool, error) {
	col := "resolve_breach_notified_at"
	if kind == "ack" {
		col = "ack_breach_notified_at"
	}
	claimed := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE incidents SET `+col+` = now() WHERE id = $1 AND `+col+` IS NULL`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return nil // another sweeper won the claim; not an error
		}
		claimed = true
		if err := r.AddTimelineTx(ctx, tx, note); err != nil {
			return err
		}
		if onClaim != nil {
			return onClaim(ctx, tx)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return claimed, nil
}

// CreateWithSeed atomically creates an incident and seeds its timeline. Used for
// system-opened incidents (e.g. auto-promoted from a high-risk correlation) that
// are not tied to a single alert.
func (r *Repository) CreateWithSeed(ctx context.Context, tenantID uuid.UUID, i *Incident, seed *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.CreateTx(ctx, tx, i); err != nil {
			return err
		}
		seed.IncidentID = i.ID
		return r.AddTimelineTx(ctx, tx, seed)
	})
}

// CreateFromAlertTx runs the promote-to-incident write atomically: create the
// incident, mark the alert promoted, and seed the timeline. The caller supplies
// a promote callback so the alert repo stays the owner of its own table.
func (r *Repository) CreateFromAlertTx(ctx context.Context, tenantID uuid.UUID, i *Incident, seed *TimelineEntry, promote func(ctx context.Context, tx pgx.Tx, incidentID uuid.UUID) error) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.CreateTx(ctx, tx, i); err != nil {
			return err
		}
		if err := promote(ctx, tx, i.ID); err != nil {
			return err
		}
		seed.IncidentID = i.ID
		return r.AddTimelineTx(ctx, tx, seed)
	})
}
