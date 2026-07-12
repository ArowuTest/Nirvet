package soar

// Authoring persistence (#187 slice A). All writes are tenant-owned only — the WHERE clauses pin `tenant_id IS
// NOT NULL` (a tenant can never mutate a global/shipped playbook) and RLS WITH CHECK pins the row to the current
// tenant. Body change + version snapshot + audit commit in ONE tx (effect + trail atomic, like the run path).

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// snapshotPlaybookTx appends an immutable version snapshot of a playbook's body.
func (r *Repository) snapshotPlaybookTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, pb *Playbook, version int, note string, by uuid.UUID) error {
	steps, _ := json.Marshal(pb.Steps)
	_, err := tx.Exec(ctx,
		`INSERT INTO playbook_versions (tenant_id, playbook_id, version, name, description, trigger_category, steps, note, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (tenant_id, playbook_id, version) DO NOTHING`,
		tenantID, pb.ID, version, pb.Name, pb.Description, pb.TriggerCategory, steps, note, by)
	return err
}

// CreatePlaybookTx inserts a tenant-owned playbook (version 1), snapshots v1, and audits — atomically.
func (r *Repository) CreatePlaybookTx(ctx context.Context, tenantID uuid.UUID, pb *Playbook, p auth.Principal) error {
	steps, _ := json.Marshal(pb.Steps)
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO playbooks (id, tenant_id, name, description, trigger_category, steps, enabled, version)
			 VALUES ($1,$2,$3,$4,$5,$6,true,1)`,
			pb.ID, tenantID, pb.Name, pb.Description, pb.TriggerCategory, steps); err != nil {
			return err
		}
		if err := r.snapshotPlaybookTx(ctx, tx, tenantID, pb, 1, "create", p.UserID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.playbook_create",
			Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"name": pb.Name, "steps": len(pb.Steps)}})
	})
}

// UpdatePlaybookTx replaces a tenant-owned playbook's body, bumping the version and snapshotting the prior body
// FIRST (append-only history), then audits — atomically. found=false if the id is not a tenant-owned playbook in
// this tenant (a global playbook or another tenant's is invisible under RLS + the tenant_id IS NOT NULL guard).
func (r *Repository) UpdatePlaybookTx(ctx context.Context, tenantID uuid.UUID, pb *Playbook, p auth.Principal) (bool, error) {
	found := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Load + lock the current row; snapshot its PRIOR body before overwriting.
		var curVersion int
		var curName, curDesc, curTrig string
		var curSteps []byte
		e := tx.QueryRow(ctx,
			`SELECT version, name, description, trigger_category, steps FROM playbooks
			  WHERE id=$1 AND tenant_id IS NOT NULL FOR UPDATE`, pb.ID).
			Scan(&curVersion, &curName, &curDesc, &curTrig, &curSteps)
		if e == pgx.ErrNoRows {
			return nil // not a tenant-owned playbook here → found stays false
		}
		if e != nil {
			return e
		}
		prior := &Playbook{ID: pb.ID, Name: curName, Description: curDesc, TriggerCategory: curTrig}
		_ = json.Unmarshal(curSteps, &prior.Steps)
		if e := r.snapshotPlaybookTx(ctx, tx, tenantID, prior, curVersion, "pre-update", p.UserID); e != nil {
			return e
		}
		newSteps, _ := json.Marshal(pb.Steps)
		ct, e := tx.Exec(ctx,
			`UPDATE playbooks SET name=$2, description=$3, trigger_category=$4, steps=$5, version=version+1, updated_at=now()
			  WHERE id=$1 AND tenant_id IS NOT NULL`,
			pb.ID, pb.Name, pb.Description, pb.TriggerCategory, newSteps)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return nil
		}
		found = true
		// Snapshot the NEW body under the bumped version too, so the history has the current state.
		if e := r.snapshotPlaybookTx(ctx, tx, tenantID, pb, curVersion+1, "update", p.UserID); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.playbook_update",
			Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"name": pb.Name, "version": curVersion + 1, "steps": len(pb.Steps)}})
	})
	return found, err
}

// SetPlaybookEnabledTx toggles a tenant-owned playbook and audits. found=false if not a tenant playbook here.
func (r *Repository) SetPlaybookEnabledTx(ctx context.Context, tenantID, id uuid.UUID, enabled bool, p auth.Principal) (bool, error) {
	found := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE playbooks SET enabled=$2, updated_at=now() WHERE id=$1 AND tenant_id IS NOT NULL`, id, enabled)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return nil
		}
		found = true
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.playbook_set_enabled",
			Target: "playbook:" + id.String(), Metadata: map[string]any{"enabled": enabled}})
	})
	return found, err
}
