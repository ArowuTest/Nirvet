package detection

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// stageTransitions is the SRS §9.4 detection lifecycle state machine: which target stages are reachable
// from each stage. Emergency deploy (EmergencyDeploy) is the sanctioned bypass to production.
var stageTransitions = map[string]map[string]bool{
	StageDraft:      {StagePeerReview: true, StageRetired: true},
	StagePeerReview: {StageQA: true, StageDraft: true, StageRetired: true},
	StageQA:         {StagePilot: true, StagePeerReview: true, StageRetired: true},
	StagePilot:      {StageProduction: true, StageQA: true, StageRetired: true},
	StageProduction: {StageTuned: true, StageRetired: true},
	StageTuned:      {StageProduction: true, StageRetired: true},
	StageRetired:    {StageDraft: true}, // reopen
}

func validStage(s string) bool {
	switch s {
	case StageDraft, StagePeerReview, StageQA, StagePilot, StageProduction, StageTuned, StageRetired:
		return true
	}
	return false
}

// RuleVersion is a stored snapshot of a rule body at a version (DET-001 rollback).
type RuleVersion struct {
	Version   int             `json:"version"`
	Stage     string          `json:"stage"`
	Note      string          `json:"note"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt string          `json:"created_at,omitempty"`
}

// getRuleTx loads a single tenant-owned rule for lifecycle ops (global rules are provider-managed and
// not tenant-transitionable). Returns nil if not a tenant-owned rule in this tenant.
func (r *Repository) getRuleForUpdate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*Rule, error) {
	var rule Rule
	var cond []byte
	err := tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM detection_rules WHERE id=$1 AND tenant_id IS NOT NULL FOR UPDATE`, id).
		Scan(&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.Severity, &rule.Confidence,
			&rule.MITRE, &cond, &rule.Expression, &rule.Enabled, &rule.CreatedAt,
			&rule.Stage, &rule.Version, &rule.OwnerID, &rule.SourceDependencies,
			&rule.Kind, &rule.WindowSeconds, &rule.Threshold, &rule.EntityField, &rule.DistinctField)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cond, &rule.Condition)
	return &rule, nil
}

// snapshotTx appends a version snapshot of the rule within a tx (append-only history).
func (r *Repository) snapshotTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, rule *Rule, note string, by uuid.UUID) error {
	body, _ := json.Marshal(rule)
	_, err := tx.Exec(ctx,
		`INSERT INTO detection_rule_versions (tenant_id, rule_id, version, stage, snapshot, note, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (rule_id, version) DO NOTHING`,
		tenantID, rule.ID, rule.Version, rule.Stage, body, note, by)
	return err
}

// Transition moves a tenant rule to a new stage per §9.4, bumping the version and snapshotting the prior
// body, atomically. applied=false if the rule is not a tenant-owned rule. bad=true if the transition is
// illegal (distinguished so the caller returns 400 not 404).
func (r *Repository) Transition(ctx context.Context, tenantID, id uuid.UUID, to string, note string, by uuid.UUID, emergency bool) (applied, bad bool, err error) {
	err = r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rule, e := r.getRuleForUpdate(ctx, tx, id)
		if e != nil {
			return e
		}
		if rule == nil {
			return nil // not a tenant rule → applied stays false
		}
		if !emergency && !stageTransitions[rule.Stage][to] {
			bad = true
			return nil
		}
		if emergency && (rule.Stage == StageRetired || to != StageProduction) {
			bad = true
			return nil
		}
		// Snapshot the current version before advancing.
		if e := r.snapshotTx(ctx, tx, tenantID, rule, note, by); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx,
			`UPDATE detection_rules SET stage=$2, version=version+1, last_transition_at=now() WHERE id=$1 AND tenant_id IS NOT NULL`,
			id, to)
		if e != nil {
			return e
		}
		applied = ct.RowsAffected() == 1
		return nil
	})
	return applied, bad, err
}

// SetMetadata sets a tenant rule's owner and declared data-source dependencies (DET-001/009).
func (r *Repository) SetMetadata(ctx context.Context, tenantID, id uuid.UUID, owner *uuid.UUID, deps []string) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if deps == nil {
			deps = []string{}
		}
		ct, e := tx.Exec(ctx,
			`UPDATE detection_rules SET owner_id=$2, source_dependencies=$3 WHERE id=$1 AND tenant_id IS NOT NULL`,
			id, owner, deps)
		if e != nil {
			return e
		}
		applied = ct.RowsAffected() == 1
		return nil
	})
	return applied, err
}

// ListVersions returns a rule's version history (newest first).
func (r *Repository) ListVersions(ctx context.Context, tenantID, id uuid.UUID) ([]RuleVersion, error) {
	var out []RuleVersion
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT version, stage, note, snapshot FROM detection_rule_versions WHERE rule_id=$1 ORDER BY version DESC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v RuleVersion
			var snap []byte
			if err := rows.Scan(&v.Version, &v.Stage, &v.Note, &snap); err != nil {
				return err
			}
			v.Snapshot = json.RawMessage(snap)
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// Rollback restores a tenant rule's body (severity/confidence/mitre/condition/expression) from a prior
// version snapshot, bumping the version (a rollback is itself a new version). applied=false if the rule
// or version is not found.
func (r *Repository) Rollback(ctx context.Context, tenantID, id uuid.UUID, toVersion int, by uuid.UUID) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, e := r.getRuleForUpdate(ctx, tx, id)
		if e != nil || cur == nil {
			return e
		}
		var snap []byte
		e = tx.QueryRow(ctx, `SELECT snapshot FROM detection_rule_versions WHERE rule_id=$1 AND version=$2`, id, toVersion).Scan(&snap)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		var prev Rule
		if e := json.Unmarshal(snap, &prev); e != nil {
			return e
		}
		// Snapshot current before overwriting, then restore the prior body (keep the live stage).
		if e := r.snapshotTx(ctx, tx, tenantID, cur, "pre-rollback", by); e != nil {
			return e
		}
		cond, _ := json.Marshal(prev.Condition)
		ct, e := tx.Exec(ctx,
			`UPDATE detection_rules SET severity=$2, confidence=$3, mitre=$4, condition=$5, expression=$6, version=version+1
			  WHERE id=$1 AND tenant_id IS NOT NULL`,
			id, prev.Severity, prev.Confidence, prev.MITRE, cond, prev.Expression)
		if e != nil {
			return e
		}
		applied = ct.RowsAffected() == 1
		return nil
	})
	return applied, err
}

// ── Service ─────────────────────────────────────────────────────────────────────────────────────────

// Transition advances a rule through the §9.4 lifecycle (DET-006). emergency=true is the sanctioned
// bypass straight to production (DET-010), which the handler restricts to senior roles.
func (s *Service) Transition(ctx context.Context, tenantID, id uuid.UUID, to, note string, by uuid.UUID, emergency bool) error {
	if !emergency && !validStage(to) {
		return httpx.ErrBadRequest("unknown stage")
	}
	// DET-005 promotion gate: a non-emergency promotion to production requires passing test cases
	// (config require_tests_for_production). Emergency deploy is the sanctioned senior-gated bypass.
	if !emergency && to == StageProduction {
		ok, reason, perr := s.promotable(ctx, tenantID, id)
		if perr != nil {
			return httpx.ErrInternal("could not evaluate promotion gate")
		}
		if !ok {
			return httpx.ErrBadRequest(reason)
		}
	}
	applied, bad, err := s.repo.Transition(ctx, tenantID, id, to, note, by, emergency)
	if err != nil {
		return httpx.ErrInternal("could not transition rule")
	}
	if bad {
		return httpx.ErrBadRequest("illegal lifecycle transition")
	}
	if !applied {
		return httpx.ErrNotFound("tenant rule not found")
	}
	s.engine.invalidate(tenantID)
	return nil
}

// SetMetadata sets a rule's owner + declared data-source dependencies (DET-001/009).
func (s *Service) SetMetadata(ctx context.Context, tenantID, id uuid.UUID, owner *uuid.UUID, deps []string) error {
	applied, err := s.repo.SetMetadata(ctx, tenantID, id, owner, deps)
	if err != nil {
		return httpx.ErrInternal("could not set metadata")
	}
	if !applied {
		return httpx.ErrNotFound("tenant rule not found")
	}
	return nil
}

// Versions returns a rule's version history.
func (s *Service) Versions(ctx context.Context, tenantID, id uuid.UUID) ([]RuleVersion, error) {
	return s.repo.ListVersions(ctx, tenantID, id)
}

// Rollback restores a rule body from a prior version (DET-001).
func (s *Service) Rollback(ctx context.Context, tenantID, id uuid.UUID, toVersion int, by uuid.UUID) error {
	applied, err := s.repo.Rollback(ctx, tenantID, id, toVersion, by)
	if err != nil {
		return httpx.ErrInternal("could not roll back rule")
	}
	if !applied {
		return httpx.ErrNotFound("rule or version not found")
	}
	s.engine.invalidate(tenantID)
	return nil
}
