package ai

// §6.12 AI Governance slice A — persistence. Prompt registry + eval suite/runs/results are PLATFORM-GLOBAL
// content (no tenant dimension) → WithSystem. Output feedback is TENANT-scoped (RLS) → WithTenant.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GovRepo persists the AI-governance surfaces.
type GovRepo struct{ db *database.DB }

// NewGovRepo builds the repository.
func NewGovRepo(db *database.DB) *GovRepo { return &GovRepo{db: db} }

// errNotFound is returned when a prompt/version/run is absent.
var errGovNotFound = errors.New("not found")

// --- prompts (global) ---

// ListPrompts returns all prompts with their active version number (0 = none).
func (r *GovRepo) ListPrompts(ctx context.Context) ([]Prompt, error) {
	var out []Prompt
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT p.id, p.key, p.title, p.description, p.purpose, p.created_at,
			       COALESCE((SELECT v.version FROM ai_prompt_version v WHERE v.prompt_id = p.id AND v.status='active'), 0)
			FROM ai_prompt p ORDER BY p.key`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p Prompt
			if e := rows.Scan(&p.ID, &p.Key, &p.Title, &p.Description, &p.Purpose, &p.CreatedAt, &p.ActiveVersion); e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// CreatePrompt inserts a prompt (idempotent on key) and returns its id.
func (r *GovRepo) CreatePrompt(ctx context.Context, key, title string, purpose PromptPurpose, desc string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO ai_prompt (key, title, purpose, description) VALUES ($1,$2,$3,$4)
			ON CONFLICT (key) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description
			RETURNING id`, key, title, string(purpose), desc).Scan(&id)
	})
	return id, err
}

// promptIDByKey resolves a prompt id inside an existing tx.
func promptIDByKey(ctx context.Context, tx pgx.Tx, key string) (uuid.UUID, error) {
	var id uuid.UUID
	e := tx.QueryRow(ctx, `SELECT id FROM ai_prompt WHERE key=$1`, key).Scan(&id)
	if e == pgx.ErrNoRows {
		return uuid.Nil, errGovNotFound
	}
	return id, e
}

// ListVersions returns a prompt's versions (newest first).
func (r *GovRepo) ListVersions(ctx context.Context, key string) ([]PromptVersion, error) {
	var out []PromptVersion
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		pid, e := promptIDByKey(ctx, tx, key)
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT id, prompt_id, version, body, model, status, notes, created_by, created_at
			FROM ai_prompt_version WHERE prompt_id=$1 ORDER BY version DESC`, pid)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v PromptVersion
			if e := rows.Scan(&v.ID, &v.PromptID, &v.Version, &v.Body, &v.Model, &v.Status, &v.Notes, &v.CreatedBy, &v.CreatedAt); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// AddVersion inserts a new DRAFT version (version = max+1) and returns it.
func (r *GovRepo) AddVersion(ctx context.Context, key, body, model, notes string, createdBy *uuid.UUID) (PromptVersion, error) {
	var v PromptVersion
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		pid, e := promptIDByKey(ctx, tx, key)
		if e != nil {
			return e
		}
		var next int
		if e := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM ai_prompt_version WHERE prompt_id=$1`, pid).Scan(&next); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `INSERT INTO ai_prompt_version (prompt_id, version, body, model, status, notes, created_by)
			VALUES ($1,$2,$3,$4,'draft',$5,$6)
			RETURNING id, prompt_id, version, body, model, status, notes, created_by, created_at`,
			pid, next, body, model, notes, createdBy).
			Scan(&v.ID, &v.PromptID, &v.Version, &v.Body, &v.Model, &v.Status, &v.Notes, &v.CreatedBy, &v.CreatedAt)
	})
	return v, err
}

// ActivateVersion archives the current active version (if any) and activates the target — atomically, so the
// "one active per prompt" partial-unique index is never violated mid-flight.
func (r *GovRepo) ActivateVersion(ctx context.Context, key string, version int) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		pid, e := promptIDByKey(ctx, tx, key)
		if e != nil {
			return e
		}
		// Archive the previous active FIRST (frees the partial-unique slot), then activate the target.
		if _, e := tx.Exec(ctx, `UPDATE ai_prompt_version SET status='archived'
			WHERE prompt_id=$1 AND status='active' AND version<>$2`, pid, version); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE ai_prompt_version SET status='active' WHERE prompt_id=$1 AND version=$2`, pid, version)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return errGovNotFound
		}
		return nil
	})
}

// activePromptBody returns the active version's body + number for a prompt id (inside a tx).
func activePromptBody(ctx context.Context, tx pgx.Tx, promptID uuid.UUID) (string, int, bool, error) {
	var body string
	var version int
	e := tx.QueryRow(ctx, `SELECT body, version FROM ai_prompt_version WHERE prompt_id=$1 AND status='active'`, promptID).Scan(&body, &version)
	if e == pgx.ErrNoRows {
		return "", 0, false, nil
	}
	if e != nil {
		return "", 0, false, e
	}
	return body, version, true, nil
}

// ActivePrompt resolves a prompt key to its id + active version body/number. ok=false when the key is unknown
// or has no active version.
func (r *GovRepo) ActivePrompt(ctx context.Context, key string) (promptID uuid.UUID, version int, body string, ok bool, err error) {
	err = r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		pid, e := promptIDByKey(ctx, tx, key)
		if e == errGovNotFound {
			return nil
		}
		if e != nil {
			return e
		}
		promptID = pid
		body, version, ok, e = activePromptBody(ctx, tx, pid)
		return e
	})
	return promptID, version, body, ok, err
}

// --- eval cases (global) ---

// ListCases returns the enabled cases in a suite.
func (r *GovRepo) ListCases(ctx context.Context, suite string) ([]EvalCase, error) {
	var out []EvalCase
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, suite, name, category, context_json, question, expected_json, enabled
			FROM ai_eval_case WHERE suite=$1 AND enabled ORDER BY name`, suite)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c EvalCase
			var ctxRaw, expRaw []byte
			if e := rows.Scan(&c.ID, &c.Suite, &c.Name, &c.Category, &ctxRaw, &c.Question, &expRaw, &c.Enabled); e != nil {
				return e
			}
			c.Context = json.RawMessage(ctxRaw)
			if len(expRaw) > 0 {
				if e := json.Unmarshal(expRaw, &c.Expected); e != nil {
					return e
				}
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// --- eval runs (global) ---

// SaveRun persists a completed run header + its per-case results in one tx, returning the run id.
func (r *GovRepo) SaveRun(ctx context.Context, run EvalRun) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `INSERT INTO ai_eval_run
			(suite, prompt_id, prompt_version, judge, total, passed, failed, pass_rate, created_by, started_at, finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
			run.Suite, run.PromptID, run.PromptVersion, run.Judge, run.Total, run.Passed, run.Failed, run.PassRate,
			run.CreatedBy, run.StartedAt, run.FinishedAt).Scan(&id); e != nil {
			return e
		}
		for _, res := range run.Results {
			if _, e := tx.Exec(ctx, `INSERT INTO ai_eval_result (run_id, case_id, category, passed, score, rationale)
				VALUES ($1,$2,$3,$4,$5,$6)`, id, res.CaseID, string(res.Category), res.Passed, res.Score, res.Rationale); e != nil {
				return e
			}
		}
		return nil
	})
	return id, err
}

// ListRuns returns recent run headers (no per-case results).
func (r *GovRepo) ListRuns(ctx context.Context, limit int) ([]EvalRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []EvalRun
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, suite, prompt_id, prompt_version, judge, total, passed, failed, pass_rate,
			created_by, started_at, finished_at FROM ai_eval_run ORDER BY started_at DESC LIMIT $1`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var run EvalRun
			if e := rows.Scan(&run.ID, &run.Suite, &run.PromptID, &run.PromptVersion, &run.Judge, &run.Total,
				&run.Passed, &run.Failed, &run.PassRate, &run.CreatedBy, &run.StartedAt, &run.FinishedAt); e != nil {
				return e
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	return out, err
}

// GetRun returns a run header + its per-case results.
func (r *GovRepo) GetRun(ctx context.Context, id uuid.UUID) (EvalRun, bool, error) {
	var run EvalRun
	found := false
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT id, suite, prompt_id, prompt_version, judge, total, passed, failed, pass_rate,
			created_by, started_at, finished_at FROM ai_eval_run WHERE id=$1`, id).
			Scan(&run.ID, &run.Suite, &run.PromptID, &run.PromptVersion, &run.Judge, &run.Total, &run.Passed,
				&run.Failed, &run.PassRate, &run.CreatedBy, &run.StartedAt, &run.FinishedAt)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		rows, e := tx.Query(ctx, `SELECT r.case_id, c.name, r.category, r.passed, r.score, r.rationale
			FROM ai_eval_result r JOIN ai_eval_case c ON c.id=r.case_id WHERE r.run_id=$1 ORDER BY c.name`, id)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var res EvalResult
			if e := rows.Scan(&res.CaseID, &res.Name, &res.Category, &res.Passed, &res.Score, &res.Rationale); e != nil {
				return e
			}
			run.Results = append(run.Results, res)
		}
		return rows.Err()
	})
	return run, found, err
}

// --- feedback (tenant-scoped) ---

// AddFeedback records a §11 label on a copilot output.
func (r *GovRepo) AddFeedback(ctx context.Context, tenantID uuid.UUID, outputRef string, label FeedbackLabel, note string, createdBy *uuid.UUID) (Feedback, error) {
	var f Feedback
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO ai_output_feedback (tenant_id, output_ref, label, note, created_by)
			VALUES ($1,$2,$3,$4,$5) RETURNING id, output_ref, label, note, created_by, created_at`,
			tenantID, outputRef, string(label), note, createdBy).
			Scan(&f.ID, &f.OutputRef, &f.Label, &f.Note, &f.CreatedBy, &f.CreatedAt)
	})
	return f, err
}

// ListFeedback returns feedback for an output (own tenant).
func (r *GovRepo) ListFeedback(ctx context.Context, tenantID uuid.UUID, outputRef string) ([]Feedback, error) {
	var out []Feedback
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, output_ref, label, note, created_by, created_at
			FROM ai_output_feedback WHERE output_ref=$1 ORDER BY created_at DESC`, outputRef)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var f Feedback
			if e := rows.Scan(&f.ID, &f.OutputRef, &f.Label, &f.Note, &f.CreatedBy, &f.CreatedAt); e != nil {
				return e
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// nowPtr is a small helper for run finish timestamps (kept here so the service stays thin).
func nowPtr() *time.Time { t := time.Now(); return &t }
