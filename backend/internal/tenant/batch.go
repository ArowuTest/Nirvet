package tenant

// Bulk onboarding factory (Ghana launch long-pole) — batch-create up to maxBatchRows tenants, each via the SAME
// secure atomic path as single-create (CreateSeeded → secure defaults + fail-closed governance in ONE tx per
// tenant). The security properties baked in:
//   - secure-defaults-by-reuse: no separate "bulk" shortcut — build()+CreateSeeded are the single-create path;
//   - no cross-tenant bleed: each row's writes are scoped to its OWN tenant_id (CreateSeeded runs under
//     WithTenant(row.ID)); the loop never shares a tx or GUC across rows;
//   - per-row failure isolation: a bad/duplicate row is reported and the rest still create;
//   - idempotency (ONB-2): external_ref is required and DB-unique, so a re-submitted (or concurrently
//     double-submitted) batch collides at the DB layer and is reported skipped — a retried onboarding converges.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// maxBatchRows is the ONB-3 hard server-side cap for a synchronous batch; an async job for very large batches
// is a documented follow-on.
const maxBatchRows = 100

// BatchRow is one tenant to onboard. ExternalRef (the operator's MDA id) is REQUIRED — it is the idempotency
// key enforced by the DB unique index (ONB-2).
type BatchRow struct {
	Name          string        `json:"name"`
	Sector        string        `json:"sector"`
	Country       string        `json:"country"`
	ServiceTier   ServiceTier   `json:"service_tier"`
	IsolationTier IsolationTier `json:"isolation_tier"`
	ExternalRef   string        `json:"external_ref"`
}

// BatchRowResult is the per-row outcome.
type BatchRowResult struct {
	ExternalRef string     `json:"external_ref"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Status      string     `json:"status"` // created | skipped_duplicate | failed
	Error       string     `json:"error,omitempty"`
}

// BatchResult is the whole-batch report (best-effort per row; the call itself only errors on a bad envelope).
type BatchResult struct {
	Results []BatchRowResult `json:"results"`
	Created int              `json:"created"`
	Skipped int              `json:"skipped"`
	Failed  int              `json:"failed"`
}

// CreateBatch onboards a batch of tenants. Per-row: validate → build (shared secure path) → CreateSeeded
// (atomic create+governance). A duplicate external_ref (in-request or already in the DB) is reported skipped,
// an invalid row is reported failed, and neither aborts the rest.
func (s *Service) CreateBatch(ctx context.Context, rows []BatchRow) (*BatchResult, error) {
	if len(rows) == 0 {
		return nil, httpx.ErrBadRequest("batch is empty")
	}
	if len(rows) > maxBatchRows {
		return nil, httpx.ErrBadRequest(fmt.Sprintf("batch too large (max %d tenants per request)", maxBatchRows))
	}
	res := &BatchResult{Results: make([]BatchRowResult, 0, len(rows))}
	seen := map[string]bool{} // within-request dedup so an in-batch repeat is skipped, not a DB race
	for _, row := range rows {
		rr := BatchRowResult{ExternalRef: strings.TrimSpace(row.ExternalRef)}
		switch {
		case rr.ExternalRef == "":
			rr.Status, rr.Error = "failed", "external_ref is required"
			res.Failed++
		case seen[rr.ExternalRef]:
			rr.Status = "skipped_duplicate"
			res.Skipped++
		default:
			seen[rr.ExternalRef] = true
			s.createOneBatchRow(ctx, row, &rr, res)
		}
		res.Results = append(res.Results, rr)
	}
	return res, nil
}

// createOneBatchRow builds + creates a single row, classifying the outcome onto rr/res. A unique violation on
// external_ref is a skipped duplicate (idempotent), not a failure.
func (s *Service) createOneBatchRow(ctx context.Context, row BatchRow, rr *BatchRowResult, res *BatchResult) {
	t, err := s.build(CreateInput{
		Name: row.Name, Sector: row.Sector, Country: row.Country,
		ServiceTier: row.ServiceTier, IsolationTier: row.IsolationTier,
	}, rr.ExternalRef)
	if err != nil {
		rr.Status, rr.Error = "failed", err.Error()
		res.Failed++
		return
	}
	if err := s.repo.CreateSeeded(ctx, t); err != nil {
		if isDuplicateExternalRef(err) {
			rr.Status = "skipped_duplicate"
			res.Skipped++
			return
		}
		rr.Status, rr.Error = "failed", "could not create tenant"
		res.Failed++
		return
	}
	id := t.ID
	rr.TenantID, rr.Status = &id, "created"
	res.Created++
}

// isDuplicateExternalRef reports whether err is specifically a duplicate external_ref collision (SQLSTATE 23505
// on the tenants_external_ref_uniq index) — the ONLY case that is an idempotent skip. Matching the exact
// constraint (not "any 23505") means a future unique constraint on tenants can never be silently mis-reported
// as a skipped duplicate; it would surface as a real failure instead (LOW-ONB).
func isDuplicateExternalRef(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "tenants_external_ref_uniq"
}
