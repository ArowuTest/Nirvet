package reporting

// §6.13 #173 Reporting slice B — report-approval workflow. A review-required report (per report_review_policy) is
// generated 'ready' but 'pending_review'; it becomes releasable only when a SECOND, senior actor approves it. This
// reuses the platform's existing controls — RLS tenant confinement (repo.Get), the auth role ladder (RoleRank), and
// the four-eyes separation-of-duties already used by SOAR run approval — so it adds NO new security surface:
//   - separation of duties: the creator of a report may NOT review it (creator ≠ approver);
//   - seniority floor: only a soc_manager (or higher) may approve/reject or view the queue;
//   - atomic state guard: the transition fires only from 'pending_review' (WHERE-guarded), so a double-approval or
//     approve-after-reject is a no-op → 409, never a silent re-decision;
//   - the approve/reject + its audit row commit in ONE transaction, so an approval can never outrun its audit trail.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// reviewApproverFloor is the minimum seniority to review (approve/reject) a report or read the pending queue. A
// soc_manager (RoleRank 4) is the structural floor — the same manager tier that clears a SOAR run — so report
// release cannot be self-cleared by the analyst tier that generates reports.
var reviewApproverFloor = auth.RoleSOCManager

// canReviewReport is the pure separation-of-duties + seniority guard for report review. It is DB-free so the two
// invariants (a junior cannot approve; the creator cannot approve their own report) are unit-testable in isolation.
func canReviewReport(role auth.Role, createdBy, approver uuid.UUID) error {
	if auth.RoleRank(role) < auth.RoleRank(reviewApproverFloor) {
		return httpx.ErrForbidden("report review requires a soc_manager (or higher) approver")
	}
	if createdBy == approver {
		return httpx.ErrForbidden("separation of duties: the creator of a report may not review it")
	}
	return nil
}

// SetReviewApproved transitions a report pending_review → approved and writes the approve audit row in the SAME
// transaction. The WHERE guard (status='ready' AND review_status='pending_review') makes the transition atomic and
// idempotent-safe: a report already decided (approved/rejected) or not ready affects 0 rows. Returning 0 rows and
// no audit is correct — nothing changed. If the audit INSERT fails the whole tx rolls back, so an approval never
// commits without its trail.
func (r *ReportRepository) SetReviewApproved(ctx context.Context, tenantID, id, approver uuid.UUID, format Format, rowCount int) (int64, error) {
	var affected int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE reports SET review_status='approved', reviewed_by=$2, reviewed_at=now()
			   WHERE id=$1 AND status='ready' AND review_status='pending_review'`, id, approver)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		if affected == 0 {
			return nil
		}
		_, e = tx.Exec(ctx,
			`INSERT INTO report_audit (tenant_id, report_id, actor_id, action, format, row_count)
			 VALUES ($1,$2,$3,'approve',$4,$5)`, tenantID, id, approver, string(format), rowCount)
		return e
	})
	return affected, err
}

// SetReviewRejected transitions a report pending_review → rejected (TERMINAL) with a reason, and writes the reject
// audit row in the same transaction. Same atomic WHERE guard as approve.
func (r *ReportRepository) SetReviewRejected(ctx context.Context, tenantID, id, approver uuid.UUID, note string, format Format, rowCount int) (int64, error) {
	if len(note) > 1000 {
		note = note[:1000]
	}
	var affected int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE reports SET review_status='rejected', reviewed_by=$2, reviewed_at=now(), review_note=$3
			   WHERE id=$1 AND status='ready' AND review_status='pending_review'`, id, approver, note)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		if affected == 0 {
			return nil
		}
		_, e = tx.Exec(ctx,
			`INSERT INTO report_audit (tenant_id, report_id, actor_id, action, format, row_count)
			 VALUES ($1,$2,$3,'reject',$4,$5)`, tenantID, id, approver, string(format), rowCount)
		return e
	})
	return affected, err
}

// ListPendingReview reads the tenant's ready reports awaiting sign-off (RLS-confined to the tenant).
func (r *ReportRepository) ListPendingReview(ctx context.Context, tenantID uuid.UUID) ([]*Report, error) {
	var out []*Report
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, tenant_id, type, format, status, review_status, reviewed_by, reviewed_at, review_note,
			        row_count, byte_size, error, created_by, created_at, ready_at
			   FROM reports
			  WHERE status='ready' AND review_status='pending_review'
			  ORDER BY created_at ASC`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var rep Report
			var format string
			if e := rows.Scan(&rep.ID, &rep.TenantID, &rep.Type, &format, &rep.Status,
				&rep.ReviewStatus, &rep.ReviewedBy, &rep.ReviewedAt, &rep.ReviewNote,
				&rep.RowCount, &rep.ByteSize, &rep.Error, &rep.CreatedBy, &rep.CreatedAt, &rep.ReadyAt); e != nil {
				return e
			}
			rep.Format = Format(format)
			out = append(out, &rep)
		}
		return rows.Err()
	})
	return out, err
}

// Approve clears a report for release: senior approver (≠ creator), atomic pending_review → approved, audited.
func (rs *ReportService) Approve(ctx context.Context, p auth.Principal, id uuid.UUID) (*Report, error) {
	rep, err := rs.repo.Get(ctx, p.TenantID, id) // RLS-confined: a foreign-tenant id resolves to not-found
	if err != nil {
		return nil, err
	}
	if err := canReviewReport(p.Role, rep.CreatedBy, p.UserID); err != nil {
		return nil, err
	}
	n, err := rs.repo.SetReviewApproved(ctx, p.TenantID, id, p.UserID, rep.Format, rep.RowCount)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, httpx.ErrConflict("report is not awaiting review (already decided, or not ready)")
	}
	return rs.repo.Get(ctx, p.TenantID, id)
}

// Reject blocks a report from release (terminal): senior approver (≠ creator), atomic pending_review → rejected,
// audited, with a reason recorded on the record.
func (rs *ReportService) Reject(ctx context.Context, p auth.Principal, id uuid.UUID, note string) (*Report, error) {
	rep, err := rs.repo.Get(ctx, p.TenantID, id)
	if err != nil {
		return nil, err
	}
	if err := canReviewReport(p.Role, rep.CreatedBy, p.UserID); err != nil {
		return nil, err
	}
	n, err := rs.repo.SetReviewRejected(ctx, p.TenantID, id, p.UserID, note, rep.Format, rep.RowCount)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, httpx.ErrConflict("report is not awaiting review (already decided, or not ready)")
	}
	return rs.repo.Get(ctx, p.TenantID, id)
}

// ListPendingApproval returns the tenant's reports awaiting sign-off — senior-gated (the queue is an approver view).
func (rs *ReportService) ListPendingApproval(ctx context.Context, p auth.Principal) ([]*Report, error) {
	if auth.RoleRank(p.Role) < auth.RoleRank(reviewApproverFloor) {
		return nil, httpx.ErrForbidden("viewing reports awaiting review requires a soc_manager (or higher)")
	}
	return rs.repo.ListPendingReview(ctx, p.TenantID)
}
