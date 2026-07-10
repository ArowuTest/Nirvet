package investigation

// §6.9 #124 I-1/I-2 — the hunt-query service. Order of operations is the security contract:
//   load ceiling → validate (allow-list/role/type/cost) → compile (bound params) → run under RLS → mask → AUDIT.
// The audit write is fail-CLOSED: if it fails, the request fails and NO rows are returned — customer data is never
// served without the query being recorded (INV-007). The read is a SELECT, so failing after it has no side effect.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
)

// Service owns the hunt-query flow.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// RunHunt validates + runs a hunt query and records the read-path audit.
func (s *Service) RunHunt(ctx context.Context, p auth.Principal, q HuntQuery) (HuntResult, error) {
	lim := s.repo.LoadLimits(ctx)
	if err := q.Validate(p, lim); err != nil {
		return HuntResult{}, err
	}
	c := Compile(q)
	rows, err := s.repo.RunHunt(ctx, p.TenantID, c, q.Limit)
	if err != nil {
		return HuntResult{}, err
	}
	maskRows(p, rows) // must-add #3 seam
	// INV-007 read-audit — fail-closed: never serve an unaudited query.
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "hunt_query", q, len(rows)); err != nil {
		return HuntResult{}, err
	}
	return HuntResult{Rows: rows, Count: len(rows)}, nil
}

// fieldVisible reports whether a role may see a registry field unmasked (must-add #3). Unknown field → visible (it is
// not a maskable registry column). Default light: every real field is MinRole analyst_t1, so every provider role sees
// everything; the seam makes elevating a field a registry edit, not a projection change.
func fieldVisible(role auth.Role, name string) bool {
	f, ok := lookupField(name)
	if !ok {
		return true
	}
	return roleMeets(role, f.MinRole)
}

// maskRows blanks the PII-carrying projected columns for a role that cannot meet their field's MinRole. Wired for the
// two entity-reference columns (the realistic future-sensitive fields); a no-op today under the light default.
func maskRows(p auth.Principal, rows []EventRow) {
	maskActor := !fieldVisible(p.Role, "actor_ref")
	maskTarget := !fieldVisible(p.Role, "target_ref")
	if !maskActor && !maskTarget {
		return
	}
	for i := range rows {
		if maskActor {
			rows[i].ActorRef = maskedText
		}
		if maskTarget {
			rows[i].TargetRef = maskedText
		}
	}
}
