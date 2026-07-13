package investigation

// §6.9 #124 I-1/I-2 — the hunt-query service. Order of operations is the security contract:
//   load ceiling → validate (allow-list/role/type/cost) → compile (bound params) → run under RLS → mask → AUDIT.
// The audit write is fail-CLOSED: if it fails, the request fails and NO rows are returned — customer data is never
// served without the query being recorded (INV-007). The read is a SELECT, so failing after it has no side effect.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service owns the hunt-query flow.
type Service struct {
	repo    *Repository
	journal CaseJournalReader // #188 optional: the incident journal, for the merged multi-lane case timeline
	rawBlob blobstore.Store   // #188 optional: the object store holding raw event payloads (get-raw-event)
}

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// WithRawStore wires the object store for the raw-event fetch path (#188). Without it, get-raw-event is unavailable.
func (s *Service) WithRawStore(b blobstore.Store) *Service { s.rawBlob = b; return s }

// RawEvent is the untransformed captured payload for one raw event — the most sensitive data an analyst can pull.
type RawEvent struct {
	ID       uuid.UUID `json:"id"`
	Checksum string    `json:"checksum"`
	Payload  []byte    `json:"-"`
}

// GetRawEvent fetches the raw captured payload for one raw event, RLS-confined to the caller's tenant (a foreign id
// resolves to not-found). The read-audit (INV-007, kind=raw_event) is FAIL-CLOSED: the payload is never served
// unless the access is recorded first. The most sensitive read in the product — role-gated at the router.
func (s *Service) GetRawEvent(ctx context.Context, p auth.Principal, id uuid.UUID) (*RawEvent, error) {
	if s.rawBlob == nil {
		return nil, httpx.ErrBadRequest("raw-event retrieval is not available")
	}
	if id == uuid.Nil {
		return nil, httpx.ErrBadRequest("raw event id is required")
	}
	blobURI, checksum, err := s.repo.RawEventMeta(ctx, p.TenantID, id) // RLS: foreign/absent id → not-found
	if err != nil {
		return nil, err
	}
	// Fail-closed audit BEFORE serving any payload — never a raw-data access that isn't recorded.
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "raw_event", map[string]string{"raw_event_id": id.String()}, 1); err != nil {
		return nil, err
	}
	if blobURI == "" {
		return nil, httpx.ErrNotFound("raw payload is not available for this event")
	}
	payload, err := s.rawBlob.Get(ctx, blobURI)
	if err != nil {
		return nil, httpx.ErrInternal("raw payload could not be read")
	}
	return &RawEvent{ID: id, Checksum: checksum, Payload: payload}, nil
}

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
