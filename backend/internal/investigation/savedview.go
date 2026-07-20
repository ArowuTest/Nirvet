package investigation

// §6.9 slice B — saved views: named, re-runnable hunt queries, PRIVATE to the creating analyst. A view stores the flat
// All/Any predicates plus a RELATIVE window (LookbackSeconds); the absolute From/To are recomputed at each run so the
// view stays "now-relative". Running a view goes through the EXISTING RunHunt, which RE-VALIDATES for the RUNNING actor
// (field-visibility + cost ceiling + read-audit) — so a saved view grants NO capability the caller lacks: no escalation
// via a stored query, by construction.

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	maxSavedViewName = 200
	maxSavedViewDesc = 2000
)

// SavedView is a named, re-runnable hunt query owned by one analyst.
type SavedView struct {
	ID              uuid.UUID   `json:"id"`
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	All             []Predicate `json:"all,omitempty"`
	Any             []Predicate `json:"any,omitempty"`
	LookbackSeconds int64       `json:"lookback_seconds"`
	Limit           int         `json:"limit,omitempty"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// savedQuery is the jsonb shape persisted for a view's predicates (no absolute time — derived on run).
type savedQuery struct {
	All []Predicate `json:"all,omitempty"`
	Any []Predicate `json:"any,omitempty"`
}

// toQuery materialises the runnable HuntQuery at the given instant: the predicates plus a FRESH window
// From = now - lookback, To = now. The absolute window is never stored, so re-running is always now-relative.
func (sv SavedView) toQuery(now time.Time) HuntQuery {
	return HuntQuery{
		All:   sv.All,
		Any:   sv.Any,
		From:  now.Add(-time.Duration(sv.LookbackSeconds) * time.Second),
		To:    now,
		Limit: sv.Limit,
	}
}

// ================= repository =================

func (r *Repository) insertSavedView(ctx context.Context, tenantID, userID uuid.UUID, sv SavedView) (uuid.UUID, time.Time, time.Time, error) {
	qb, _ := json.Marshal(savedQuery{All: sv.All, Any: sv.Any})
	var id uuid.UUID
	var created, updated time.Time
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO investigation_saved_views (user_id, name, description, query, lookback_seconds, row_limit)
			 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at, updated_at`,
			userID, sv.Name, sv.Description, qb, sv.LookbackSeconds, sv.Limit).Scan(&id, &created, &updated)
	})
	return id, created, updated, err
}

func (r *Repository) listSavedViews(ctx context.Context, tenantID, userID uuid.UUID) ([]SavedView, error) {
	var out []SavedView
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, name, description, query, lookback_seconds, row_limit, created_at, updated_at
			   FROM investigation_saved_views WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 200`, userID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			sv, e := scanSavedView(rows)
			if e != nil {
				return e
			}
			out = append(out, *sv)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) getSavedView(ctx context.Context, tenantID, userID, id uuid.UUID) (*SavedView, error) {
	var sv *SavedView
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		s, e := scanSavedView(tx.QueryRow(ctx,
			`SELECT id, name, description, query, lookback_seconds, row_limit, created_at, updated_at
			   FROM investigation_saved_views WHERE id=$1 AND user_id=$2`, id, userID))
		if e != nil {
			return e
		}
		sv = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sv, nil
}

func (r *Repository) deleteSavedView(ctx context.Context, tenantID, userID, id uuid.UUID) (int64, error) {
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM investigation_saved_views WHERE id=$1 AND user_id=$2`, id, userID)
		if e != nil {
			return e
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

type svRowScanner interface{ Scan(dest ...any) error }

func scanSavedView(row svRowScanner) (*SavedView, error) {
	var sv SavedView
	var qb []byte
	if err := row.Scan(&sv.ID, &sv.Name, &sv.Description, &qb, &sv.LookbackSeconds, &sv.Limit, &sv.CreatedAt, &sv.UpdatedAt); err != nil {
		return nil, err
	}
	var q savedQuery
	if len(qb) > 0 {
		_ = json.Unmarshal(qb, &q)
	}
	sv.All, sv.Any = q.All, q.Any
	return &sv, nil
}

// ================= service =================

// SavedViewInput is the create payload.
type SavedViewInput struct {
	Name            string      `json:"name"`
	Description     string      `json:"description"`
	All             []Predicate `json:"all"`
	Any             []Predicate `json:"any"`
	LookbackSeconds int64       `json:"lookback_seconds"`
	Limit           int         `json:"limit"`
}

// CreateSavedView validates the query is well-formed + within the CREATING actor's role + cost ceiling (a view you
// couldn't run cannot be saved), then persists it private to the caller.
func (s *Service) CreateSavedView(ctx context.Context, p auth.Principal, in SavedViewInput) (*SavedView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxSavedViewName {
		return nil, httpx.ErrBadRequest("name is required (<=200 chars)")
	}
	if len(in.Description) > maxSavedViewDesc {
		return nil, httpx.ErrBadRequest("description too long")
	}
	if in.LookbackSeconds <= 0 {
		return nil, httpx.ErrBadRequest("lookback_seconds must be > 0")
	}
	sv := SavedView{Name: name, Description: strings.TrimSpace(in.Description), All: in.All, Any: in.Any,
		LookbackSeconds: in.LookbackSeconds, Limit: in.Limit}
	// Validate the runnable query for the CREATING actor — rejects an unknown field, an over-role predicate, or a
	// window/predicate-count over the ceiling.
	lim := s.repo.LoadLimits(ctx)
	q := sv.toQuery(time.Now())
	if err := q.Validate(p, lim); err != nil {
		return nil, err
	}
	id, created, updated, err := s.repo.insertSavedView(ctx, p.TenantID, p.UserID, sv)
	if err != nil {
		return nil, httpx.ErrInternal("could not save view")
	}
	sv.ID, sv.CreatedAt, sv.UpdatedAt = id, created, updated
	return &sv, nil
}

// ListSavedViews returns the caller's own saved views.
func (s *Service) ListSavedViews(ctx context.Context, p auth.Principal) ([]SavedView, error) {
	vs, err := s.repo.listSavedViews(ctx, p.TenantID, p.UserID)
	if err != nil {
		return nil, httpx.ErrInternal("could not list saved views")
	}
	return vs, nil
}

// GetSavedView returns one of the caller's own saved views.
func (s *Service) GetSavedView(ctx context.Context, p auth.Principal, id uuid.UUID) (*SavedView, error) {
	sv, err := s.repo.getSavedView(ctx, p.TenantID, p.UserID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("saved view not found")
	}
	return sv, nil
}

// DeleteSavedView removes one of the caller's own saved views.
func (s *Service) DeleteSavedView(ctx context.Context, p auth.Principal, id uuid.UUID) error {
	n, err := s.repo.deleteSavedView(ctx, p.TenantID, p.UserID, id)
	if err != nil {
		return httpx.ErrInternal("could not delete saved view")
	}
	if n == 0 {
		return httpx.ErrNotFound("saved view not found")
	}
	return nil
}

// RunSavedView materialises the view's query with a FRESH now-relative window and runs it through RunHunt — which
// re-validates for the RUNNING actor (field-visibility + cost ceiling) and writes the read-audit. A saved view grants
// no capability the caller lacks: escalation via a stored query is impossible by construction.
func (s *Service) RunSavedView(ctx context.Context, p auth.Principal, id uuid.UUID) (HuntResult, error) {
	sv, err := s.repo.getSavedView(ctx, p.TenantID, p.UserID, id)
	if err != nil {
		return HuntResult{}, httpx.ErrNotFound("saved view not found")
	}
	return s.RunHunt(ctx, p, sv.toQuery(time.Now()))
}
