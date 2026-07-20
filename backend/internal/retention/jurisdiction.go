package retention

// §6.14 B3 — the OPERATOR (platform_admin) surface for jurisdictional retention: manage the per-jurisdiction
// floor/ceiling windows and the go-live arm for the ceiling's destructive enforcement. A sovereign regime is
// operator-level, never tenant-self-service (gate 2b) — these run under WithSystem (app_current_tenant() IS NULL),
// which the jurisdiction_* RLS write policies require; the padmin route chain audits the mutation.

import (
	"context"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
)

// Jurisdiction is one sovereign regime's retention rule. A nil bound means "none" (no floor / no ceiling).
type Jurisdiction struct {
	Key           string `json:"jurisdiction_key"`
	Name          string `json:"name"`
	MinRetainDays *int   `json:"min_retain_days"` // floor: retain >= (nil/0 = none)
	MaxRetainDays *int   `json:"max_retain_days"` // ceiling: delete after (nil = none)
}

// ListJurisdictions returns every configured jurisdiction (operator view).
func (s *Service) ListJurisdictions(ctx context.Context) ([]Jurisdiction, error) {
	var out []Jurisdiction
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT jurisdiction_key, name, min_retain_days, max_retain_days FROM jurisdiction_retention ORDER BY jurisdiction_key`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var j Jurisdiction
			if e := rows.Scan(&j.Key, &j.Name, &j.MinRetainDays, &j.MaxRetainDays); e != nil {
				return e
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list jurisdictions")
	}
	return out, nil
}

// JurisdictionInput upserts a jurisdiction's windows.
type JurisdictionInput struct {
	Key           string `json:"jurisdiction_key"`
	Name          string `json:"name"`
	MinRetainDays *int   `json:"min_retain_days"`
	MaxRetainDays *int   `json:"max_retain_days"`
}

// UpsertJurisdiction validates + writes a jurisdiction rule. Floor and ceiling may COEXIST even when floor>ceiling —
// resolveWindow resolves that contradiction toward the floor (retain longer); a mandated-retention floor must never be
// un-settable because a ceiling exists (gate 2b). platform_admin only (WithSystem).
func (s *Service) UpsertJurisdiction(ctx context.Context, in JurisdictionInput) (*Jurisdiction, error) {
	key := strings.TrimSpace(in.Key)
	if key == "" || len(key) > 64 {
		return nil, httpx.ErrBadRequest("jurisdiction_key is required (<=64 chars)")
	}
	if in.MinRetainDays != nil && *in.MinRetainDays < 0 {
		return nil, httpx.ErrBadRequest("min_retain_days must be >= 0 or null")
	}
	if in.MaxRetainDays != nil && *in.MaxRetainDays < 1 {
		return nil, httpx.ErrBadRequest("max_retain_days must be >= 1 or null")
	}
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO jurisdiction_retention (jurisdiction_key, name, min_retain_days, max_retain_days, updated_at)
			 VALUES ($1,$2,$3,$4, now())
			 ON CONFLICT (jurisdiction_key) DO UPDATE SET
			   name=EXCLUDED.name, min_retain_days=EXCLUDED.min_retain_days, max_retain_days=EXCLUDED.max_retain_days, updated_at=now()`,
			key, strings.TrimSpace(in.Name), in.MinRetainDays, in.MaxRetainDays)
		return e
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not save jurisdiction")
	}
	return &Jurisdiction{Key: key, Name: strings.TrimSpace(in.Name), MinRetainDays: in.MinRetainDays, MaxRetainDays: in.MaxRetainDays}, nil
}

// GetArmed returns whether the jurisdictional-ceiling destructive enforcement is armed (go-live D-arm-retention).
func (s *Service) GetArmed(ctx context.Context) bool { return s.armedNow(ctx) }

// SetArmed flips the jurisdictional-ceiling destructive enforcement arm. This is the go-live step that lets a
// jurisdiction CEILING shorten a delete window below tenant/entitlement (irreversible early deletion) — platform_admin
// only, and the padmin route chain audits it. Floor + tighten-only deletions are unaffected.
func (s *Service) SetArmed(ctx context.Context, armed bool) error {
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE jurisdiction_delete_armed SET armed=$1, updated_at=now() WHERE id=1`, armed)
		return e
	})
	if err != nil {
		return httpx.ErrInternal("could not set arm flag")
	}
	return nil
}

// ================= HTTP (platform_admin) =================

// ListJurisdictions handles GET /admin/retention/jurisdictions.
func (h *Handler) ListJurisdictions(w http.ResponseWriter, r *http.Request) {
	js, err := h.svc.ListJurisdictions(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"jurisdictions": js})
}

// UpsertJurisdiction handles PUT /admin/retention/jurisdictions.
func (h *Handler) UpsertJurisdiction(w http.ResponseWriter, r *http.Request) {
	var in JurisdictionInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	j, err := h.svc.UpsertJurisdiction(r.Context(), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, j)
}

// GetArm handles GET /admin/retention/arm.
func (h *Handler) GetArm(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"armed": h.svc.GetArmed(r.Context())})
}

// SetArm handles PUT /admin/retention/arm — the go-live D-arm-retention step.
func (h *Handler) SetArm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Armed bool `json:"armed"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetArmed(r.Context(), in.Armed); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"armed": in.Armed})
}
