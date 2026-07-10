package platformadmin

// §6.18 #122 P-1 — the feature-flag resolver. Enforces, at read time, the guarantees the safety classification
// promises: immutable-from-code (a planted DB row is inert), fail-safe value + class for unknown keys, and
// tighten-only for protected flags. Write-time gating (senior+four-eyes for a protected less-secure flip) is P-2.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FlagResolver resolves a feature flag's effective boolean for a tenant.
type FlagResolver struct{ db *database.DB }

// NewFlagResolver builds the resolver.
func NewFlagResolver(db *database.DB) *FlagResolver { return &FlagResolver{db: db} }

// Enabled resolves whether `key` is on for `tenantID`:
//   - immutable key → the code SecureDefault, DB IGNORED (a planted row is inert — Reinf-A).
//   - unknown/unregistered key → protected class + SecureDefault(false) (M-1 / fail-safe value).
//   - precedence: a tenant-scoped row overrides global for open/guarded; a protected flag can only be TIGHTENED by a
//     tenant (moved toward its secure state), never loosened below the platform baseline.
//   - ANY read error → SecureDefault (fail-safe; never a permissive fallback on uncertainty).
func (r *FlagResolver) Enabled(ctx context.Context, tenantID uuid.UUID, key string) bool {
	secure := SecureDefault(key)
	if IsImmutable(key) {
		return secure // code-only: the DB can never move an immutable control
	}
	globalVal, hasGlobal, tenantVal, hasTenant, err := r.read(ctx, tenantID, key)
	if err != nil {
		return secure // fail-safe on infra error
	}
	base := secure
	if hasGlobal {
		base = globalVal
	}
	if ClassOf(key) == ClassProtected {
		if hasTenant && tenantVal == secure { // a tenant may tighten toward secure
			return secure
		}
		return base // never loosened below the platform baseline
	}
	if hasTenant { // open/guarded: narrowest scope wins
		return tenantVal
	}
	return base
}

func (r *FlagResolver) read(ctx context.Context, tenantID uuid.UUID, key string) (gv, hg, tv, ht bool, err error) {
	e := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, qe := tx.Query(ctx, `SELECT scope, enabled FROM platform_feature_flags
			WHERE key=$1 AND (scope='global' OR (scope='tenant' AND scope_ref=$2::text))`, key, tenantID)
		if qe != nil {
			return qe
		}
		defer rows.Close()
		for rows.Next() {
			var scope string
			var en bool
			if se := rows.Scan(&scope, &en); se != nil {
				return se
			}
			if scope == "global" {
				gv, hg = en, true
			} else {
				tv, ht = en, true
			}
		}
		return rows.Err()
	})
	return gv, hg, tv, ht, e
}
