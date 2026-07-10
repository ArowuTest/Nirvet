package posture

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Service is the vendor posture oversight service: resolve the reader's scope, then read the metadata-only
// fleet posture within it. It also exposes Record, the write the projector calls (scalars only).
type Service struct {
	db   *database.DB
	repo *Repository
}

// NewService wires the posture service.
func NewService(db *database.DB) *Service {
	return &Service{db: db, repo: NewRepository(db)}
}

// resolveScope maps the reader to the tenant-set it may see posture for — derived PURELY from the principal
// (MA4-3), never from client input, and FAIL-CLOSED. The vendor posture-oversight seat is platform_admin (the
// vendor-vs-operator seat distinction itself is §6.18 provisioning, not a slice-A code gate): a platform_admin
// resolves to the whole instance; every other principal resolves to an EMPTY set → zero rows via the
// fail-closed SD function. Deriving from the principal means a "who is the vendor" bug fails CLOSED, not open.
func (s *Service) resolveScope(ctx context.Context, p auth.Principal) ([]uuid.UUID, error) {
	if p.Role != auth.RolePlatformAdmin {
		return nil, nil // fail-closed: no posture oversight scope for a non-vendor principal
	}
	return s.allInstanceTenants(ctx)
}

// allInstanceTenants lists every tenant in the instance (the fleet on a dedicated single-operator instance).
// `tenants` is the global registry (no per-tenant RLS), read under WithSystem.
func (s *Service) allInstanceTenants(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// Fleet returns the metadata-only posture across the reader's resolved scope, and records a read-audit (the
// vendor oversight read is a deliberate cross-tenant read, so it is logged). A non-vendor principal resolves to
// an empty scope → zero rows (the SD function fail-closes), so this is safe by default.
func (s *Service) Fleet(ctx context.Context, p auth.Principal) ([]Posture, error) {
	scope, err := s.resolveScope(ctx, p)
	if err != nil {
		return nil, err
	}
	out, err := s.repo.FleetPosture(ctx, scope)
	if err != nil {
		return nil, err
	}
	// Read-audit under the reader's own tenant: who looked at the fleet posture, and how wide.
	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "posture.fleet_read",
			Target: "posture:fleet", Metadata: map[string]any{"tenants_in_scope": len(scope), "rows": len(out)}})
	})
	return out, nil
}

// Record writes a tenant's posture projection. Its signature takes metadata scalars (Metrics) only — never a
// content struct — so content cannot cross into the store even by accident (MA4-1). Called by the projector
// (internal/postureproj), the single content→posture choke point.
func (s *Service) Record(ctx context.Context, tenantID uuid.UUID, m Metrics) error {
	return s.repo.Upsert(ctx, tenantID, m)
}
