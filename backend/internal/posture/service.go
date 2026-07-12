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

// resolveScope maps the reader to the tenant-set it may see posture for — derived PURELY from the principal,
// never from client input, and FAIL-CLOSED. This is the BOLA boundary of the oversight-read family, so it is a
// CLOSED switch whose DEFAULT is EMPTY (MA-OV-1: an unrecognized/ungranted principal → empty → the SD function's
// zero rows; never a widening default). Every arm derives its tenant-set from the AUTHENTICATED principal
// (MA-OV-2: platform_admin from role; org-sub-admin/payer from a grant lookup keyed on p.UserID) — there is no
// org/account/tenant id anywhere in the request path a caller can supply to widen. Whatever set this returns is
// then funnelled through the capped, fail-closed tenant_posture_fleet() SD function (MA-OV-4).
func (s *Service) resolveScope(ctx context.Context, p auth.Principal) ([]uuid.UUID, error) {
	switch p.Role {
	case auth.RolePlatformAdmin:
		return s.allInstanceTenants(ctx) // vendor/platform seat: the whole instance
	case auth.RoleOrgSubAdmin:
		return s.orgScope(ctx, p.UserID) // only the tenants of the orgs this principal is granted
	case auth.RolePayer:
		return s.payerScope(ctx, p.UserID) // only the tenants covered by the accounts this principal is granted
	default:
		return nil, nil // MA-OV-1: closed switch, empty default — no oversight scope
	}
}

// TenantScope exports the fail-closed oversight scope resolution for other packages that need the SAME
// principal-derived, grant-scoped, empty-by-default tenant set (readmodel's regulator rollups reuse it). It is a
// thin wrapper over resolveScope so there is ONE scope authority, not a second copy that could drift.
func (s *Service) TenantScope(ctx context.Context, p auth.Principal) ([]uuid.UUID, error) {
	return s.resolveScope(ctx, p)
}

// orgScope returns the tenants belonging to the organisations this principal holds an org_admin_grant for. The
// grant set is keyed on the AUTHENTICATED p.UserID (MA-OV-2) — never a client-supplied org id. Read under
// WithSystem (grant + tenants registries are not per-tenant-RLS'd); a principal with no grant → empty.
func (s *Service) orgScope(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.scanTenantIDs(ctx, `
		SELECT t.id FROM tenants t
		 WHERE t.org_id IN (SELECT org_id FROM org_admin_grant WHERE principal_id = $1)
		 ORDER BY t.id`, userID)
}

// payerScope returns the tenants covered by the billing accounts this principal holds a payer_account_grant
// for, via the cleared billing_account_tenants() SD function. Keyed on the authenticated p.UserID (MA-OV-2).
func (s *Service) payerScope(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.scanTenantIDs(ctx, `
		SELECT bat.tenant_id
		  FROM payer_account_grant g
		  CROSS JOIN LATERAL billing_account_tenants(g.account_id) bat
		 WHERE g.principal_id = $1
		 ORDER BY bat.tenant_id`, userID)
}

// scanTenantIDs runs a principal-keyed scope query under WithSystem and returns the tenant-set.
func (s *Service) scanTenantIDs(ctx context.Context, query string, userID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, query, userID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
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
