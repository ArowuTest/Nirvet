package iam

// Service accounts + API keys (SRS §6.2: IAM-001/005/008). A service account is a non-human,
// non-loginable principal; an API key authenticates as its service account. Only sha256(key)
// + a public prefix are stored — the secret is shown once and never retrievable.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// apiKeyScheme prefixes every raw key: nvt_<prefix>_<secret>.
const apiKeyScheme = "nvt_"

// ServiceAccount is a non-human tenant principal used for programmatic access.
type ServiceAccount struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Name     string    `json:"name"`
	Role     auth.Role `json:"role"`
	Active   bool      `json:"active"`
}

// APIKey is the non-secret metadata of a key (the secret is never returned after creation).
type APIKey struct {
	ID               uuid.UUID  `json:"id"`
	ServiceAccountID uuid.UUID  `json:"service_account_id"`
	Prefix           string     `json:"prefix"`
	Label            string     `json:"label"`
	Role             auth.Role  `json:"role"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ---- generation / hashing ----

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// generateKey returns (rawKey, prefix, keyHash). rawKey is shown to the caller once.
func generateKey() (raw, prefix, hash string, err error) {
	pb := make([]byte, 5) // 10 hex chars of prefix
	sb := make([]byte, 32)
	if _, err = rand.Read(pb); err != nil {
		return
	}
	if _, err = rand.Read(sb); err != nil {
		return
	}
	prefix = hex.EncodeToString(pb)
	raw = apiKeyScheme + prefix + "_" + hex.EncodeToString(sb)
	hash = sha256hex(raw)
	return
}

// prefixOf extracts the lookup prefix from a raw key (nvt_<prefix>_<secret>).
func prefixOf(raw string) string {
	parts := strings.Split(strings.TrimPrefix(raw, apiKeyScheme), "_")
	if len(parts) < 2 {
		return ""
	}
	return parts[0]
}

// =========================== service ===========================

// SACreateInput creates a service account.
type SACreateInput struct {
	Name string    `json:"name"`
	Role auth.Role `json:"role"`
}

// CreateServiceAccount provisions a non-human principal. Least privilege (IAM-005): the role must
// be a grantable, non-admin role, and — Round-4 H1 — a customer_admin may NOT mint a provider-role
// service account (cross-domain BFLA). Same allowlist + domain guard as invitation creation.
func (s *Service) CreateServiceAccount(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in SACreateInput) (*ServiceAccount, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if in.Role == "" {
		return nil, httpx.ErrBadRequest("role is required")
	}
	if err := validateGrantableRole(p.Role, in.Role); err != nil {
		return nil, err
	}
	sa := &ServiceAccount{ID: uuid.New(), TenantID: tenantID, Name: in.Name, Role: in.Role, Active: true}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO service_accounts (id, tenant_id, name, role, active) VALUES ($1,$2,$3,$4,true)`,
			sa.ID, tenantID, sa.Name, sa.Role); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.service_account_create", Target: "service_account:" + sa.ID.String(),
			Metadata: map[string]any{"name": sa.Name, "role": sa.Role}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not create service account")
	}
	return sa, nil
}

// ListServiceAccounts returns the tenant's service accounts.
func (s *Service) ListServiceAccounts(ctx context.Context, tenantID uuid.UUID) ([]ServiceAccount, error) {
	var out []ServiceAccount
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, name, role, active FROM service_accounts ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sa ServiceAccount
			if err := rows.Scan(&sa.ID, &sa.TenantID, &sa.Name, &sa.Role, &sa.Active); err != nil {
				return err
			}
			out = append(out, sa)
		}
		return rows.Err()
	})
	return out, err
}

// KeyCreateInput creates an API key for a service account.
type KeyCreateInput struct {
	Label     string     `json:"label"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreateAPIKey mints a key for a service account and returns the RAW key exactly once.
func (s *Service) CreateAPIKey(ctx context.Context, p auth.Principal, tenantID, saID uuid.UUID, in KeyCreateInput) (*APIKey, string, error) {
	raw, prefix, hash, err := generateKey()
	if err != nil {
		return nil, "", httpx.ErrInternal("could not generate key")
	}
	k := &APIKey{ID: uuid.New(), ServiceAccountID: saID, Prefix: prefix, Label: in.Label, ExpiresAt: in.ExpiresAt}
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// The service account must exist in this tenant, and its role becomes the key's role.
		var role auth.Role
		if e := tx.QueryRow(ctx, `SELECT role FROM service_accounts WHERE id=$1 AND active=true`, saID).Scan(&role); e != nil {
			return e
		}
		k.Role = role
		if _, e := tx.Exec(ctx,
			`INSERT INTO api_keys (id, tenant_id, service_account_id, prefix, key_hash, label, role, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			k.ID, tenantID, saID, prefix, hash, in.Label, role, in.ExpiresAt); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.api_key_create", Target: "api_key:" + k.ID.String(),
			Metadata: map[string]any{"service_account": saID.String(), "prefix": prefix}})
	})
	if err == pgx.ErrNoRows {
		return nil, "", httpx.ErrNotFound("service account not found or inactive")
	}
	if err != nil {
		return nil, "", httpx.ErrInternal("could not create api key")
	}
	return k, raw, nil
}

// ListAPIKeys returns a service account's key metadata (never the secret).
func (s *Service) ListAPIKeys(ctx context.Context, tenantID, saID uuid.UUID) ([]APIKey, error) {
	var out []APIKey
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, service_account_id, prefix, label, role, expires_at, last_used_at, revoked_at, created_at
			   FROM api_keys WHERE service_account_id=$1 ORDER BY created_at DESC`, saID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k APIKey
			if err := rows.Scan(&k.ID, &k.ServiceAccountID, &k.Prefix, &k.Label, &k.Role,
				&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeAPIKey marks a key revoked (fail-closed on next use).
func (s *Service) RevokeAPIKey(ctx context.Context, p auth.Principal, tenantID, keyID uuid.UUID) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, keyID)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.api_key_revoke", Target: "api_key:" + keyID.String()})
	})
	if err == pgx.ErrNoRows {
		return httpx.ErrNotFound("api key not found or already revoked")
	}
	if err != nil {
		return httpx.ErrInternal("could not revoke api key")
	}
	return nil
}

// ResolveAPIKey authenticates a raw API key and returns its Principal (implements
// auth.APIKeyResolver). Pre-auth: no tenant context yet, so the lookup goes through the
// SECURITY DEFINER function; the hash is compared constant-time and revoked/expired/inactive
// keys fail closed. last_used_at is bumped best-effort under the resolved tenant.
func (s *Service) ResolveAPIKey(ctx context.Context, rawKey string) (auth.Principal, error) {
	prefix := prefixOf(rawKey)
	if prefix == "" {
		return auth.Principal{}, httpx.ErrUnauthorized("malformed api key")
	}
	var (
		keyID, tenantID, saID uuid.UUID
		storedHash, role      string
		expiresAt, revokedAt  *time.Time
		saActive              bool
	)
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, service_account_id, key_hash, role, expires_at, revoked_at, sa_active
			   FROM auth_find_api_key_by_prefix($1)`, prefix).
			Scan(&keyID, &tenantID, &saID, &storedHash, &role, &expiresAt, &revokedAt, &saActive)
	})
	if err != nil {
		return auth.Principal{}, httpx.ErrUnauthorized("invalid api key")
	}
	if subtle.ConstantTimeCompare([]byte(sha256hex(rawKey)), []byte(storedHash)) != 1 {
		return auth.Principal{}, httpx.ErrUnauthorized("invalid api key")
	}
	if revokedAt != nil || !saActive {
		return auth.Principal{}, httpx.ErrUnauthorized("api key revoked")
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return auth.Principal{}, httpx.ErrUnauthorized("api key expired")
	}
	// Best-effort last-used bump (never blocks auth). Round-4 L5: emit a first-use-per-hour audit
	// event so API-key USE (not only create/revoke) leaves an immutable trail — the CTE captures the
	// prior last_used_at so we audit at most once per key per hour, keeping the hot path cheap.
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var prev *time.Time
		if e := tx.QueryRow(ctx,
			`WITH old AS (SELECT last_used_at AS prev FROM api_keys WHERE id=$1)
			 UPDATE api_keys k SET last_used_at=now() FROM old WHERE k.id=$1 RETURNING old.prev`, keyID).Scan(&prev); e != nil {
			return e
		}
		if prev == nil || time.Since(*prev) > time.Hour {
			return audit.Record(ctx, tx, audit.Entry{ActorID: saID, ActorEmail: "svc:" + saID.String(),
				Action: "iam.api_key_used", Target: "api_key:" + keyID.String()})
		}
		return nil
	})
	// ServiceAccount:true marks this as a NON-HUMAN principal — the billing-suspension gate exempts
	// machine principals so a suspended tenant's telemetry/ingest keeps flowing (keep-protecting).
	return auth.Principal{UserID: saID, TenantID: tenantID, Role: auth.Role(role), Email: "svc:" + saID.String(), ServiceAccount: true}, nil
}
