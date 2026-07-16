package soar

// §6.11 D5 protected-target designation — the WRITE path for the crown-jewel deny-lists the guards already read.
//
// The guards have always read these tables (connector.EntraProtectedGuard L1, connector.HostProtectedGuard M3),
// and 0066/0098 created them so "the tenant/operator designates its crown jewels" — but nothing ever wrote to
// them. No route, no UI, no Go writer; the only INSERT in the tree is in an integration test. And an empty
// deny-list does NOT withhold: host_guard.go returns allow on len(patterns)==0. So the net designated nothing,
// caught nothing, and logged nothing while doing it. This is the missing surface.
//
// Authority is asymmetric on purpose, mirroring the existing "config overrides may only tighten" guardrail:
// ADD tightens the net (more refusals → manager), DELETE weakens it (a crown jewel becomes auto-isolatable →
// platform-admin). Global (tenant_id NULL) rows are instance-wide and read-only here: RLS
// WITH CHECK (tenant_id = app_current_tenant()) makes the app role structurally unable to write them, so globals
// stay migration-seeded and no handler can remove a protection it did not create.

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// ProtectedKind selects which deny-list a target belongs to. The two are NOT symmetric in how the guards match
// them, which is the single most important thing to know before designating one:
//
//	host     — connector.HostProtectedGuard matches the pattern as a case-insensitive SUBSTRING of the resolved
//	           host (computerDnsName / machine id). "sql" protects sql01, sql02, and mysql-test. Broad by nature.
//	identity — connector.EntraProtectedGuard matches the ref EXACTLY (a lower-cased set membership) against the
//	           UPN and the resolved object id. A partial UPN protects NOTHING.
//
// Over-matching only ever withholds more (fail-safe: the run escalates to a human). Under-matching is the
// dangerous direction — it silently leaves a crown jewel auto-isolatable — which is why the exact-match kind
// gets the stricter input validation.
type ProtectedKind string

// The two protected-target deny-lists.
const (
	ProtectedKindHost     ProtectedKind = "host"
	ProtectedKindIdentity ProtectedKind = "identity"
)

// ProtectedTarget is one designated crown jewel, normalised across the two underlying tables (protected_hosts
// stores pattern/note; protected_identities stores identity_ref/reason).
type ProtectedTarget struct {
	ID        uuid.UUID     `json:"id"`
	Kind      ProtectedKind `json:"kind"`
	Value     string        `json:"value"`
	Note      string        `json:"note"`
	Global    bool          `json:"global"` // instance-wide (tenant_id NULL): visible to all tenants, editable by none
	CreatedAt time.Time     `json:"created_at"`
}

// protectedSpec holds fully-static SQL per kind. The kind is a closed enum resolved through this map, so no
// identifier is ever interpolated into a statement and every value is a bound parameter.
type protectedSpec struct {
	list   string
	insert string
	del    string
}

var protectedSpecs = map[ProtectedKind]protectedSpec{
	ProtectedKindHost: {
		list: `SELECT id, pattern, note, tenant_id IS NULL, created_at FROM protected_hosts
		        ORDER BY (tenant_id IS NULL) DESC, lower(pattern)`,
		insert: `INSERT INTO protected_hosts (tenant_id, pattern, note) VALUES ($1,$2,$3) RETURNING id, created_at`,
		del:    `DELETE FROM protected_hosts WHERE id = $1 AND tenant_id = $2`,
	},
	ProtectedKindIdentity: {
		list: `SELECT id, identity_ref, reason, tenant_id IS NULL, created_at FROM protected_identities
		        ORDER BY (tenant_id IS NULL) DESC, lower(identity_ref)`,
		insert: `INSERT INTO protected_identities (tenant_id, identity_ref, reason) VALUES ($1,$2,$3) RETURNING id, created_at`,
		del:    `DELETE FROM protected_identities WHERE id = $1 AND tenant_id = $2`,
	},
}

// ParseProtectedKind validates the kind path segment.
func ParseProtectedKind(s string) (ProtectedKind, error) {
	k := ProtectedKind(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := protectedSpecs[k]; !ok {
		return "", httpx.ErrBadRequest("kind must be 'host' or 'identity'")
	}
	return k, nil
}

// globChars are the metacharacters that mean "match anything" in every tool an operator has ever used, and mean
// NOTHING here: the host guard runs a literal strings.Contains, the identity guard a literal equality test. So
// "*.corp.gov.gh" matches only a host whose name literally contains an asterisk — i.e. nothing at all. An
// operator globbing to protect a whole domain would get ZERO protection and no error: the deny-list would read as
// populated in the UI while every containment sailed straight past it. That silent fail-open is the exact defect
// this slice exists to retire, so it is refused at the door.
//
// Only these three: none is legal in a DNS name or a UPN, so their presence is always a globbing mistake and
// never a real crown jewel. Notably absent are '.', '_' and '-', which are ordinary in hostnames
// (dc01.corp.gov.gh) and service accounts (svc_backup) and must be accepted.
const globChars = "*?%"

// containsGlob reports whether a value carries a wildcard ANYWHERE — not merely whether it is made only of them.
// The narrower "is it entirely wildcards" test passes "*.corp.*" straight through, which is the likelier mistake
// and the more dangerous one: it looks like a considered, specific rule.
func containsGlob(s string) bool { return strings.ContainsAny(s, globChars) }

const maxProtectedValue = 253 // a DNS name's maximum length; UPNs and object ids are comfortably shorter

// validateProtectedValue enforces the input rules that differ by matching semantics.
func validateProtectedValue(kind ProtectedKind, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", httpx.ErrBadRequest("value is required")
	}
	if len(v) > maxProtectedValue {
		return "", httpx.ErrBadRequest("value is too long (max 253 characters)")
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return "", httpx.ErrBadRequest("value must not contain whitespace")
	}
	if containsGlob(v) {
		return "", httpx.ErrBadRequest(
			"wildcards are not supported and would protect nothing: host patterns match as a literal " +
				"case-insensitive substring, identities match exactly. Drop the wildcard — 'dc01' already " +
				"protects dc01.corp.gov.gh — or enter a full UPN / object id for an identity.")
	}
	if kind == ProtectedKindHost && len(v) < 2 {
		// A 1-character substring matches nearly every host, which withholds nearly every isolate. That is
		// fail-safe rather than dangerous, but it is never what anyone means, and it would quietly disable the
		// tenant's whole containment capability.
		return "", httpx.ErrBadRequest("host pattern must be at least 2 characters (it matches as a substring)")
	}
	if kind == ProtectedKindIdentity && !strings.Contains(v, "@") && !isUUIDish(v) {
		// The identity guard matches EXACTLY, so a fragment protects nothing while looking like it protects
		// something. Require the two forms the guard can actually match: a UPN or an object id.
		return "", httpx.ErrBadRequest(
			"identity must be a full UPN (user@domain) or an object id — the identity deny-list matches exactly, " +
				"so a partial value would protect nothing")
	}
	return v, nil
}

func isUUIDish(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// ListProtectedTargets returns the tenant's own designations plus the instance-wide globals it inherits.
func (r *Repository) ListProtectedTargets(ctx context.Context, tenantID uuid.UUID, kind ProtectedKind) ([]ProtectedTarget, error) {
	spec, ok := protectedSpecs[kind]
	if !ok {
		return nil, httpx.ErrBadRequest("unknown protected-target kind")
	}
	out := []ProtectedTarget{}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, spec.list)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t := ProtectedTarget{Kind: kind}
			if err := rows.Scan(&t.ID, &t.Value, &t.Note, &t.Global, &t.CreatedAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// AddProtectedTarget designates a tenant-owned crown jewel (TIGHTENS the net) and audits it atomically.
func (r *Repository) AddProtectedTarget(ctx context.Context, tenantID uuid.UUID, kind ProtectedKind, value, note string, p auth.Principal) (ProtectedTarget, error) {
	spec, ok := protectedSpecs[kind]
	if !ok {
		return ProtectedTarget{}, httpx.ErrBadRequest("unknown protected-target kind")
	}
	v, err := validateProtectedValue(kind, value)
	if err != nil {
		return ProtectedTarget{}, err
	}
	t := ProtectedTarget{Kind: kind, Value: v, Note: strings.TrimSpace(note)}
	err = r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, spec.insert, tenantID, t.Value, t.Note).Scan(&t.ID, &t.CreatedAt); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.protected_target_add",
			Target:   string(kind) + ":" + t.Value,
			Metadata: map[string]any{"kind": string(kind), "value": t.Value, "note": t.Note},
		})
	})
	if err != nil {
		return ProtectedTarget{}, err
	}
	return t, nil
}

// DeleteProtectedTarget removes a tenant-owned designation (WEAKENS the net — the target becomes auto-isolatable
// again) and audits it atomically. found=false when the id is not a tenant-owned row of this kind: a global row
// is filtered by the `tenant_id = $2` predicate as well as by the RLS DELETE policy, so an instance-wide
// protection cannot be dropped through this path even by a platform admin.
func (r *Repository) DeleteProtectedTarget(ctx context.Context, tenantID uuid.UUID, kind ProtectedKind, id uuid.UUID, p auth.Principal) (bool, error) {
	spec, ok := protectedSpecs[kind]
	if !ok {
		return false, httpx.ErrBadRequest("unknown protected-target kind")
	}
	found := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, spec.del, id, tenantID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		found = true
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.protected_target_remove",
			Target:   string(kind) + ":" + id.String(),
			Metadata: map[string]any{"kind": string(kind), "id": id.String()},
		})
	})
	return found, err
}

// ProtectedTargets lists a tenant's designations (own + inherited globals).
func (s *Service) ProtectedTargets(ctx context.Context, tenantID uuid.UUID, kind ProtectedKind) ([]ProtectedTarget, error) {
	return s.repo.ListProtectedTargets(ctx, tenantID, kind)
}

// AddProtectedTarget designates a crown jewel for the caller's tenant.
func (s *Service) AddProtectedTarget(ctx context.Context, p auth.Principal, kind ProtectedKind, value, note string) (ProtectedTarget, error) {
	return s.repo.AddProtectedTarget(ctx, p.TenantID, kind, value, note, p)
}

// RemoveProtectedTarget undesignates a crown jewel for the caller's tenant.
func (s *Service) RemoveProtectedTarget(ctx context.Context, p auth.Principal, kind ProtectedKind, id uuid.UUID) error {
	found, err := s.repo.DeleteProtectedTarget(ctx, p.TenantID, kind, id, p)
	if err != nil {
		return err
	}
	if !found {
		return httpx.ErrNotFound("protected target not found (instance-wide protections cannot be removed here)")
	}
	return nil
}
