// Package syslogd is the mTLS syslog-listener ingress (Ghana operator L connector) — the platform's first
// non-HTTP, unauthenticated-network ingress. Its whole job is to re-establish, over a channel with no JWT, the
// same tenant isolation the rest of the platform gets from authenticated principals:
//
//	MA-SYS-1 (mTLS enforced): tls.RequireAnyClientCert (a certless connection is rejected at the handshake) +
//	  a VerifyPeerCertificate that pins the client leaf-cert fingerprint against the syslog_sources registry —
//	  an unknown/disabled cert makes the handshake FAIL (rejected, not accepted-then-dropped).
//	MA-SYS-2 (attribution from the channel): the tenant is derived from the VERIFIED client cert's fingerprint,
//	  bound at connection-accept, immutable for the connection's life; the syslog PAYLOAD is never consulted for
//	  attribution — a sender cannot inject events attributed to another tenant.
//	MA-SYS-3 (revocation on live connections): the source's enabled-state is re-checked periodically on a
//	  long-lived connection, so a disabled/deleted source stops ingesting on its existing socket.
//	MA-SYS-4 (bounds): seeded max message size, max connections, timeouts, per-source rate limit, all bounded.
package syslogd

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Source is a registered syslog source: which tenant a client cert attributes to, and whether it is enabled.
type Source struct {
	TenantID uuid.UUID
	Enabled  bool
}

// SourceStore reads the syslog_sources registry. It is a platform registry (no per-tenant RLS), read via
// WithSystem — the listener has no tenant context at accept time; attribution is exactly what this returns.
type SourceStore struct{ db *database.DB }

// NewSourceStore builds the source store.
func NewSourceStore(db *database.DB) *SourceStore { return &SourceStore{db: db} }

// LookupByFingerprint returns the source registered for a client leaf-cert fingerprint (lowercase hex SHA-256).
// ok=false when no source is registered for the fingerprint (fail-closed: the listener rejects/drops). enabled
// is returned separately so a registered-but-disabled source is distinguishable (also rejected, but not a
// "spoof" — a provisioned source turned off).
func (s *SourceStore) LookupByFingerprint(ctx context.Context, fingerprint string) (Source, bool, error) {
	var src Source
	found := false
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT tenant_id, enabled FROM syslog_sources WHERE cert_fingerprint = $1`, fingerprint).
			Scan(&src.TenantID, &src.Enabled)
		if e == pgx.ErrNoRows {
			return nil // ok stays false — fail-closed
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	return src, found, err
}

// AuditDisabledReject records (under the source's OWN tenant) that a disabled source's cert tried to connect —
// data-owner-visible (LOW-SYS). Best-effort; a system-actor entry (no principal).
func (s *SourceStore) AuditDisabledReject(ctx context.Context, tenantID uuid.UUID, fingerprint string) {
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{Action: "syslog.source.rejected",
			Target: "fingerprint:" + fingerprint, Metadata: map[string]any{"reason": "disabled"}})
	})
}

// SourceRow is a registered source as listed by the padmin management surface (no key material beyond the
// fingerprint, which is public).
type SourceRow struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"cert_fingerprint"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// Create registers a source for a tenant, DISABLED by default (secure default — an operator must explicitly
// enable it). Returns the new id.
func (s *SourceStore) Create(ctx context.Context, tenantID uuid.UUID, name, fingerprint string) (uuid.UUID, error) {
	id := uuid.New()
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO syslog_sources (id, tenant_id, name, cert_fingerprint, enabled) VALUES ($1,$2,$3,$4,false)`,
			id, tenantID, name, fingerprint)
		return e
	})
	return id, err
}

// SetEnabled enables/disables a source (disabling is the revocation path — the listener stops honoring it on
// live connections at the next re-check, and rejects new handshakes).
func (s *SourceStore) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	return s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE syslog_sources SET enabled=$2 WHERE id=$1`, id, enabled)
		return e
	})
}

// Delete removes a source.
func (s *SourceStore) Delete(ctx context.Context, id uuid.UUID) error {
	return s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM syslog_sources WHERE id=$1`, id)
		return e
	})
}

// List returns all registered sources (padmin sees the whole registry).
func (s *SourceStore) List(ctx context.Context) ([]SourceRow, error) {
	var out []SourceRow
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, tenant_id, name, cert_fingerprint, enabled, created_at FROM syslog_sources ORDER BY created_at DESC`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r SourceRow
			if e := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Fingerprint, &r.Enabled, &r.CreatedAt); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
