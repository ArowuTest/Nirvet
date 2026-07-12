package soar

// §6.11 #188 HEAVY-2 (sub-commit 1) — the single-use, run-bound approval-link primitive. A customer approves a
// destructive run without a platform session, so the link IS the capability: a high-entropy token shown once,
// stored only as a SHA-256 hash, bound to a SPECIFIC run + tenant, and consumed ATOMICALLY exactly once. This is
// the replay fix (notify.VerifyLink is stateless HMAC = replayable; here consumption flips consumed_at in the same
// statement, so a replayed / expired / unknown token yields nothing).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// defaultApprovalLinkTTL is the fallback lifetime of an approval link (a containment authorization is short-lived;
// single-use + run-binding is the real protection, short TTL is defense-in-depth). Config-tunable in sub-commit 2.
const defaultApprovalLinkTTL = 3 * time.Hour

// hashToken is the at-rest form of a link token: SHA-256 hex. The raw token is never stored, so a DB read cannot
// recover a usable link.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// newApprovalToken mints a 256-bit URL-safe random token (shown to the caller once).
func newApprovalToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", httpx.ErrInternal("could not mint approval token")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// insertApprovalLink stores the hash of a fresh link bound to (tenant, run), tenant-scoped (RLS).
func (r *Repository) insertApprovalLink(ctx context.Context, tenantID, runID uuid.UUID, tokenHash string, expiresAt time.Time, createdBy uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO approval_link (tenant_id, run_id, token_hash, expires_at, created_by) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, runID, tokenHash, expiresAt, createdBy)
		return e
	})
}

// consumeApprovalLink atomically consumes a link by its token hash and returns the bound tenant + run. Runs through
// the SECURITY DEFINER consume_approval_link (no tenant session — the token is the capability). A replayed /
// expired / unknown token returns ErrNotFound.
func (r *Repository) consumeApprovalLink(ctx context.Context, tokenHash string) (tenantID, runID uuid.UUID, err error) {
	e := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id, run_id FROM consume_approval_link($1)`, tokenHash).Scan(&tenantID, &runID)
	})
	if e == pgx.ErrNoRows {
		return uuid.Nil, uuid.Nil, httpx.ErrNotFound("approval link is invalid, expired, or already used")
	}
	if e != nil {
		return uuid.Nil, uuid.Nil, e
	}
	return tenantID, runID, nil
}

// IssueApprovalLink mints a single-use link for a run that is pending approval, to send to the customer approver.
// Only a pending, tenant-owned run can have a link issued. Returns the raw token (shown once). Audited.
func (s *Service) IssueApprovalLink(ctx context.Context, p auth.Principal, runID uuid.UUID) (string, error) {
	run, err := s.repo.GetRun(ctx, p.TenantID, runID)
	if err != nil {
		return "", httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return "", httpx.ErrBadRequest("run is not pending approval")
	}
	raw, err := newApprovalToken()
	if err != nil {
		return "", err
	}
	// Link lifetime from the tenant's policy (config-tunable, default 3h) — containment authorization is short-lived.
	ttl := defaultApprovalLinkTTL
	if pol := s.resolveCustomerPolicy(ctx, p.TenantID); pol.LinkTTLSeconds >= 300 {
		ttl = time.Duration(pol.LinkTTLSeconds) * time.Second
	}
	if err := s.repo.insertApprovalLink(ctx, p.TenantID, runID, hashToken(raw), time.Now().Add(ttl), p.UserID); err != nil {
		return "", httpx.ErrInternal("could not issue approval link")
	}
	_ = s.repo.RunTx(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.approval_link_issue", Target: "run:" + runID.String(),
		})
	})
	return raw, nil
}
