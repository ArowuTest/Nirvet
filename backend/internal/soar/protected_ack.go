package soar

// D5 arm-gate — destructive SOAR may not be enabled for a tenant that has not DECIDED about its crown jewels.
//
// The invariant (reviewer, and it is the testable form of what the D5 reachability bug taught us):
//
//	A safety control must have a built-in floor that works with zero configuration — or must refuse to arm until
//	configured. An empty config table must never mean allow.
//
// internal/ai/redaction.go takes the first branch: a built-in compiled floor, always active, never disable-able,
// so a broken config never egresses cleartext. D5 cannot — Nirvet cannot guess that a given agency's domain
// controller is dc01.mofep.gov.gh. So D5 takes the second: refuse to arm.
//
// Note what is NOT required: a non-empty list. "You must designate at least one crown jewel" invites a dummy row,
// and a dummy row is worse than an empty list because it looks like a decision. The dangerous state was never "no
// protection" — it is "no protection that anybody decided on". So arming requires EITHER ≥1 designated target OR
// an explicit, audited attestation that this tenant designates none. Both are decisions; only one is a list.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CodeProtectedTargetsUndecided lets the console dispatch on the CODE rather than matching prose (the J2 lesson:
// prose gets reworded, codes are contract). The SPA uses it to route the operator to the designation screen.
const CodeProtectedTargetsUndecided = "protected_targets_undecided"

// ErrProtectedTargetsUndecided is returned when a tenant tries to arm destructive response having neither
// designated a crown jewel nor recorded that it has none.
func ErrProtectedTargetsUndecided() *httpx.APIError {
	return &httpx.APIError{
		Status: 409,
		Code:   CodeProtectedTargetsUndecided,
		Message: "destructive response cannot be enabled until this tenant's crown jewels are decided: " +
			"designate at least one protected host or identity, or record an explicit acknowledgement that " +
			"this tenant designates none. An empty deny-list does not withhold — it allows.",
	}
}

// ProtectedAck is the audited attestation that a tenant deliberately designates no crown jewels.
type ProtectedAck struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	AckedAt       time.Time `json:"acked_at"`
	AckedBy       uuid.UUID `json:"acked_by"`
	AckedByEmail  string    `json:"acked_by_email"`
	ConfirmedWith string    `json:"confirmed_with"`
	Note          string    `json:"note"`
}

// ProtectedDecision is the tenant's arm-readiness, for the console to render honestly.
type ProtectedDecision struct {
	TargetCount int           `json:"target_count"` // this tenant's OWN designations; inherited globals excluded
	Ack         *ProtectedAck `json:"ack"`          // nil when never attested
	Decided     bool          `json:"decided"`      // TargetCount > 0 || Ack != nil
}

// GetProtectedAck returns the tenant's attestation, or nil when there is none.
func (r *Repository) GetProtectedAck(ctx context.Context, tenantID uuid.UUID) (*ProtectedAck, error) {
	var a ProtectedAck
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, acked_at, acked_by, acked_by_email, confirmed_with, note
			   FROM soar_protected_ack WHERE tenant_id = $1`, tenantID).
			Scan(&a.TenantID, &a.AckedAt, &a.AckedBy, &a.AckedByEmail, &a.ConfirmedWith, &a.Note)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// SetProtectedAck records (or replaces) the attestation, audited.
func (r *Repository) SetProtectedAck(ctx context.Context, tenantID uuid.UUID, confirmedWith, note string, p auth.Principal) (ProtectedAck, error) {
	a := ProtectedAck{TenantID: tenantID, AckedBy: p.UserID, AckedByEmail: p.Email,
		ConfirmedWith: strings.TrimSpace(confirmedWith), Note: strings.TrimSpace(note)}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO soar_protected_ack (tenant_id, acked_by, acked_by_email, confirmed_with, note)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (tenant_id) DO UPDATE SET acked_at = now(), acked_by = EXCLUDED.acked_by,
			   acked_by_email = EXCLUDED.acked_by_email, confirmed_with = EXCLUDED.confirmed_with,
			   note = EXCLUDED.note
			 RETURNING acked_at`, tenantID, a.AckedBy, a.AckedByEmail, a.ConfirmedWith, a.Note).
			Scan(&a.AckedAt); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.protected_targets_ack",
			Target:   "tenant:" + tenantID.String(),
			Metadata: map[string]any{"confirmed_with": a.ConfirmedWith, "note": a.Note},
		})
	})
	if err != nil {
		return ProtectedAck{}, err
	}
	return a, nil
}

// ClearProtectedAck withdraws the attestation, audited. Withdrawing re-blocks a future arm; it does NOT disarm a
// tenant that is already enabled — see Service.ProtectedDecision's doc for why that is deliberate.
func (r *Repository) ClearProtectedAck(ctx context.Context, tenantID uuid.UUID, p auth.Principal) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM soar_protected_ack WHERE tenant_id = $1`, tenantID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.protected_targets_ack_withdraw",
			Target: "tenant:" + tenantID.String(),
		})
	})
}

// countProtectedTargets counts THIS TENANT'S OWN designations — deliberately excluding the inherited globals.
//
// This exclusion is the whole gate, and getting it wrong makes the gate a no-op. 0066 seeds four privileged Entra
// roles as GLOBAL rows (tenant_id NULL) that every tenant can read, so counting globals would put every tenant at
// >= 4 designations from birth, `Decided` would always be true, and this control would never once block an arm —
// a safety check that cannot fail, which is worse than no check because it reads like one.
//
// The distinction is not pedantic. Those four roles are OUR floor, not the tenant's decision — they are the
// redaction.go pattern correctly applied to the identity net, and they are why the L2 layer alone actually worked
// through this whole defect. The HOST net has no such floor and can have none: Nirvet cannot guess that an
// agency's domain controller is dc01.mofep.gov.gh. So what this gate demands is the thing no seed can supply —
// the tenant's own decision. `WHERE tenant_id IS NOT NULL` is own-rows-only, because RLS has already narrowed
// the visible set to own-or-global.
//
// A tenant that genuinely has nothing to designate is not stuck: that is exactly what the attestation is for.
//
// The predicate is `tenant_id = $1`, NOT `tenant_id IS NOT NULL`, and that is deliberate belt-and-braces rather
// than redundancy. `IS NOT NULL` leans entirely on RLS to narrow the visible set to this tenant — correct in
// production, where the app connects as the non-bypass role nirvet_app, and catastrophically wrong under any
// connection that bypasses RLS: the count then sweeps the WHOLE FLEET's designations, reports Decided=true for a
// tenant that has decided nothing, and arms destructive response. Silently. That is the exact failure this whole
// arc exists to retire, so the gate does not get to depend on a single control being in effect. It is also the
// pattern the sibling writes here already use (DeleteProtectedTarget: `WHERE id = $1 AND tenant_id = $2`).
//
// Found the hard way: this query returned 33 for a brand-new tenant against a superuser DSN. CI connects as
// nirvet_app, so it would have been green there and the fragility would have shipped unseen.
func (r *Repository) countProtectedTargets(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM protected_hosts           WHERE tenant_id = $1)
			     + (SELECT count(*) FROM protected_identities      WHERE tenant_id = $1)
			     + (SELECT count(*) FROM protected_directory_roles WHERE tenant_id = $1)`, tenantID).Scan(&n)
	})
	return n, err
}

// ProtectedDecision reports whether the tenant has decided about its crown jewels, and how.
//
// This is checked when ARMING (SetSettings), not on every run. Arming is the moment a human chooses to let
// software take destructive action unattended; that is where the decision belongs. A per-run check would add a
// query to the hot path to re-litigate a decision already made, and — worse — could disarm a tenant mid-incident
// because someone withdrew an attestation, which is its own outage.
func (s *Service) ProtectedDecision(ctx context.Context, tenantID uuid.UUID) (ProtectedDecision, error) {
	n, err := s.repo.countProtectedTargets(ctx, tenantID)
	if err != nil {
		return ProtectedDecision{}, httpx.ErrInternal("could not read protected targets")
	}
	ack, err := s.repo.GetProtectedAck(ctx, tenantID)
	if err != nil {
		return ProtectedDecision{}, httpx.ErrInternal("could not read the protected-target acknowledgement")
	}
	return ProtectedDecision{TargetCount: n, Ack: ack, Decided: n > 0 || ack != nil}, nil
}

// AckProtectedTargets records the attestation that this tenant designates no crown jewels.
func (s *Service) AckProtectedTargets(ctx context.Context, p auth.Principal, confirmedWith, note string) (ProtectedAck, error) {
	// confirmed_with is mandatory and must be a real name. The SOC cannot know whether an agency has a crown
	// jewel — only the agency can. An attestation with nobody's name on it is the silent default wearing a hat.
	cw := strings.TrimSpace(confirmedWith)
	if len(cw) < 3 {
		return ProtectedAck{}, httpx.ErrBadRequest(
			"confirmed_with is required: name the person at the customer who confirmed this tenant has no " +
				"crown jewels. Nirvet cannot make that determination on their behalf.")
	}
	if len(cw) > 200 {
		return ProtectedAck{}, httpx.ErrBadRequest("confirmed_with is too long (max 200 characters)")
	}
	a, err := s.repo.SetProtectedAck(ctx, p.TenantID, cw, note, p)
	if err != nil {
		return ProtectedAck{}, httpx.ErrInternal("could not record the acknowledgement")
	}
	return a, nil
}

// WithdrawProtectedTargetsAck removes the attestation.
func (s *Service) WithdrawProtectedTargetsAck(ctx context.Context, p auth.Principal) error {
	if err := s.repo.ClearProtectedAck(ctx, p.TenantID, p); err != nil {
		return httpx.ErrInternal("could not withdraw the acknowledgement")
	}
	return nil
}
