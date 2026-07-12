package tenant

// Tenant profile & governance (SRS §6.1: TEN-004 status lifecycle, TEN-006 org profile /
// escalation matrix / business hours / authority-to-act policy, TEN-010 change history).
// Every policy is an admin-configurable row with a seeded default — nothing hardcoded.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/ArowuTest/nirvet/internal/platform/severity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// --- status lifecycle (TEN-004) ---

const (
	StatusProspect  Status = "prospect"
	StatusChurned   Status = "churned"
	StatusArchived  Status = "archived"
	StatusLegalHold Status = "legal_hold"
)

// statusTransitions is the allowed state machine (structural domain vocabulary, not a
// per-tenant tunable). An unlisted transition is rejected fail-closed.
var statusTransitions = map[Status][]Status{
	StatusProspect:   {StatusOnboarding, StatusChurned, StatusArchived},
	StatusOnboarding: {StatusActive, StatusSuspended, StatusChurned, StatusArchived},
	StatusActive:     {StatusSuspended, StatusChurned, StatusLegalHold, StatusArchived},
	StatusSuspended:  {StatusActive, StatusChurned, StatusLegalHold, StatusArchived},
	StatusChurned:    {StatusActive, StatusArchived},
	StatusLegalHold:  {StatusActive, StatusArchived},
	StatusArchived:   {},
}

func canTransition(from, to Status) bool {
	for _, s := range statusTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// --- config value types ---

// Profile is a tenant's org profile (TEN-006): timezone, weekly business hours, legal/
// regulatory profile and critical-asset notes. All admin-configurable.
type Profile struct {
	TenantID            uuid.UUID       `json:"tenant_id"`
	Timezone            string          `json:"timezone"`
	BusinessHours       json.RawMessage `json:"business_hours"`
	LegalRegulatory     json.RawMessage `json:"legal_regulatory"`
	CriticalAssetsNotes string          `json:"critical_assets_notes"`
}

// ProfileInput updates the org profile (all fields optional; nil/empty leaves unchanged).
type ProfileInput struct {
	Timezone            *string         `json:"timezone"`
	BusinessHours       json.RawMessage `json:"business_hours"`
	LegalRegulatory     json.RawMessage `json:"legal_regulatory"`
	CriticalAssetsNotes *string         `json:"critical_assets_notes"`
}

// EscalationContact is one entry in the tenant escalation matrix (TEN-006). §6.16 routing
// consumes it: fire contacts whose min_severity ≤ the event severity, in order_index order.
type EscalationContact struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	MinSeverity string    `json:"min_severity"`
	OrderIndex  int       `json:"order_index"`
	Channel     string    `json:"channel"`
	Address     string    `json:"address"`
	Category    string    `json:"category"` // #188 routing scope ('' = all categories)
	Active      bool      `json:"active"`
}

// AuthorityPolicy is the authority-to-act rule for an action type (TEN-006 / SOAR-003).
// mode decides whether a response action may run and whether it needs approval; the seeded
// default ('*' => approval) is fail-closed so no unconfigured tenant auto-executes (NFR-009).
type AuthorityPolicy struct {
	ID                uuid.UUID `json:"id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	ActionType        string    `json:"action_type"`
	Mode              string    `json:"mode"`
	ApproverRole      string    `json:"approver_role"`
	BusinessHoursOnly bool      `json:"business_hours_only"`
	Active            bool      `json:"active"`
}

// ChangeHistoryEntry is one append-only material-settings change (TEN-010).
type ChangeHistoryEntry struct {
	ID         uuid.UUID `json:"id"`
	ActorEmail string    `json:"actor_email"`
	Entity     string    `json:"entity"`
	Field      string    `json:"field"`
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
	At         string    `json:"at"`
}

var validSeverity = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}
var validChannel = map[string]bool{"email": true, "sms": true, "webhook": true, "teams": true, "slack": true}
var validAuthorityMode = map[string]bool{"observe": true, "approval": true, "pre_authorized": true, "emergency": true}

// validateEscalationAddress checks an escalation-contact address for its channel (Round-4 L4). The
// URL channels (webhook/teams/slack) must be https and must NOT target an internal/loopback/link-
// local host or the cloud metadata endpoint — §6.16 routing POSTs to these, so an unvalidated
// address is an SSRF/exfil surface. This is the WRITE-TIME guard only; a hostname (non-literal-IP)
// passes here and MUST be re-resolved and re-checked at SEND time when the outbound webhook channel
// is built (§6.16) — that DNS-rebinding defence is NOT present yet (the notifier is a log stub).
func validateEscalationAddress(channel, address string) error {
	address = strings.TrimSpace(address)
	switch channel {
	case "email":
		if !strings.Contains(address, "@") || strings.ContainsAny(address, " \t") {
			return httpx.ErrBadRequest("invalid email address")
		}
	case "sms":
		if len(address) < 5 {
			return httpx.ErrBadRequest("invalid phone number")
		}
	case "webhook", "teams", "slack":
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return httpx.ErrBadRequest(channel + " address must be an absolute https URL")
		}
		if netsafe.IsInternalHost(u.Hostname()) {
			return httpx.ErrForbidden("webhook address may not target an internal, loopback, or metadata host")
		}
	}
	return nil
}

// =========================== repository (governance) ===========================

// recordChange appends an immutable change-history row inside an existing tenant tx (TEN-010).
func recordChange(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p auth.Principal, entity, field, oldV, newV string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_change_history (id, tenant_id, actor_id, actor_email, entity, field, old_value, new_value)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.New(), tenantID, p.UserID, p.Email, entity, field, oldV, newV)
	return err
}

// SeedGovernance inserts the default profile + fail-closed catch-all authority policy for a
// tenant (idempotent). Called in a WithTenant tx from tenant.Create so no new tenant is ever
// unconfigured; the migration seeds pre-existing tenants.
func (r *Repository) SeedGovernance(ctx context.Context, tenantID uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return r.seedGovernanceTx(ctx, tx, tenantID)
	})
}

// seedGovernanceTx inserts the default profile + fail-closed catch-all authority policy + SLA/correlation
// defaults for a tenant (idempotent) in a caller-provided WithTenant tx. Extracted so CreateSeeded can run it
// atomically in the SAME transaction as the tenants INSERT (ONB-1) — single-create and batch share this body,
// so secure defaults cannot drift between the two paths.
func (r *Repository) seedGovernanceTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_profiles (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return err
	}
	// Seeded catch-all is 'observe' — the most fail-closed mode: NO response action
	// auto-executes until an admin configures otherwise (matches the platform's prior
	// default and what SOAR consumes via ResolveAuthority; Phase 0 reconciliation).
	if _, err := tx.Exec(ctx,
		`INSERT INTO authority_policies (id, tenant_id, action_type, mode) VALUES ($1,$2,'*','observe')
			 ON CONFLICT (tenant_id, action_type) DO NOTHING`, uuid.New(), tenantID); err != nil {
		return err
	}
	// §6.8 SLA targets + §6.7 correlation policy: seed the admin-configurable defaults so
	// no new tenant is unconfigured and the incident/correlation resolvers always find a row
	// (Phase 0-D no-hardcoding). Values come from the Go seeded-default maps in policy.go.
	for sev, secs := range defaultSLASeconds {
		if _, err := tx.Exec(ctx,
			`INSERT INTO sla_policies (tenant_id, severity, ack_seconds, resolve_seconds)
				 VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id, severity) DO NOTHING`,
			tenantID, sev, secs[0], secs[1]); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO correlation_policies (tenant_id, window_seconds, promote_threshold, min_alerts_for_promotion)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID, defaultCorrelationWindowSeconds, defaultCorrelationPromote, defaultCorrelationMinAlerts)
	return err
}

func (r *Repository) getProfile(ctx context.Context, tenantID uuid.UUID) (*Profile, error) {
	var p Profile
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, timezone, business_hours, legal_regulatory, critical_assets_notes
			   FROM tenant_profiles WHERE tenant_id=$1`, tenantID).
			Scan(&p.TenantID, &p.Timezone, &p.BusinessHours, &p.LegalRegulatory, &p.CriticalAssetsNotes)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// =========================== service (governance) ===========================

// GetProfile returns the tenant's org profile, seeding the default row if none exists yet
// (so the response is always the configurable default, never empty).
func (s *Service) GetProfile(ctx context.Context, tenantID uuid.UUID) (*Profile, error) {
	p, err := s.repo.getProfile(ctx, tenantID)
	if err == pgx.ErrNoRows {
		if serr := s.repo.SeedGovernance(ctx, tenantID); serr != nil {
			return nil, httpx.ErrInternal("could not initialise tenant profile")
		}
		p, err = s.repo.getProfile(ctx, tenantID)
	}
	if err != nil {
		return nil, httpx.ErrInternal("could not load tenant profile")
	}
	return p, nil
}

// UpdateProfile applies a partial profile update, recording each changed field to the
// append-only change history and the audit log (TEN-006/TEN-010).
func (s *Service) UpdateProfile(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in ProfileInput) (*Profile, error) {
	if in.BusinessHours != nil && !json.Valid(in.BusinessHours) {
		return nil, httpx.ErrBadRequest("business_hours must be valid JSON")
	}
	if in.LegalRegulatory != nil && !json.Valid(in.LegalRegulatory) {
		return nil, httpx.ErrBadRequest("legal_regulatory must be valid JSON")
	}
	prev, err := s.GetProfile(ctx, tenantID) // ensures a row exists
	if err != nil {
		return nil, err
	}
	err = s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		set := []string{"updated_at=now()"}
		args := []any{tenantID}
		add := func(col string, val any) {
			args = append(args, val)
			set = append(set, fmt.Sprintf("%s=$%d", col, len(args)))
		}
		if in.Timezone != nil && *in.Timezone != prev.Timezone {
			add("timezone", strings.TrimSpace(*in.Timezone))
			if e := recordChange(ctx, tx, tenantID, p, "profile", "timezone", prev.Timezone, *in.Timezone); e != nil {
				return e
			}
		}
		if in.BusinessHours != nil {
			add("business_hours", []byte(in.BusinessHours))
			if e := recordChange(ctx, tx, tenantID, p, "profile", "business_hours", string(prev.BusinessHours), string(in.BusinessHours)); e != nil {
				return e
			}
		}
		if in.LegalRegulatory != nil {
			add("legal_regulatory", []byte(in.LegalRegulatory))
			if e := recordChange(ctx, tx, tenantID, p, "profile", "legal_regulatory", string(prev.LegalRegulatory), string(in.LegalRegulatory)); e != nil {
				return e
			}
		}
		if in.CriticalAssetsNotes != nil && *in.CriticalAssetsNotes != prev.CriticalAssetsNotes {
			add("critical_assets_notes", *in.CriticalAssetsNotes)
			if e := recordChange(ctx, tx, tenantID, p, "profile", "critical_assets_notes", prev.CriticalAssetsNotes, *in.CriticalAssetsNotes); e != nil {
				return e
			}
		}
		if len(set) == 1 { // nothing changed but updated_at
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE tenant_profiles SET `+strings.Join(set, ", ")+` WHERE tenant_id=$1`, args...)
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.profile_update", Target: "tenant:" + tenantID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not update tenant profile")
	}
	return s.GetProfile(ctx, tenantID)
}

// SetStatus performs a guarded tenant status transition (TEN-004), recording it to the
// change history + audit. The tenants registry is platform-level (WithSystem); the history
// is tenant-scoped (WithTenant).
func (s *Service) SetStatus(ctx context.Context, p auth.Principal, tenantID uuid.UUID, to Status, reason string) (*Tenant, error) {
	cur, err := s.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrNotFound("tenant not found")
	}
	if _, ok := statusTransitions[to]; !ok && to != cur.Status {
		return nil, httpx.ErrBadRequest("unknown target status")
	}
	if cur.Status == to {
		return cur, nil // idempotent
	}
	if !canTransition(cur.Status, to) {
		return nil, httpx.ErrBadRequest(fmt.Sprintf("illegal status transition %s -> %s", cur.Status, to))
	}
	// Round-4 M8: write the TEN-010 change-history + audit FIRST and PROPAGATE its error — a sensitive
	// transition (active→legal_hold/archived) must never persist without its audit trail. The tenants
	// registry is platform-level (WithSystem) and the history is tenant-RLS (WithTenant), so they can't
	// share one tx; ordering history-before-status and failing on its error closes the evidentiary
	// hole the previously-swallowed `_ =` left. (A rare status-update failure after history is written
	// only leaves an extra history row on retry — never a status change with no history.)
	if err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if e := recordChange(ctx, tx, tenantID, p, "status", "status", string(cur.Status), string(to)+" ("+reason+")"); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.status_change",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"from": cur.Status, "to": to, "reason": reason}})
	}); err != nil {
		return nil, httpx.ErrInternal("could not record tenant status change")
	}
	if err := s.repo.setStatus(ctx, tenantID, to); err != nil {
		return nil, httpx.ErrInternal("could not update tenant status")
	}
	cur.Status = to
	return cur, nil
}

// ListEscalationContacts / AddEscalationContact / DeleteEscalationContact manage the matrix.
func (s *Service) ListEscalationContacts(ctx context.Context, tenantID uuid.UUID) ([]EscalationContact, error) {
	return s.repo.listEscalationContacts(ctx, tenantID)
}

// ResolveEscalation returns the active escalation contacts that fire at or above the given severity, in escalation
// (order_index) order — the routing seam §6.16/incident consumes (implements incident.EscalationResolver). This is
// the category-AGNOSTIC form: it broadcasts to ALL matching contacts regardless of their category scope, so
// existing callers (and category-less notifications like cred-expiry reminders) are unchanged.
func (s *Service) ResolveEscalation(ctx context.Context, tenantID uuid.UUID, sevLevel string) ([]incident.EscalationTarget, error) {
	return s.ResolveEscalationFor(ctx, tenantID, sevLevel, "")
}

// ResolveEscalationFor is the category-scoped router (#188). A contact fires when its min_severity is at/below the
// notification severity AND its category scope matches: an empty `category` argument broadcasts to ALL contacts
// (category-agnostic notification); a non-empty `category` routes to GENERAL contacts (category='') PLUS contacts
// scoped to exactly that category — so a "network" incident never pages the identity-only on-call. Severity
// ordering is the canonical §10.2 scale.
func (s *Service) ResolveEscalationFor(ctx context.Context, tenantID uuid.UUID, sevLevel, category string) ([]incident.EscalationTarget, error) {
	contacts, err := s.repo.listEscalationContacts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	want := severity.Rank(sevLevel)
	var out []incident.EscalationTarget
	for _, c := range contacts {
		if !c.Active || severity.Rank(c.MinSeverity) > want {
			continue
		}
		// Category gate: broadcast when the notification has no category; otherwise general + same-category only.
		if category != "" && c.Category != "" && c.Category != category {
			continue
		}
		out = append(out, incident.EscalationTarget{Channel: c.Channel, Address: c.Address})
	}
	return out, nil
}

// EscalationInput adds a contact to the escalation matrix.
type EscalationInput struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	MinSeverity string `json:"min_severity"`
	OrderIndex  int    `json:"order_index"`
	Channel     string `json:"channel"`
	Address     string `json:"address"`
	Category    string `json:"category"` // #188 optional routing scope ('' = all categories)
}

func (s *Service) AddEscalationContact(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in EscalationInput) (*EscalationContact, error) {
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Address) == "" {
		return nil, httpx.ErrBadRequest("name and address are required")
	}
	if in.MinSeverity == "" {
		in.MinSeverity = "high"
	}
	if !validSeverity[in.MinSeverity] {
		return nil, httpx.ErrBadRequest("invalid min_severity")
	}
	if in.Channel == "" {
		in.Channel = "email"
	}
	if !validChannel[in.Channel] {
		return nil, httpx.ErrBadRequest("invalid channel")
	}
	// Round-4 L4: validate the address per channel at write time — §6.16 routing will POST to webhook/
	// teams/slack addresses, so an unvalidated internal URL is an SSRF/exfil surface. The notifier
	// re-checks at send time (defence in depth).
	if err := validateEscalationAddress(in.Channel, in.Address); err != nil {
		return nil, err
	}
	in.Category = strings.TrimSpace(in.Category)
	if len(in.Category) > 64 {
		return nil, httpx.ErrBadRequest("category too long (max 64)")
	}
	c := &EscalationContact{ID: uuid.New(), TenantID: tenantID, Name: in.Name, Role: in.Role,
		MinSeverity: in.MinSeverity, OrderIndex: in.OrderIndex, Channel: in.Channel, Address: in.Address, Category: in.Category, Active: true}
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO escalation_contacts (id, tenant_id, name, role, min_severity, order_index, channel, address, category, active)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true)`,
			c.ID, tenantID, c.Name, c.Role, c.MinSeverity, c.OrderIndex, c.Channel, c.Address, c.Category); e != nil {
			return e
		}
		if e := recordChange(ctx, tx, tenantID, p, "escalation", "add", "", c.Name+"/"+c.Channel); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.escalation_add", Target: "tenant:" + tenantID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not add escalation contact")
	}
	return c, nil
}

func (s *Service) DeleteEscalationContact(ctx context.Context, p auth.Principal, tenantID, id uuid.UUID) error {
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM escalation_contacts WHERE id=$1`, id)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		if e := recordChange(ctx, tx, tenantID, p, "escalation", "delete", id.String(), ""); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.escalation_delete", Target: "tenant:" + tenantID.String()})
	})
	if err == pgx.ErrNoRows {
		return httpx.ErrNotFound("escalation contact not found")
	}
	if err != nil {
		return httpx.ErrInternal("could not delete escalation contact")
	}
	return nil
}

// ListAuthorityPolicies / SetAuthorityPolicy manage authority-to-act config (TEN-006/SOAR-003).
func (s *Service) ListAuthorityPolicies(ctx context.Context, tenantID uuid.UUID) ([]AuthorityPolicy, error) {
	return s.repo.listAuthorityPolicies(ctx, tenantID)
}

// AuthorityInput upserts an authority-to-act policy for an action type.
type AuthorityInput struct {
	ActionType        string `json:"action_type"`
	Mode              string `json:"mode"`
	ApproverRole      string `json:"approver_role"`
	BusinessHoursOnly bool   `json:"business_hours_only"`
}

func (s *Service) SetAuthorityPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in AuthorityInput) (*AuthorityPolicy, error) {
	in.ActionType = strings.TrimSpace(in.ActionType)
	if in.ActionType == "" {
		in.ActionType = "*"
	}
	if !validAuthorityMode[in.Mode] {
		return nil, httpx.ErrBadRequest("invalid mode: observe|approval|pre_authorized|emergency")
	}
	// Round-4 L3: the blanket '*' catch-all may only set a RESTRICTIVE mode (observe|approval).
	// Permissive modes (pre_authorized|emergency) auto-run actions, so they must be scoped to a
	// specific action_type — a single customer-side change must not drop the response gate for EVERY
	// action at once.
	if in.ActionType == "*" && (in.Mode == "pre_authorized" || in.Mode == "emergency") {
		return nil, httpx.ErrBadRequest("the '*' catch-all may only be 'observe' or 'approval'; scope pre_authorized/emergency to a specific action_type")
	}
	// Round-4 R-3: a PERMISSIVE mode (auto-runs the action) requires a provider platform_admin —
	// a customer_admin may only TIGHTEN (observe|approval), never unilaterally enable autonomous
	// containment for a specific action (e.g. isolate_endpoint → emergency). Overrides tighten only.
	if (in.Mode == "pre_authorized" || in.Mode == "emergency") && p.Role != auth.RolePlatformAdmin {
		return nil, httpx.ErrForbidden("a permissive authority mode (pre_authorized/emergency) may only be set by a platform_admin")
	}
	ap := &AuthorityPolicy{ID: uuid.New(), TenantID: tenantID, ActionType: in.ActionType, Mode: in.Mode,
		ApproverRole: in.ApproverRole, BusinessHoursOnly: in.BusinessHoursOnly, Active: true}
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx,
			`INSERT INTO authority_policies (id, tenant_id, action_type, mode, approver_role, business_hours_only, active)
			 VALUES ($1,$2,$3,$4,$5,$6,true)
			 ON CONFLICT (tenant_id, action_type) DO UPDATE
			   SET mode=EXCLUDED.mode, approver_role=EXCLUDED.approver_role,
			       business_hours_only=EXCLUDED.business_hours_only, active=true
			 RETURNING id`,
			ap.ID, tenantID, ap.ActionType, ap.Mode, ap.ApproverRole, ap.BusinessHoursOnly).Scan(&ap.ID); e != nil {
			return e
		}
		if e := recordChange(ctx, tx, tenantID, p, "authority", in.ActionType, "", in.Mode); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.authority_set",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"action_type": in.ActionType, "mode": in.Mode}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not set authority policy")
	}
	return ap, nil
}

// ResolveAuthority returns the effective authority mode for an action type, falling back to
// the '*' catch-all and finally to fail-closed 'observe' (nothing auto-executes) if nothing is
// configured. This is the seam §6.11 SOAR consumes; the fallback is defense-in-depth (NFR-009).
func (s *Service) ResolveAuthority(ctx context.Context, tenantID uuid.UUID, actionType string) (AuthorityPolicy, error) {
	pols, err := s.repo.listAuthorityPolicies(ctx, tenantID)
	if err != nil {
		return AuthorityPolicy{Mode: "observe"}, err
	}
	var star *AuthorityPolicy
	for i := range pols {
		if !pols[i].Active {
			continue
		}
		if pols[i].ActionType == actionType {
			return pols[i], nil
		}
		if pols[i].ActionType == "*" {
			star = &pols[i]
		}
	}
	if star != nil {
		return *star, nil
	}
	return AuthorityPolicy{TenantID: tenantID, ActionType: actionType, Mode: "observe", Active: true}, nil
}

// ResolveAuthorityMode returns just the effective mode string (implements soar.Authorizer).
func (s *Service) ResolveAuthorityMode(ctx context.Context, tenantID uuid.UUID, actionType string) (string, error) {
	ap, err := s.ResolveAuthority(ctx, tenantID, actionType)
	return ap.Mode, err
}

// ResolveAuthorityDecision returns the effective mode + approver-role floor + business-hours-only
// flag for an action (implements soar.Authorizer) so SOAR can enforce the stored controls.
func (s *Service) ResolveAuthorityDecision(ctx context.Context, tenantID uuid.UUID, actionType string) (mode, approverRole string, businessHoursOnly bool, err error) {
	ap, e := s.ResolveAuthority(ctx, tenantID, actionType)
	return ap.Mode, ap.ApproverRole, ap.BusinessHoursOnly, e
}

// SetCatchAllAuthority upserts the tenant-wide '*' authority-to-act policy (implements
// soar.Authorizer; backs the legacy POST /soar/authority convenience endpoint).
func (s *Service) SetCatchAllAuthority(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, mode string) error {
	_, err := s.SetAuthorityPolicy(ctx, actor, tenantID, AuthorityInput{ActionType: "*", Mode: mode})
	return err
}

// ListHistory returns the tenant's change history, newest first (TEN-010).
func (s *Service) ListHistory(ctx context.Context, tenantID uuid.UUID) ([]ChangeHistoryEntry, error) {
	return s.repo.listChangeHistory(ctx, tenantID)
}

// =========================== repository helpers ===========================

func (r *Repository) setStatus(ctx context.Context, tenantID uuid.UUID, to Status) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE tenants SET status=$2 WHERE id=$1`, tenantID, to)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

func (r *Repository) listEscalationContacts(ctx context.Context, tenantID uuid.UUID) ([]EscalationContact, error) {
	var out []EscalationContact
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, name, role, min_severity, order_index, channel, address, category, active
			   FROM escalation_contacts ORDER BY order_index, created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c EscalationContact
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Role, &c.MinSeverity, &c.OrderIndex, &c.Channel, &c.Address, &c.Category, &c.Active); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) listAuthorityPolicies(ctx context.Context, tenantID uuid.UUID) ([]AuthorityPolicy, error) {
	var out []AuthorityPolicy
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, action_type, mode, approver_role, business_hours_only, active
			   FROM authority_policies ORDER BY action_type`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AuthorityPolicy
			if err := rows.Scan(&a.ID, &a.TenantID, &a.ActionType, &a.Mode, &a.ApproverRole, &a.BusinessHoursOnly, &a.Active); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) listChangeHistory(ctx context.Context, tenantID uuid.UUID) ([]ChangeHistoryEntry, error) {
	var out []ChangeHistoryEntry
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, actor_email, entity, field, old_value, new_value, to_char(at, 'YYYY-MM-DD"T"HH24:MI:SSOF')
			   FROM tenant_change_history ORDER BY at DESC LIMIT 500`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e ChangeHistoryEntry
			if err := rows.Scan(&e.ID, &e.ActorEmail, &e.Entity, &e.Field, &e.OldValue, &e.NewValue, &e.At); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
