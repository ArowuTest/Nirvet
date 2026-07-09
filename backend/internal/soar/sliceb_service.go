package soar

// §6.11 slice B service — the admin-configurable safety surface: per-tenant destructive-action settings
// and the global kill-switch. Both are the highest-consequence config on the platform, so writes are
// platform-admin gated (in the router) and explicitly audited here.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Settings returns the tenant's destructive-action settings (defaults when unset).
func (s *Service) Settings(ctx context.Context, tenantID uuid.UUID) (SoarSettings, error) {
	set, err := s.repo.GetSoarSettings(ctx, tenantID)
	if err != nil {
		return SoarSettings{}, httpx.ErrInternal("could not load SOAR settings")
	}
	return set, nil
}

// SetSettings validates + upserts the tenant's destructive-action settings and audits the change (enabling
// real containment for a tenant is a material, forensically-important event).
func (s *Service) SetSettings(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in SoarSettings) (SoarSettings, error) {
	if in.MaxClass3PerHour < 0 || in.MaxClass4PerHour < 0 {
		return SoarSettings{}, httpx.ErrBadRequest("rate limits must be non-negative")
	}
	if err := s.repo.SetSoarSettings(ctx, tenantID, in); err != nil {
		return SoarSettings{}, httpx.ErrInternal("could not save SOAR settings")
	}
	_ = s.repo.recordAudit(ctx, tenantID, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.settings_set",
		Target: "tenant:" + tenantID.String(), Metadata: map[string]any{
			"destructive_enabled": in.DestructiveEnabled, "dry_run": in.DryRun,
			"max_class3_per_hour": in.MaxClass3PerHour, "max_class4_per_hour": in.MaxClass4PerHour}})
	return in, nil
}

// PlatformFlags returns the global kill-switch + dry-run flags.
func (s *Service) PlatformFlags(ctx context.Context) (PlatformFlags, error) {
	f, err := s.repo.GetPlatformFlags(ctx)
	if err != nil {
		return PlatformFlags{}, httpx.ErrInternal("could not load platform flags")
	}
	return f, nil
}

// SetPlatformFlags updates the GLOBAL kill-switch / dry-run and audits it under the actor's tenant. The
// router restricts this to platform-admin; engaging the kill-switch is the platform emergency stop.
func (s *Service) SetPlatformFlags(ctx context.Context, p auth.Principal, in PlatformFlags) (PlatformFlags, error) {
	if err := s.repo.SetPlatformFlags(ctx, in); err != nil {
		return PlatformFlags{}, httpx.ErrInternal("could not save platform flags")
	}
	_ = s.repo.recordAudit(ctx, p.TenantID, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.platform_flags_set",
		Target: "platform", Metadata: map[string]any{"kill_switch": in.KillSwitch, "dry_run": in.DryRun}})
	return in, nil
}
