package soar_test

// §6.11 slice B config surface (per-tenant settings + global platform flags) against a migrated Postgres.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func TestSoarSettingsAndPlatformFlags(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "soar-" + uuid.NewString()})
	svc := soar.NewService(soar.NewRepository(db))
	p := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "admin@t", Role: auth.RolePlatformAdmin}

	// Per-tenant settings default to destructive OFF.
	if s, err := svc.Settings(ctx, tn.ID); err != nil || s.DestructiveEnabled || s.MaxClass3PerHour != 10 || s.MaxClass4PerHour != 0 {
		t.Fatalf("default settings: %+v (err %v)", s, err)
	}
	set, err := svc.SetSettings(ctx, p, tn.ID, soar.SoarSettings{DestructiveEnabled: true, DryRun: true, MaxClass3PerHour: 5, MaxClass4PerHour: 1})
	if err != nil {
		t.Fatalf("set settings: %v", err)
	}
	if !set.DestructiveEnabled || !set.DryRun || set.MaxClass3PerHour != 5 {
		t.Fatalf("set settings echo: %+v", set)
	}
	if got, _ := svc.Settings(ctx, tn.ID); !got.DestructiveEnabled || got.MaxClass4PerHour != 1 {
		t.Fatalf("settings round-trip: %+v", got)
	}
	// Negative rate limit rejected.
	if _, err := svc.SetSettings(ctx, p, tn.ID, soar.SoarSettings{MaxClass3PerHour: -1}); err == nil {
		t.Fatal("negative rate limit must be rejected")
	}

	// Global platform flags (single row) — engage then RESET the kill-switch so other tests are unaffected.
	t.Cleanup(func() { _, _ = svc.SetPlatformFlags(context.Background(), p, soar.PlatformFlags{}) })
	if f, err := svc.PlatformFlags(ctx); err != nil || f.KillSwitch {
		t.Fatalf("platform default: %+v (err %v)", f, err)
	}
	if _, err := svc.SetPlatformFlags(ctx, p, soar.PlatformFlags{KillSwitch: true, DryRun: true}); err != nil {
		t.Fatalf("set platform: %v", err)
	}
	if f, _ := svc.PlatformFlags(ctx); !f.KillSwitch || !f.DryRun {
		t.Fatalf("platform round-trip: %+v", f)
	}

	// Tenant isolation: another tenant sees default settings, not the first tenant's.
	other, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "soar-other-" + uuid.NewString()})
	if s, _ := svc.Settings(ctx, other.ID); s.DestructiveEnabled {
		t.Fatal("cross-tenant settings leak")
	}
}
