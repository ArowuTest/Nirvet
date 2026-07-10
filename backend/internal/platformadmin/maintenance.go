package platformadmin

// §6.18 #122 P-4 — maintenance windows (ADMIN-008) + the protected-flag time-box auto-revert (Reinf-B). A window
// never stops ingestion/detection; it may only hold notifications / pause SLA — and a CRITICAL (P1) always breaks
// through (M-2). The auto-revert sweep reverts any expired protected weakening to its secure default.

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// MaintenanceService answers whether an active window is currently suppressing notifications / pausing SLA.
type MaintenanceService struct{ repo *Repository }

// NewMaintenanceService builds the service.
func NewMaintenanceService(repo *Repository) *MaintenanceService {
	return &MaintenanceService{repo: repo}
}

// CreateWindow opens a maintenance window (padmin). It affects ONLY notification/SLA behavior — never ingestion or
// detection (a window is not a detection blackout).
func (m *MaintenanceService) CreateWindow(ctx context.Context, actor auth.Principal, scope, scopeRef string, startsAt, endsAt time.Time, suppressNotif, pauseSLA bool, banner string) error {
	if !endsAt.After(startsAt) {
		return httpx.ErrBadRequest("ends_at must be after starts_at")
	}
	if scope != "global" && scope != "tenant" {
		return httpx.ErrBadRequest("scope must be global or tenant")
	}
	return m.repo.CreateWindow(ctx, scope, scopeRef, startsAt, endsAt, suppressNotif, pauseSLA, banner, actor.UserID)
}

// SuppressNotification — M-2: a window may hold a notification, but a CRITICAL (P1) ALWAYS delivers. On any read
// error, do NOT suppress (fail toward delivery — a missed critical is the silent gap).
func (m *MaintenanceService) SuppressNotification(ctx context.Context, tenantID uuid.UUID, severity string) bool {
	if severity == "critical" {
		return false // M-2: critical/P1 breaks through suppression
	}
	suppress, _, err := m.repo.ActiveMaintenance(ctx, tenantID)
	if err != nil {
		return false
	}
	return suppress
}

// PauseSLA — a window may pause SLA timers, but NEVER for a CRITICAL (P1).
func (m *MaintenanceService) PauseSLA(ctx context.Context, tenantID uuid.UUID, severity string) bool {
	if severity == "critical" {
		return false
	}
	_, pause, err := m.repo.ActiveMaintenance(ctx, tenantID)
	if err != nil {
		return false
	}
	return pause
}

// RevertExpiredWeakenings — Reinf-B: revert any protected flag whose time-box elapsed to its secure default, with an
// audit row + a HIGH alert. Returns the count reverted; a single failure does not abort the sweep.
func (s *Service) RevertExpiredWeakenings(ctx context.Context, limit int) (int, error) {
	flags, err := s.repo.ExpiredWeakenings(ctx, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range flags {
		if err := s.repo.RevertFlag(ctx, f.Key, f.Scope, f.ScopeRef, SecureDefault(f.Key), "auto-revert: protected-flag time-box expired"); err != nil {
			continue
		}
		_, _ = s.alerter.RaisePlatform(ctx, uuid.Nil,
			"flag-autorevert:"+f.Key+":"+f.Scope+":"+f.ScopeRef,
			"Protected flag "+f.Key+" AUTO-REVERTED to secure at time-box expiry (Reinf-B)", "high", "flag:"+f.Key, "platform-admin")
		n++
	}
	return n, nil
}

// StartRevertSweep runs RevertExpiredWeakenings on a ticker (the worker owns it). Panic-guarded.
func (s *Service) StartRevertSweep(ctx context.Context, log *slog.Logger, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Error("flag time-box sweep panicked", "err", r)
					}
				}()
				if n, err := s.RevertExpiredWeakenings(ctx, 200); err != nil {
					log.Error("flag time-box sweep failed", "err", err)
				} else if n > 0 {
					log.Info("flag time-box: auto-reverted expired protected weakenings", "count", n)
				}
			}()
		}
	}
}
