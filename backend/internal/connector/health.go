package connector

// §6.4 #118 H-3 — host-source silence detection (US-032). A host telemetry source that reported before but has gone
// quiet is a DETECTION GAP — the SOC-worst-failure theme — so the worker raises a platform alert once per silence
// episode. The other half (last-seen) is already recorded on every keyed ingest (Service.Receive → MarkSuccess).

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// SilenceAlerter raises the "source silent" alert. *alert.Service satisfies it structurally (RaisePlatform), so this
// package needs no import of alert.
type SilenceAlerter interface {
	RaisePlatform(ctx context.Context, tenantID uuid.UUID, dedupeKey, title, severity, targetRef, source string) (bool, error)
}

// SilenceSweeper flags + alerts host sources that have gone silent past a threshold.
type SilenceSweeper struct {
	repo    *Repository
	alerter SilenceAlerter
}

// NewSilenceSweeper builds the sweeper.
func NewSilenceSweeper(repo *Repository, alerter SilenceAlerter) *SilenceSweeper {
	return &SilenceSweeper{repo: repo, alerter: alerter}
}

// RunOnce finds silent host sources, raises one alert each, and flags them 'silent' so the next tick does not
// re-alert (MarkSuccess resets to 'healthy' when the source reports again). Returns the count newly flagged; a single
// source's error is logged-by-omission and does not abort the sweep.
func (s *SilenceSweeper) RunOnce(ctx context.Context, within time.Duration, limit int) (int, error) {
	sources, err := s.repo.SilentHostSources(ctx, within, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, src := range sources {
		title := fmt.Sprintf("Host telemetry source silent: %s (%s) — no events for over %d min",
			src.Name, src.Kind, int(within.Minutes()))
		// Dedupe per (source, silence-episode): the last_success stamp changes after the source resumes and goes
		// quiet again, so a fresh episode re-alerts while the same episode does not.
		dedupe := "host-source-silent:" + src.ID.String() + ":" + src.LastSuccess.UTC().Format(time.RFC3339)
		if _, aerr := s.alerter.RaisePlatform(ctx, src.TenantID, dedupe, title, "medium", "connector:"+src.ID.String(), "host-telemetry-health"); aerr != nil {
			continue
		}
		if merr := s.repo.MarkSilent(ctx, src.TenantID, src.ID); merr != nil {
			continue
		}
		n++
	}
	return n, nil
}

// Start runs RunOnce on a ticker until ctx is cancelled. Panic-guarded — a bad tick must not take down the worker.
func (s *SilenceSweeper) Start(ctx context.Context, log *slog.Logger, interval, within time.Duration, limit int) {
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
						log.Error("host-source silence sweep panicked", "err", r)
					}
				}()
				if n, err := s.RunOnce(ctx, within, limit); err != nil {
					log.Error("host-source silence sweep failed", "err", err)
				} else if n > 0 {
					log.Info("host-source silence: flagged silent host sources", "count", n)
				}
			}()
		}
	}
}
