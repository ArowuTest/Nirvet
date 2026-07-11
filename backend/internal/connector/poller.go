package connector

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
)

// Poller pulls telemetry from enabled Microsoft pull connectors on a schedule and
// feeds each alert through the ingestion pipeline (normalize → evidence → dedupe →
// detect). It runs at the system level; each ingest uses the connector's tenant.
// Read-only: no destructive action, so no authority-to-act gate is needed.
type Poller struct {
	repo   *Repository
	vault  *Vault
	ingest *ingestion.Service
	log    *slog.Logger
	http   *http.Client

	// Endpoint overrides (empty = real Microsoft endpoints). Set in tests.
	tokenURL string
	graphURL string
}

// NewPoller builds the poller.
func NewPoller(repo *Repository, vault *Vault, ingest *ingestion.Service, log *slog.Logger) *Poller {
	// Carry-forward Low: SafeClient so a misconfigured/hostile token or Graph URL cannot reach
	// internal hosts (defense-in-depth before any tenant-settable Graph base URL).
	return &Poller{repo: repo, vault: vault, ingest: ingest, log: log, http: netsafe.SafeClient(30 * time.Second)}
}

// WithEndpoints overrides the token/graph base URLs (used by tests).
func (p *Poller) WithEndpoints(tokenURL, graphURL string) *Poller {
	p.tokenURL, p.graphURL = tokenURL, graphURL
	return p
}

// Start runs the poll loop until ctx is cancelled.
func (p *Poller) Start(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(p.log, "connector-poller", func() {
				if n, err := p.RunOnce(ctx); err != nil {
					p.log.Error("poller error", "err", err)
				} else if n > 0 {
					p.log.Info("poller ingested", "count", n)
				}
			})
		}
	}
}

// RunOnce polls every enabled pull connector once and returns the alerts ingested.
func (p *Poller) RunOnce(ctx context.Context) (int, error) {
	pullers, err := p.repo.ListPullers(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, pc := range pullers {
		if len(pc.Secret) == 0 {
			continue // not configured with credentials yet
		}
		secret, err := p.vault.Open(ctx, pc.TenantID, pc.ID, "poll", pc.Secret)
		if err != nil {
			p.log.Warn("poller: cannot decrypt connector secret", "connector", pc.ID)
			continue
		}
		clientID, _ := pc.Config["client_id"].(string)
		azTenant, _ := pc.Config["azure_tenant"].(string)
		checkpoint, _ := pc.Config["checkpoint"].(string)

		tokenURL := p.tokenURL
		if tokenURL == "" {
			tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", azTenant)
		}
		graphURL := p.graphURL
		if graphURL == "" {
			graphURL = "https://graph.microsoft.com/v1.0"
		}

		gc := newGraphClient(tokenURL, graphURL, clientID, string(secret), p.http)
		alerts, err := gc.fetchAlerts(ctx, checkpoint)
		if err != nil {
			p.log.Warn("poller: fetch failed", "connector", pc.ID, "err", err)
			_ = p.repo.UpdateCheckpoint(ctx, pc.TenantID, pc.ID, checkpoint, "degraded")
			continue
		}
		newCheckpoint := checkpoint
		for _, a := range alerts {
			in := ingestion.IngestInput{
				Source:   "microsoft-defender",
				NativeID: a.ID,
				Severity: a.Severity,
				Data: map[string]any{
					"title":           a.Title,
					"category":        a.Category,
					"deviceName":      a.DeviceName,
					"accountName":     a.AccountName,
					"mitreTechniques": a.MitreTechniques,
					"createdDateTime": a.CreatedDateTime,
				},
			}
			if _, err := p.ingest.Ingest(ctx, pc.TenantID, in); err != nil {
				p.log.Warn("poller: ingest failed", "connector", pc.ID, "err", err)
				continue
			}
			if checkpointAfter(a.CreatedDateTime, newCheckpoint) {
				newCheckpoint = a.CreatedDateTime
			}
			total++
		}
		_ = p.repo.UpdateCheckpoint(ctx, pc.TenantID, pc.ID, newCheckpoint, "healthy")
	}
	return total, nil
}

// checkpointAfter reports whether candidate is chronologically after current. R6: the
// Graph createdDateTime is compared as a TIME, not lexically — variable fractional-second
// precision (".7Z" vs ".789Z") would sort wrong as strings and could rewind the watermark,
// re-pulling already-ingested alerts. Falls back to string compare only if either value is
// unparseable (empty current => any candidate advances it).
func checkpointAfter(candidate, current string) bool {
	if current == "" {
		return candidate != ""
	}
	ct, cerr := time.Parse(time.RFC3339, candidate)
	pt, perr := time.Parse(time.RFC3339, current)
	if cerr != nil || perr != nil {
		return candidate > current
	}
	return ct.After(pt)
}
