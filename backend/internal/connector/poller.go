package connector

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
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

// knownStreams maps a configured stream name → (canonical source key, its own checkpoint config key). LAUNCH #1:
// a Microsoft connector can pull several independent Graph streams; each advances its own cursor. Code-owned
// allowlist — an unknown stream name in config is ignored (never a raw source string reaching ingest).
var knownStreams = map[string]struct{ source, checkpointKey string }{
	"alerts":  {"microsoft-defender", "checkpoint"}, // legacy default; keeps the original `checkpoint` key
	"signins": {"microsoft-entra-signin", "checkpoint_signins"},
	"audit":   {"microsoft-entra-audit", "checkpoint_directory_audits"},
	"risky":   {"microsoft-entra-risky", "checkpoint_risky"},
}

// connectorStreams reads the per-connector `streams` allowlist from config, defaulting to ["alerts"] so existing
// Defender connectors are unchanged. Unknown names are dropped.
func connectorStreams(cfg map[string]any) []string {
	raw, ok := cfg["streams"].([]any)
	if !ok || len(raw) == 0 {
		return []string{"alerts"}
	}
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			if _, known := knownStreams[s]; known {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return []string{"alerts"}
	}
	return out
}

// RunOnce polls every enabled pull connector once (all its configured streams) and returns the total ingested.
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

		tokenURL := p.tokenURL
		if tokenURL == "" {
			tokenURL = msLoginTokenURL(azTenant)
		}
		graphURL := p.graphURL
		if graphURL == "" {
			graphURL = "https://graph.microsoft.com/v1.0"
		}
		gc := newGraphClient(tokenURL, graphURL, clientID, string(secret), p.http)

		for _, stream := range connectorStreams(pc.Config) {
			meta := knownStreams[stream]
			cp, _ := pc.Config[meta.checkpointKey].(string)
			n, newCP, err := p.pollStream(ctx, pc.TenantID, gc, stream, meta.source, cp)
			if err != nil {
				// Degraded-not-dropped: record the per-stream degraded health at the unchanged cursor, so the
				// next tick retries from the same watermark (no silent loss, no double-ingest).
				p.log.Warn("poller: stream fetch failed", "connector", pc.ID, "stream", stream, "err", err)
				_ = p.repo.UpdateStreamCheckpoint(ctx, pc.TenantID, pc.ID, meta.checkpointKey, cp, "degraded")
				continue
			}
			_ = p.repo.UpdateStreamCheckpoint(ctx, pc.TenantID, pc.ID, meta.checkpointKey, newCP, "healthy")
			total += n
		}
	}
	return total, nil
}

// pollStream fetches one stream since its checkpoint, ingests each item under the stream's canonical source, and
// returns the count + advanced checkpoint. Each item's canonical fields are set by the registered source mapper
// (Defender / Entra sign-in / audit / risky) — the poller only supplies the raw fields as Data.
func (p *Poller) pollStream(ctx context.Context, tenantID uuid.UUID, gc *graphClient, stream, source, checkpoint string) (int, string, error) {
	switch stream {
	case "alerts":
		alerts, err := gc.fetchAlerts(ctx, checkpoint)
		if err != nil {
			return 0, checkpoint, err
		}
		newCP, n := checkpoint, 0
		for _, a := range alerts {
			in := ingestion.IngestInput{Source: source, NativeID: a.ID, Severity: a.Severity, Data: map[string]any{
				"title": a.Title, "category": a.Category, "deviceName": a.DeviceName,
				"accountName": a.AccountName, "mitreTechniques": a.MitreTechniques, "createdDateTime": a.CreatedDateTime,
			}}
			if p.ingestOne(ctx, tenantID, in) {
				n++
				if checkpointAfter(a.CreatedDateTime, newCP) {
					newCP = a.CreatedDateTime
				}
			}
		}
		return n, newCP, nil
	case "signins":
		items, err := gc.fetchSignIns(ctx, checkpoint)
		if err != nil {
			return 0, checkpoint, err
		}
		newCP, n := checkpoint, 0
		for _, s := range items {
			outcome := "success"
			if s.Status.ErrorCode != 0 {
				outcome = "failure"
			}
			in := ingestion.IngestInput{Source: source, NativeID: s.ID, Data: map[string]any{
				"userPrincipalName": s.UserPrincipalName, "userId": s.UserID, "ipAddress": s.IPAddress,
				"appDisplayName": s.AppDisplayName, "clientAppUsed": s.ClientAppUsed, "isInteractive": s.IsInteractive,
				"outcome_raw": outcome, "failureReason": s.Status.FailureReason, "mfaAuthMethod": s.MfaDetail.AuthMethod,
				"city": s.Location.City, "countryOrRegion": s.Location.CountryOrRegion,
				"riskState": s.RiskState, "riskLevelDuringSignIn": s.RiskLevelDuringSignIn, "createdDateTime": s.CreatedDateTime,
			}}
			if p.ingestOne(ctx, tenantID, in) {
				n++
				if checkpointAfter(s.CreatedDateTime, newCP) {
					newCP = s.CreatedDateTime
				}
			}
		}
		return n, newCP, nil
	case "audit":
		items, err := gc.fetchDirectoryAudits(ctx, checkpoint)
		if err != nil {
			return 0, checkpoint, err
		}
		newCP, n := checkpoint, 0
		for _, a := range items {
			targetUpn, targetName := "", ""
			if len(a.TargetResources) > 0 {
				targetUpn, targetName = a.TargetResources[0].UserPrincipalName, a.TargetResources[0].DisplayName
			}
			in := ingestion.IngestInput{Source: source, NativeID: a.ID, Data: map[string]any{
				"activityDisplayName": a.ActivityDisplayName, "category": a.Category, "result": a.Result,
				"initiatedByUpn": a.InitiatedBy.User.UserPrincipalName, "targetUpn": targetUpn,
				"targetDisplayName": targetName, "activityDateTime": a.ActivityDateTime,
			}}
			if p.ingestOne(ctx, tenantID, in) {
				n++
				if checkpointAfter(a.ActivityDateTime, newCP) {
					newCP = a.ActivityDateTime
				}
			}
		}
		return n, newCP, nil
	case "risky":
		items, err := gc.fetchRiskyUsers(ctx, checkpoint)
		if err != nil {
			return 0, checkpoint, err
		}
		newCP, n := checkpoint, 0
		for _, u := range items {
			in := ingestion.IngestInput{Source: source, NativeID: u.ID, Data: map[string]any{
				"userPrincipalName": u.UserPrincipalName, "riskLevel": u.RiskLevel, "riskState": u.RiskState,
				"riskDetail": u.RiskDetail, "riskLastUpdatedDateTime": u.RiskLastUpdatedDateTime,
			}}
			if p.ingestOne(ctx, tenantID, in) {
				n++
				if checkpointAfter(u.RiskLastUpdatedDateTime, newCP) {
					newCP = u.RiskLastUpdatedDateTime
				}
			}
		}
		return n, newCP, nil
	}
	return 0, checkpoint, nil
}

// ingestOne ingests a single item; a per-item ingest error is logged and skipped (does not fail the stream or
// advance its cursor past the failed item). Returns true on success.
func (p *Poller) ingestOne(ctx context.Context, tenantID uuid.UUID, in ingestion.IngestInput) bool {
	if _, err := p.ingest.Ingest(ctx, tenantID, in); err != nil {
		p.log.Warn("poller: ingest failed", "source", in.Source, "err", err)
		return false
	}
	return true
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
