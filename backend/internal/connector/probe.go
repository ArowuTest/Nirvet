package connector

// Connector test-connection probe (launch-line, light tier). A live credential + connectivity check for an
// OUTBOUND Microsoft connector, run over the SAME SSRF-safe egress path the poller uses (netsafe.SafeClient) — so
// it adds NO new outbound surface. Inbound push sources (webhook/syslog/host telemetry) have nothing to dial and
// report not_applicable. The stored secret and raw upstream bodies are never returned to the caller.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/google/uuid"
)

// ProbeResult is the outcome of a connector test-connection.
type ProbeResult struct {
	Status string `json:"status"` // ok | failed | not_applicable
	Detail string `json:"detail"`
}

const probeTimeout = 15 * time.Second

// TestConnection probes an outbound Microsoft connector by acquiring an OAuth token, reflecting the result in the
// connector's health. Tenant-scoped: GetWithSecret reads under RLS, so a caller can only probe its own connectors.
func (s *Service) TestConnection(ctx context.Context, tenantID, id uuid.UUID) (*ProbeResult, error) {
	c, err := s.repo.GetWithSecret(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("connector not found")
	}
	switch c.Kind {
	case KindMicrosoft365, KindDefender, KindEntraID:
		// outbound Microsoft connector — probe below
	default:
		return &ProbeResult{Status: "not_applicable", Detail: "inbound source: it pushes telemetry to Nirvet; there is nothing to dial"}, nil
	}
	if len(c.Secret) == 0 {
		return &ProbeResult{Status: "failed", Detail: "no credentials configured"}, nil
	}
	secret, err := s.vault.Open(tenantID, c.Secret)
	if err != nil {
		return &ProbeResult{Status: "failed", Detail: "could not decrypt the stored secret"}, nil
	}
	clientID, _ := c.Config["client_id"].(string)
	azTenant, _ := c.Config["azure_tenant"].(string)

	tokenURL := s.probeTokenURL
	if tokenURL == "" {
		// azTenant is only ever a PATH segment of a fixed host (login.microsoftonline.com), so it cannot redirect
		// the request to another host; SafeClient additionally blocks any internal/loopback target.
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(azTenant))
	}
	graphURL := s.probeGraphURL
	if graphURL == "" {
		graphURL = "https://graph.microsoft.com/v1.0"
	}
	hc := s.probeHTTP
	if hc == nil {
		hc = netsafe.SafeClient(probeTimeout) // SSRF-safe: the SAME guard the poller uses, no new egress surface
	}

	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	gc := newGraphClient(tokenURL, graphURL, clientID, string(secret), hc)
	if _, err := gc.accessToken(pctx); err != nil {
		_ = s.repo.SetHealth(ctx, tenantID, id, "degraded")
		return &ProbeResult{Status: "failed", Detail: probeReason(err)}, nil
	}
	_ = s.repo.SetHealth(ctx, tenantID, id, "healthy")
	return &ProbeResult{Status: "ok", Detail: "authenticated to Microsoft Graph"}, nil
}

// probeReason maps an internal probe error to a safe, actionable message. It NEVER echoes the secret, the URL, or
// a raw upstream body — only a bounded classification (credentials vs connectivity vs generic).
func probeReason(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "status 400"), strings.Contains(s, "status 401"), strings.Contains(s, "status 403"):
		return "Microsoft rejected the credentials (check client id, secret, and Azure tenant)"
	case strings.Contains(s, "deadline"), strings.Contains(s, "timeout"),
		strings.Contains(s, "no such host"), strings.Contains(s, "blocked"), strings.Contains(s, "dial"),
		strings.Contains(s, "connection refused"):
		return "could not reach the Microsoft endpoint"
	default:
		return "connection test failed"
	}
}
