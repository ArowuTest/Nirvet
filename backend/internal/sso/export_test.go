package sso

import "net/http"

// SetHTTPClientForTest injects a test HTTP client into the OIDC client, replacing the
// netsafe.SafeClient the prod NewClient bakes in. It lives in export_test.go, so it is compiled
// ONLY into the sso package's test binary and is unreachable from any production build — the
// SafeClient default (and its SSRF/DNS-rebinding dial-time guard) is unconditional in prod.
//
// This exists because the OIDC integration test runs a mock IdP on a loopback httptest server,
// which SafeClient correctly refuses to dial. The test points the issuer at a non-internal
// hostname (which legitimately passes netsafe.IsInternalHost) and supplies a client that dials
// that name back to the loopback listener — so no prod guard is loosened to make the test pass.
func (c *Client) SetHTTPClientForTest(hc *http.Client) { c.http = hc }
