package ticketing

import "net/http"

// SetHTTPClient swaps the package outbound client and returns a restore func. Test-only: the production
// client is netsafe.SafeClient (R6 SEC-carry), which refuses to dial the loopback httptest mocks these
// tests use, so a test that must reach a local mock injects a plain client for the duration.
func SetHTTPClient(c *http.Client) func() {
	old := httpClient
	httpClient = c
	return func() { httpClient = old }
}
