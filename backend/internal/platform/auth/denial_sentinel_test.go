package auth

// J2 contract test. The SPA distinguishes two kinds of 403:
//
//   - a DOMAIN refusal, which states its real reason ("separation of duties: the requester of a playbook run may
//     not approve it", "alert is not within your fleet scope") — the SPA shows the server's sentence verbatim;
//   - a ROLE-gate refusal from RequireRole, which carries no information beyond "your role is not on the
//     allow-list" — the SPA substitutes a contextual hint, because "insufficient role" helps nobody.
//
// It tells them apart by matching this exact sentinel (frontend/lib/api.ts → GENERIC_DENIALS). If this string is
// ever reworded, that match silently fails OPEN: the terse sentinel would be shown to operators verbatim in place
// of the useful hint. Nothing else would catch it — so pin it here, next to the code that emits it.
//
// If you are changing this message: update GENERIC_DENIALS in frontend/lib/api.ts in the same commit.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireRoleDenialSentinelIsStable(t *testing.T) {
	const sentinel = `"message":"insufficient role"`

	h := RequireRole(RolePlatformAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler ran despite a role the gate must refuse")
	}))

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{Role: RoleAnalystT1}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, sentinel) {
		t.Fatalf("role-gate denial message changed.\n got: %s\nwant it to contain: %s\n\n"+
			"The SPA keys off this exact string to tell a role refusal from a domain refusal (J2). "+
			"If you reworded it deliberately, update GENERIC_DENIALS in frontend/lib/api.ts in the same commit.",
			body, sentinel)
	}
}
