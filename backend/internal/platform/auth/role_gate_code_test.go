package auth

// The role gate must answer with CodeInsufficientRole, not a bare "forbidden". Clients need Code to tell a role
// refusal ("your role is not on the allow-list" — say something more useful) from a domain refusal that also
// returns 403 and states a real reason ("separation of duties: the requester may not approve" — say exactly that).
// This asserts the middleware's behaviour, which the SPA's errorText() depends on.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireRoleAnswersWithInsufficientRoleCode(t *testing.T) {
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
	if body := rec.Body.String(); !strings.Contains(body, `"code":"insufficient_role"`) {
		t.Fatalf("role gate did not emit the insufficient_role code.\n got: %s\n\n"+
			"The SPA dispatches on this code (frontend/lib/api.ts errorText) to decide whether to show the "+
			"server's reason or its own hint. Domain refusals must NOT use it.", body)
	}
}
