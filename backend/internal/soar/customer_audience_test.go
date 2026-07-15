package soar

// J3 — the customer approval endpoints must not disclose internal SOC state in their refusal prose. This is the
// prose twin of BUG-10: the read-model withholds internal FACTS from a customer audience, but the approval gate
// was handing the same facts over in an error message. Latent only while every tenant sits on the
// platform_analyst default — enabling customer_approver/both_required (the ROE decision) arms it.
//
// These cases are the ACTUAL refusals the gate emits (customer_approval.go, service.go), not invented ones.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

func TestCustomerSafeError_WithholdsInternalSOCState(t *testing.T) {
	// Verbatim from the gate + executor. Each names something a customer must never learn.
	internal := []struct {
		name string
		err  error
		// leak is the substring that would betray internal state if it escaped.
		leak string
	}{
		{"approver liveness / SOC staffing", httpx.ErrForbidden("the internal approver is no longer active"), "approver"},
		{"four-eyes mechanics", httpx.ErrForbidden("the same principal cannot provide both the internal and the customer approval"), "principal"},
		{"requester attribution", httpx.ErrForbidden("run has no requester; cannot be approved in this flow"), "requester"},
		{"separation of duties", httpx.ErrForbidden("separation of duties: the requester may not approve"), "separation of duties"},
		{"internal role taxonomy + tier", httpx.ErrForbidden("approver role 'analyst_t2' is insufficient to approve a high-risk action"), "analyst_t2"},
		{"generic role gate", httpx.ErrForbidden("insufficient role"), "insufficient role"},
	}

	for _, tc := range internal {
		t.Run(tc.name, func(t *testing.T) {
			out := customerSafeError(tc.err)
			var ae *httpx.APIError
			if !asAPIError(out, &ae) {
				t.Fatalf("expected an APIError, got %T", out)
			}
			if strings.Contains(strings.ToLower(ae.Message), strings.ToLower(tc.leak)) {
				t.Fatalf("internal detail crossed the audience boundary: %q leaked %q", ae.Message, tc.leak)
			}
			if ae.Status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (the refusal must still be a refusal)", ae.Status)
			}
		})
	}
}

func TestCustomerSafeError_LetsThroughWhatTheCustomerCanActOn(t *testing.T) {
	// A refusal about the customer's OWN tenant policy is safe and useful — withholding it would just confuse.
	out := customerSafeError(httpx.ErrForbidden(MsgCustomerApprovalDisabled))
	var ae *httpx.APIError
	if !asAPIError(out, &ae) {
		t.Fatalf("expected an APIError, got %T", out)
	}
	if ae.Message != MsgCustomerApprovalDisabled {
		t.Fatalf("message = %q, want the tenant-policy refusal passed through verbatim", ae.Message)
	}

	// Errors about the caller's own request stay verbatim too (a stale run must say so, or the portal lies).
	for _, e := range []error{httpx.ErrBadRequest("invalid run id"), httpx.ErrNotFound("run not found"), httpx.ErrConflict("run is not pending approval")} {
		got := customerSafeError(e)
		if got != e {
			t.Fatalf("request-scoped error was rewritten: %v -> %v", e, got)
		}
	}
}

func TestCustomerSafeError_FailsClosedOnUnknownError(t *testing.T) {
	// A plain error (not an APIError) must not fall through as-is — an unclassified failure is treated as internal.
	out := customerSafeError(errString("pq: relation \"run_approval\" does not exist"))
	var ae *httpx.APIError
	if !asAPIError(out, &ae) {
		t.Fatalf("expected an APIError, got %T", out)
	}
	if strings.Contains(ae.Message, "run_approval") {
		t.Fatalf("raw internal error leaked to the customer: %q", ae.Message)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// asAPIError is errors.As with the generic noise kept out of the test bodies.
func asAPIError(err error, target **httpx.APIError) bool {
	ae, ok := err.(*httpx.APIError)
	if ok {
		*target = ae
	}
	return ok
}
