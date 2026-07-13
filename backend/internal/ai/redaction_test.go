package ai

// §6.12 #188 HEAVY-1 — AI-egress redaction unit tests (no DB). Discriminating BOTH ways per the reviewer's
// landing round: (a) raw PII/secrets NEVER reach the captured provider payload, (b) fail-safe still masks with no
// config wired, (c) allowlist/safe keys pass VERBATIM (no silent over-mask that would break grounding), plus
// grounding-stable placeholders, identifier-ref masking, strict/off modes.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// captureProvider records the exact (system, user) it was asked to Complete — the payload that would egress.
type captureProvider struct{ system, user string }

func (c *captureProvider) Available() bool { return true }
func (c *captureProvider) Model() string   { return "capture" }
func (c *captureProvider) Complete(_ context.Context, system, user string) (string, error) {
	c.system, c.user = system, user
	return "ok", nil
}

func floor() []CompiledPattern { return append(builtinSpecific(), builtinBroad()...) }

// (a) + (b): with NO Redactor wired (fail-safe built-in floor), raw email/IP/secret NEVER appear in the payload.
func TestEgress_RawPIINeverReachesProvider(t *testing.T) {
	s := &Service{} // redaction nil → fail-safe floor
	cap := &captureProvider{}
	lines := []string{
		"title=suspicious login",
		"actor=jdoe@corp.example", // identifier (email) → wholesale masked
		"source=10.1.2.3",         // identifier (ip)    → wholesale masked
		"target=host-db-01",       // identifier         → wholesale masked
		"note=leaked key ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 here", // free-text w/ secret token → token masked
		"severity=high", // safe → verbatim
	}
	_, rr, err := s.completeExternal(context.Background(), uuid.New(), cap, lines, "\n\ninstr")
	if err != nil {
		t.Fatalf("completeExternal: %v", err)
	}
	if !rr.Applied || rr.Mode != RedactBalanced {
		t.Fatalf("expected balanced masking applied, got %+v", rr)
	}
	for _, raw := range []string{"jdoe@corp.example", "10.1.2.3", "host-db-01", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"} {
		if strings.Contains(cap.user, raw) {
			t.Fatalf("raw PII/secret %q leaked into the provider payload:\n%s", raw, cap.user)
		}
	}
	// Masking actually happened (placeholders present) and the safe field survived verbatim.
	if !strings.Contains(cap.user, "IDENT_") || !strings.Contains(cap.user, "SECRET_") {
		t.Fatalf("expected IDENT_/SECRET_ placeholders in payload:\n%s", cap.user)
	}
	if !strings.Contains(cap.user, "severity=high") {
		t.Fatalf("safe field severity=high must pass verbatim:\n%s", cap.user)
	}
}

// (c): allowlist/safe keys are NEVER mangled (over-masking would silently break grounding).
func TestRedact_AllowlistPassesVerbatim(t *testing.T) {
	lines := []string{"severity=high", "status=open", "stage=investigating", "mitre=T1078,T1110", "alerts=3", "asset_criticalities=critical, high"}
	out, rr := redactLines(lines, RedactionPolicy{Enabled: true, Mode: RedactBalanced}, floor())
	if rr.Count != 0 {
		t.Fatalf("safe fields must not be masked; got %d substitutions", rr.Count)
	}
	for i := range lines {
		if out[i] != lines[i] {
			t.Fatalf("safe field mangled: %q → %q", lines[i], out[i])
		}
	}
}

// Grounding: the same raw value maps to the SAME placeholder within one call (stable), and distinct values differ.
func TestRedact_StablePlaceholders(t *testing.T) {
	out, rr := redactLines([]string{"actor=jdoe", "target=jdoe", "entity=svc01"},
		RedactionPolicy{Enabled: true, Mode: RedactBalanced}, floor())
	if out[0] != "actor=IDENT_1" || out[1] != "target=IDENT_1" {
		t.Fatalf("same value must map to the same placeholder: %v", out)
	}
	if out[2] != "entity=IDENT_2" {
		t.Fatalf("distinct value must get a distinct placeholder: %v", out)
	}
	if rr.Count != 2 {
		t.Fatalf("expected 2 distinct substitutions, got %d", rr.Count)
	}
}

// Identifier ref fields are wholesale-masked in balanced; free-text title keeps its non-token words (reviewer Q4).
func TestRedact_IdentifierMaskedTitleFreeInBalanced(t *testing.T) {
	out, _ := redactLines([]string{"actor=alice", "title=alice logged in from newdevice"},
		RedactionPolicy{Enabled: true, Mode: RedactBalanced}, floor())
	if out[0] != "actor=IDENT_1" {
		t.Fatalf("identifier ref must be wholesale-masked: %q", out[0])
	}
	if !strings.HasPrefix(out[1], "title=") || strings.Contains(out[1], "IDENT_") {
		t.Fatalf("free-text title must stay free in balanced (token-only): %q", out[1])
	}
	if !strings.Contains(out[1], "logged in") {
		t.Fatalf("title free-text words should survive balanced: %q", out[1])
	}
}

// strict additionally wholesale-masks free-text fields.
func TestRedact_StrictMasksFreeText(t *testing.T) {
	out, _ := redactLines([]string{"title=alice logged in"}, RedactionPolicy{Enabled: true, Mode: RedactStrict}, floor())
	if out[0] != "title=TEXT_1" {
		t.Fatalf("strict must wholesale-mask free text: %q", out[0])
	}
}

// off (and disabled) egress verbatim — an explicit, audited choice.
func TestRedact_OffAndDisabledPassThrough(t *testing.T) {
	in := []string{"actor=jdoe@corp.example", "source=10.0.0.1"}
	for _, pol := range []RedactionPolicy{{Enabled: true, Mode: RedactOff}, {Enabled: false, Mode: RedactBalanced}} {
		out, rr := redactLines(in, pol, floor())
		if rr.Applied {
			t.Fatalf("policy %+v must not apply masking", pol)
		}
		for i := range in {
			if out[i] != in[i] {
				t.Fatalf("policy %+v must pass through verbatim: %q → %q", pol, in[i], out[i])
			}
		}
	}
}
