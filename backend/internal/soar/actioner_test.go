package soar

import (
	"context"
	"testing"
)

func noopFn(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
	return "", nil, nil
}

// TestCanAutoRun_Contract is the MUST-1 structural guard: the engine may auto-run a connector action
// only when it is idempotent-or-prechecking, and a Class3+ action must also declare a reversible undo.
// Anything else is refused (forced to human confirmation) — the reaper double-fire vector is closed by
// the registration contract, not reviewer vigilance.
func TestCanAutoRun_Contract(t *testing.T) {
	reg := NewActionerRegistry().
		Register(Actioner{ConnectorKey: "defender", Action: "isolate", Idempotent: true, PreCheck: true, Reversible: true, Inverse: "release", Fn: noopFn}).
		Register(Actioner{ConnectorKey: "flaky", Action: "fire_and_forget", Idempotent: false, PreCheck: false, Fn: noopFn}).
		Register(Actioner{ConnectorKey: "panw", Action: "block_ip", Idempotent: true, Reversible: false, Fn: noopFn})

	// Well-formed high-risk containment: idempotent + prechecked + reversible with inverse → auto-run ok.
	if ok, reason := canAutoRun(reg, "defender", "isolate", RiskHigh); !ok {
		t.Fatalf("well-formed isolate should auto-run, got refusal: %s", reason)
	}
	// Not idempotent and not prechecking → refused even at low risk (re-drive could double-fire).
	if ok, _ := canAutoRun(reg, "flaky", "fire_and_forget", RiskLow); ok {
		t.Fatal("non-idempotent, non-prechecking action must not auto-run")
	}
	// Idempotent but NOT reversible at Class3+ → refused (no containment without a defined undo).
	if ok, _ := canAutoRun(reg, "panw", "block_ip", RiskHigh); ok {
		t.Fatal("high-risk action without a reversible undo must not auto-run")
	}
	// The same idempotent-but-irreversible action at a LOW class is allowed (reverse requirement is
	// Class3+ only) — proves the gate keys on risk, not a blanket ban.
	if ok, reason := canAutoRun(reg, "panw", "block_ip", RiskLow); !ok {
		t.Fatalf("idempotent low-risk action should auto-run, got: %s", reason)
	}
	// Unregistered → refused (falls back to simulation elsewhere).
	if ok, _ := canAutoRun(reg, "nope", "whatever", RiskHigh); ok {
		t.Fatal("unregistered action must not auto-run")
	}
}

// TestRegister_ReversibleWithoutInverse is a wiring-time programming error, caught by a panic.
func TestRegister_ReversibleWithoutInverse(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering Reversible without an Inverse must panic at wiring")
		}
	}()
	NewActionerRegistry().Register(Actioner{ConnectorKey: "x", Action: "y", Reversible: true, Fn: noopFn})
}
