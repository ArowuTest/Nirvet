package platformadmin

import "testing"

// M-1 / fail-safe class: an unregistered flag key must be treated as protected, never open.
func TestClassOf_UnknownIsProtected(t *testing.T) {
	if ClassOf("totally.unregistered.flag") != ClassProtected {
		t.Fatal("an unregistered flag key must fail closed to protected (M-1)")
	}
	if ClassOf("mfa.enforce") != ClassImmutable {
		t.Fatalf("mfa.enforce class = %s", ClassOf("mfa.enforce"))
	}
	if ClassOf(TestFlagOpen) != ClassOpen {
		t.Fatalf("open fixture class = %s", ClassOf(TestFlagOpen))
	}
	if ClassOf("soar.destructive_enabled") != ClassProtected {
		t.Fatalf("soar.destructive_enabled class = %s", ClassOf("soar.destructive_enabled"))
	}
}

func TestSecureDefault(t *testing.T) {
	if SecureDefault("totally.unregistered.flag") != false {
		t.Fatal("unknown key must default to false (conservative)")
	}
	if SecureDefault("mfa.enforce") != true {
		t.Fatal("a security control must default ON")
	}
	if SecureDefault("soar.destructive_enabled") != false {
		t.Fatal("a risky feature must default OFF")
	}
}

func TestIsImmutable(t *testing.T) {
	if !IsImmutable("rls.enforce") {
		t.Fatal("rls.enforce must be immutable")
	}
	if IsImmutable(TestFlagOpen) {
		t.Fatal("a beta flag must not be immutable")
	}
}
