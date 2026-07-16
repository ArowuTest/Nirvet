package platformadmin

// Test-only access to the code-owned flag registry, via Go's export_test.go idiom: this file is compiled ONLY
// for this package's tests, so nothing here can reach a production binary.
//
// Why it exists (J4 fallout). The flag registry declared five settable flags that nothing read, and the fix was
// to delete them. That broke seven tests — none of which were testing those flags. They were testing the
// SUBSYSTEM's guarantees (class gating, reason requirements, protected four-eyes, tighten-only, cross-tenant
// isolation, time-box auto-revert) and merely borrowed whatever real flags happened to be registered as
// fixtures.
//
// That coupling was itself a defect: those guarantees are generic over any flag, so deleting an unrelated
// production entry should never have been able to turn a four-eyes test red. Worse, it creates pressure to keep
// a flag registered *so the tests still pass* — which is how a lying registry entry earns tenure.
//
// So the fixtures are now synthetic and self-evidently so ("test.*"). The subsystem's guarantees are tested
// against flags that exist for exactly that purpose, and the production registry is free to be honest.

import (
	"os"
	"testing"
)

// TestMain registers the synthetic fixtures for every test in this package.
//
// Ordering matters and is load-bearing: package-level var initialisation runs BEFORE TestMain, so
// flags_reachability_test.go's `productionRegistry` snapshot is taken while the registry still holds only what
// the code declares. The fence therefore cannot see these fixtures — it can be neither satisfied nor tripped by
// them, which is the property that makes it worth having.
func TestMain(m *testing.M) {
	restore := RegisterStandardTestFlags()
	code := m.Run()
	restore()
	os.Exit(code)
}

// RegisterFlagForTest adds (or overrides) a registry entry for the duration of a test and returns a restore
// func. Callers MUST defer the restore — the registry is package state.
//
// Note the reachability fence (flags_reachability_test.go) snapshots the registry at package-var init, before
// any test body runs, so a synthetic fixture can never satisfy — or trip — that fence.
func RegisterFlagForTest(key string, spec FlagSpec) func() {
	prev, existed := registry[key]
	registry[key] = spec
	return func() {
		if existed {
			registry[key] = prev
			return
		}
		delete(registry, key)
	}
}

// Test fixture keys. Deliberately namespaced so nobody mistakes them for real controls.
//
// There are TWO protected fixtures because a protected flag's SecureDefault decides which DIRECTION counts as
// "weakening", and the subsystem behaves differently on each: for a secure=ON control (like an egress
// restriction) turning it OFF is the weakening; for a secure=OFF one (like an opt-in destructive capability)
// turning it ON is. Testing only one shape would leave the other's tighten-only path unexercised.
const (
	TestFlagOpen         = "test.open_fixture"
	TestFlagGuarded      = "test.guarded_fixture"
	TestFlagProtected    = "test.protected_fixture"     // SecureDefault ON  — weakening = setting it OFF
	TestFlagProtectedOff = "test.protected_off_fixture" // SecureDefault OFF — weakening = setting it ON
	TestFlagImmutable    = "test.immutable_fixture"     // code-only; a planted DB row must be inert (Reinf-A)
)

// RegisterStandardTestFlags registers one fixture per settable class and returns a single restore func.
func RegisterStandardTestFlags() func() {
	restores := []func(){
		RegisterFlagForTest(TestFlagOpen, FlagSpec{Class: ClassOpen, SecureDefault: false, Desc: "test fixture: open"}),
		RegisterFlagForTest(TestFlagGuarded, FlagSpec{Class: ClassGuarded, SecureDefault: false, Desc: "test fixture: guarded"}),
		// SecureDefault true, so "weakening" it means setting false — the shape of a real protected control.
		RegisterFlagForTest(TestFlagProtected, FlagSpec{Class: ClassProtected, SecureDefault: true, Desc: "test fixture: protected, secure=on"}),
		RegisterFlagForTest(TestFlagProtectedOff, FlagSpec{Class: ClassProtected, SecureDefault: false, Desc: "test fixture: protected, secure=off"}),
		// An immutable fixture needs no EnforcedBy: the per-flag proof fence (J5) reads the init-time snapshot of
		// the PRODUCTION registry, so a fixture can neither satisfy that fence nor be policed by it. Which is the
		// point — the fence exists to make real immutable claims earn themselves, not to police test scaffolding.
		RegisterFlagForTest(TestFlagImmutable, FlagSpec{Class: ClassImmutable, SecureDefault: true, Desc: "test fixture: immutable"}),
	}
	return func() {
		for _, r := range restores {
			r()
		}
	}
}
