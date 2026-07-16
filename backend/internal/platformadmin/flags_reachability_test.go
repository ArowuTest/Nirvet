package platformadmin

// CI fence for J4: a declared control must have a WRITER and a READER, both in production code. One end alone is
// not a control.
//
// J4 was the feature-flag registry declaring five settable flags — including
// `"soar.destructive_enabled": {ClassProtected, false, "SOAR real-containment master gate"}` — that NOTHING read.
// NewFlagResolver was never constructed in main.go. A platform admin could flip the containment master gate, with
// four-eyes ceremony and an audit trail, and change nothing; the real gates were elsewhere. That is the mirror of
// the D5 protected_hosts bug: that guard had a reader and no writer, so it silently ALLOWED; flags had a writer
// and no reader, so they silently REASSURED.
//
// Both ends were missed by careful people. The reviewer's own audit logged "Feature Flags = empty, dead-end until
// seeded" as a by-design observation — checking whether the list was populated and never asking whether anything
// read it. I found protected_hosts only because a question about a different registry sent me looking. Neither of
// us is immune, which is exactly why this is a test and not a rule in a document.
//
// The fence is source-scanning, like the net.Dial and SECURITY-DEFINER fences: the fact it needs to assert is
// structural (does a reader exist?), not behavioural, so no amount of runtime testing can see it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// productionRegistry is the registry as DECLARED in code, snapshotted at package-var init — i.e. before any test
// body can run and temporarily register a synthetic fixture (see export_test.go RegisterFlagForTest).
//
// This matters: without it, a fence that reads the live `registry` could be tripped by a test fixture, or — far
// worse — a fixture could satisfy it, and the fence would be evadable by registering a flag in a test. The whole
// point of this file is that it cannot be talked out of its answer.
var productionRegistry = func() map[string]FlagSpec {
	m := make(map[string]FlagSpec, len(registry))
	for k, v := range registry {
		m[k] = v
	}
	return m
}()

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate go.mod")
	return ""
}

// prodGoFiles returns every non-test .go file under the module.
func prodGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if n := info.Name(); n == "vendor" || n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// Every non-immutable registry entry must be referenced by production code somewhere other than the registry
// itself. A settable flag nobody reads is J4 — it can be flipped, audited, and shown as a control while doing
// nothing.
//
// ClassImmutable is exempt BY DESIGN: those are resolved from code and a DB row is deliberately inert (the
// registry entry exists so the SET path can refuse them and so the claim is auditable). The code IS their reader.
func TestEverySettableFlagHasAProductionReader(t *testing.T) {
	root := repoRoot(t)
	files := prodGoFiles(t, root)

	var corpus strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, filepath.Join("platformadmin", "flags.go")) {
			continue // the declaration site is not a reader
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		corpus.Write(b)
	}
	hay := corpus.String()

	for key, spec := range productionRegistry {
		if spec.Class == ClassImmutable {
			continue
		}
		if !strings.Contains(hay, `"`+key+`"`) {
			t.Errorf("flag %q (class %s) is settable but NOTHING in production code references it — this is J4: "+
				"an admin can flip it, with audit and ceremony, and change nothing. Either wire a reader "+
				"(FlagResolver.Enabled) or delete the registry entry. A declared control needs a writer AND a "+
				"reader; one end alone is not a control.", key, spec.Class)
		}
	}
}

// The structural fact whose absence made every flag inert: nothing ever built the resolver. If the registry
// declares any settable flag, main.go must construct one — otherwise the reader cannot exist no matter how many
// call sites reference the key.
func TestFlagResolverIsWiredWhenSettableFlagsExist(t *testing.T) {
	settable := 0
	for _, spec := range productionRegistry {
		if spec.Class != ClassImmutable {
			settable++
		}
	}
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "cmd", "api", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	wired := strings.Contains(string(b), "NewFlagResolver(")

	switch {
	case settable > 0 && !wired:
		t.Errorf("the registry declares %d settable flag(s) but cmd/api/main.go never constructs NewFlagResolver — "+
			"no flag can be read in production. This is exactly the J4 state.", settable)
	case settable == 0 && wired:
		// Not a failure: harmless, but it means the resolver is built and consulted for nothing. Flag it so the
		// next person deletes one or adds the other rather than inheriting an ambiguity.
		t.Log("note: no settable flags are registered, yet main.go constructs a FlagResolver — the resolver is " +
			"wired but has nothing to resolve. Fine while the registry is immutable-only; revisit if that changes.")
	}
}

// Guards the exemption itself: if ClassImmutable ever became settable, the reachability fence above would silently
// stop covering those keys. Pin the property the exemption depends on.
func TestImmutableFlagsAreNotSettable(t *testing.T) {
	for key, spec := range productionRegistry {
		if spec.Class != ClassImmutable {
			continue
		}
		if !IsImmutable(key) {
			t.Errorf("flag %q is registered ClassImmutable but IsImmutable() disagrees — the reachability fence "+
				"exempts immutable keys, so this would silently drop it from coverage", key)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------
// J5: the exemption must be EARNED PER FLAG.
//
// The J4 fix exempted ClassImmutable from the reachability fence because "the code is the reader". That is a
// per-flag FACT and it was asserted as a CLASS PROPERTY, so nothing ever checked it — and it was false for
// mfa.enforce, which claimed "MFA enforcement", immutable, secure-default true, while login demanded a code only
// `if u.MFAEnabled`. The single flag the fence exempted was the single flag that was lying. A category exemption
// is an exemption nobody re-checks.
//
// So each immutable flag must name its enforcing code (FlagSpec.EnforcedBy) AND register a proof below that fails
// if that control is absent. Deleting the REVOKE from 0017, or re-adding mfa.enforce, turns this red.
// ---------------------------------------------------------------------------------------------------------

// immutableProofs asserts the CONTROL exists — not that the flag is declared. Adding an immutable flag without a
// proof here fails TestEveryImmutableFlagProvesItsControl, which is the whole point: you cannot claim
// "configuration can never disable this" without showing what enforces it.
var immutableProofs = map[string]func(t *testing.T, root string){
	"rls.enforce":     proveRLSEnforced,
	"audit.immutable": proveAuditAppendOnly,
}

func TestEveryImmutableFlagProvesItsControl(t *testing.T) {
	root := repoRoot(t)
	for key, spec := range productionRegistry {
		if spec.Class != ClassImmutable {
			continue
		}
		if strings.TrimSpace(spec.EnforcedBy) == "" {
			t.Errorf("immutable flag %q declares no EnforcedBy — it claims configuration can never disable this "+
				"control while naming nothing that enforces it. This is J5 (mfa.enforce). Name the code path, or "+
				"delete the flag until the control exists.", key)
			continue
		}
		proof, ok := immutableProofs[key]
		if !ok {
			t.Errorf("immutable flag %q has no proof-test in immutableProofs — the reachability fence EXEMPTS "+
				"immutable flags, so without a proof nothing on this project will ever check that %q is real. "+
				"That exemption is earned per flag, never granted by class.", key, spec.EnforcedBy)
			continue
		}
		t.Run(key, func(t *testing.T) { proof(t, root) })
	}
}

// migrationsCorpus concatenates every migration — the enforcement for both surviving immutable flags is schema-level.
func migrationsCorpus(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	entries, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		c, err := os.ReadFile(filepath.Join(root, "migrations", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		b.Write(c)
	}
	return b.String()
}

// rls.enforce: tenant isolation is real if migrations FORCE row security (so even the table owner is bound) and
// schemacheck fences it. Verified: 63 migrations carry FORCE ROW LEVEL SECURITY.
func proveRLSEnforced(t *testing.T, root string) {
	if !strings.Contains(migrationsCorpus(t, root), "FORCE ROW LEVEL SECURITY") {
		t.Error("rls.enforce claims tenant isolation cannot be disabled by config, but no migration FORCEs row " +
			"level security — the claim is unbacked")
	}
	b, err := os.ReadFile(filepath.Join(root, "internal", "schemacheck", "schemacheck_test.go"))
	if err != nil || !strings.Contains(string(b), "relforcerowsecurity") {
		t.Error("rls.enforce's second leg is the schemacheck fence asserting relforcerowsecurity; it is gone, so " +
			"a future table could ship without FORCE RLS and nothing would notice")
	}
}

// audit.immutable: append-only is real if the app role cannot mutate audit_log. Verified: 0017:9.
func proveAuditAppendOnly(t *testing.T, root string) {
	corpus := migrationsCorpus(t, root)
	if !strings.Contains(corpus, "REVOKE UPDATE, DELETE, TRUNCATE ON audit_log") {
		t.Error("audit.immutable claims the audit log is append-only and config can never change that, but no " +
			"migration revokes UPDATE/DELETE/TRUNCATE on audit_log from the app role — the claim is unbacked")
	}
}
