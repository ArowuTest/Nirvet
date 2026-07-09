// Package testsupport holds shared helpers for integration tests. It is imported ONLY from _test.go
// files, so its dependency on the testing package never reaches a production binary.
package testsupport

import (
	"os"
	"testing"
)

// RequireDSN returns the integration-test database DSN from NIRVET_TEST_DATABASE_URL.
//
// When the variable is unset it SKIPS locally (developer convenience — a dev without a Postgres can
// still run the unit tests) but FAILS under CI. That asymmetry is the whole point: if the CI database
// service ever fails to come up, an integration suite that merely t.Skip()'d would let the whole run
// go green on a suite that never executed — the same silent-green failure the red-HEAD incident
// exposed, one layer up. Failing here turns "silently skipped in CI" into a loud red at the source.
//
// CI is detected via the CI env var, which GitHub Actions (and most CI providers) set to "true".
func RequireDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("NIRVET_TEST_DATABASE_URL must be set in CI: integration tests must not silently skip (is the Postgres service up?)")
		}
		t.Skip("set NIRVET_TEST_DATABASE_URL to run integration tests")
	}
	return dsn
}
