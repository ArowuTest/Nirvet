// Package schemacheck contains structural schema-invariant tests (tenant-composite PK/UNIQUE and
// enum↔CHECK consistency) that run against the migrated database in CI. It has no runtime code — the
// invariants live entirely in schemacheck_test.go. See that file for the rationale.
package schemacheck
