// Package dbmigrate applies the embedded SQL migrations as a privileged OWNER role. It is the single source of
// truth for schema migration, called BOTH by the standalone `cmd/migrate` binary AND by the API on boot
// (main.go) when NIRVET_MIGRATE_DATABASE_URL is set — so the schema self-heals on every deploy regardless of the
// hosting platform's pre-deploy support (e.g. Render free web services do NOT run preDeployCommand, which silently
// left the live DB behind — this boot path removes that dependency). The app itself serves as the non-owner
// nirvet_app role; only this migration path uses the owner string.
//
// FORCE ROW LEVEL SECURITY + non-superuser owners: several migrations seed GLOBAL (tenant_id NULL) rows into
// FORCE-RLS tables. A managed-Postgres owner is NOT a superuser, so FORCE applies to it and the tenant-scoped
// WITH CHECK rejects those seeds (SQLSTATE 42501). Remedy (per Postgres' own HINT): the owner lifts FORCE for the
// migration session, seeds freely (still isolated — the APP connects as non-owner nirvet_app which ENABLEs, not
// FORCEs), then FORCE is restored from the live catalog. For a bypassing role (local/CI superuser) it's a no-op.
package dbmigrate

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/migrations"
)

// advisoryLockKey serializes concurrent migrators (e.g. multiple booting instances) so only one applies at a time;
// the others wait, then find everything already applied. Arbitrary stable constant ("nirvet-migrate").
const advisoryLockKey int64 = 0x4e4952564d4947 // NIRVMIG

// forceStmtRe matches a standalone `ALTER TABLE <name> FORCE ROW LEVEL SECURITY;`. The identifier class excludes
// `%`, so the dynamic EXECUTE format('ALTER TABLE %I FORCE ...') in 0001 is deliberately NOT matched — those core
// tables are never seeded and are restored from the live snapshot instead.
var forceStmtRe = regexp.MustCompile(`(?im)^[ \t]*ALTER[ \t]+TABLE[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+FORCE[ \t]+ROW[ \t]+LEVEL[ \t]+SECURITY[ \t]*;[ \t]*$`)

// forceRLSAllowlist mirrors schemacheck.TestTenantForceRLS: tenant_id tables intentionally NOT FORCE-RLS
// (pool-level / pre-tenant access). Keep in sync with that test and the NOT IN list in the restore block.
var forceRLSAllowlist = []string{"ingest_jobs", "syslog_sources", "tenant_offboarding"}

// Logf is an optional logging sink (e.g. fmt.Printf or a structured logger adapter). nil silences progress lines.
type Logf func(format string, args ...any)

// Run applies all pending embedded migrations under an advisory lock and returns how many were applied. It is
// idempotent: already-recorded migrations are skipped, so re-running at head applies 0. Any failure returns an
// error (the caller decides whether to fail-closed); nothing is left partially recorded — each file is recorded
// only after it applies cleanly.
func Run(ctx context.Context, dsn string, logf Logf) (applied int, err error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	// Serialize migrators (multi-instance safe). Released on session close; also explicitly below.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return 0, fmt.Errorf("advisory lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey) }()

	if _, err := conn.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return 0, fmt.Errorf("glob: %w", err)
	}
	sort.Strings(entries)

	var bypass bool
	if err := conn.QueryRow(ctx,
		`SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		return 0, fmt.Errorf("role check: %w", err)
	}

	if !bypass {
		if _, e := conn.Exec(ctx, `DO $$
			DECLARE r record;
			BEGIN
			  FOR r IN SELECT c.relname FROM pg_class c
			    WHERE c.relkind='r' AND c.relnamespace='public'::regnamespace
			      AND c.relrowsecurity AND c.relforcerowsecurity
			  LOOP EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', r.relname); END LOOP;
			END$$;`); e != nil {
			return 0, fmt.Errorf("lift FORCE: %w", e)
		}
		logf("migrate: role %q does not bypass RLS — FORCE lifted for the migration session", currentUser(ctx, conn))
	}

	for _, name := range entries {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&exists); err != nil {
			return applied, fmt.Errorf("check %s: %w", name, err)
		}
		if exists {
			continue
		}
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return applied, fmt.Errorf("read %s: %w", name, err)
		}
		sqlText := string(sqlBytes)
		if !bypass {
			sqlText = forceStmtRe.ReplaceAllString(sqlText, "-- [migrate] FORCE deferred (non-bypass role): $0")
		}
		if mrr := conn.PgConn().Exec(ctx, sqlText); mrr != nil {
			if _, err := mrr.ReadAll(); err != nil {
				return applied, fmt.Errorf("apply %s: %w", name, err)
			}
		}
		if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			return applied, fmt.Errorf("record %s: %w", name, err)
		}
		logf("migrate: applied %s", name)
		applied++
	}

	if !bypass {
		if _, e := conn.Exec(ctx, `DO $$
			DECLARE r record;
			BEGIN
			  FOR r IN SELECT c.relname FROM pg_class c
			    WHERE c.relkind='r' AND c.relnamespace='public'::regnamespace
			      AND c.relrowsecurity AND NOT c.relforcerowsecurity
			      AND c.relname NOT IN ('ingest_jobs','syslog_sources','tenant_offboarding')
			  LOOP EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', r.relname); END LOOP;
			END$$;`); e != nil {
			return applied, fmt.Errorf("restore FORCE: %w", e)
		}
	}

	logf("migrate: done (%d applied, %d total)", applied, len(entries))
	return applied, nil
}

func currentUser(ctx context.Context, conn *pgx.Conn) string {
	var u string
	_ = conn.QueryRow(ctx, `SELECT current_user`).Scan(&u)
	return u
}
