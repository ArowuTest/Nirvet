// Command migrate applies embedded SQL migrations. It connects as a privileged
// owner role so it can create the app role, tables, RLS policies and SECURITY
// DEFINER functions. The application itself connects as nirvet_app.
//
// FORCE ROW LEVEL SECURITY and non-superuser owners
// -------------------------------------------------
// Several migrations seed GLOBAL rows (tenant_id NULL) into tables that carry
// FORCE ROW LEVEL SECURITY. FORCE makes RLS apply even to the table owner, and
// the tenant-scoped WITH CHECK (tenant_id = app_current_tenant()) rejects those
// NULL-tenant rows. On a local/CI Postgres the migrator connects as a SUPERUSER,
// which bypasses RLS, so the seeds commit. But managed Postgres (Render, Cloud
// SQL, RDS) only ever gives you a NON-superuser database owner — it is subject to
// FORCE, so those seeds fail with SQLSTATE 42501.
//
// Postgres' own remedy (see the error HINT) is `ALTER TABLE ... NO FORCE ROW
// LEVEL SECURITY`, which the owner is allowed to run. So when the connected role
// does not bypass RLS, this runner lifts FORCE for the duration of the migration
// (owner then seeds freely, still isolated because the APP connects as the
// non-owner nirvet_app which ENABLE — not FORCE — already binds), and restores
// FORCE on every declared table at the end. For a bypassing role the code path
// is a no-op: nothing is scanned, stripped, toggled, or restored.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"

	"github.com/ArowuTest/nirvet/migrations"
	"github.com/jackc/pgx/v5"
)

// Matches a standalone `ALTER TABLE <name> FORCE ROW LEVEL SECURITY;` statement.
// The identifier class excludes `%`, so the dynamic `EXECUTE format('ALTER TABLE
// %I FORCE ...')` in 0001 is deliberately NOT matched — those 7 core tables are
// never seeded and are restored from the live snapshot instead.
var forceStmtRe = regexp.MustCompile(`(?im)^[ \t]*ALTER[ \t]+TABLE[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+FORCE[ \t]+ROW[ \t]+LEVEL[ \t]+SECURITY[ \t]*;[ \t]*$`)

// forceRLSAllowlist mirrors schemacheck.TestTenantForceRLS: tables that carry a
// tenant_id but are intentionally NOT FORCE-RLS (pool-level / pre-tenant access).
// Keep in sync with that test and with the NOT IN list in the restore DO block.
var forceRLSAllowlist = []string{"ingest_jobs", "syslog_sources", "tenant_offboarding"}

func main() {
	dsn := os.Getenv("NIRVET_MIGRATE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/nirvet?sslmode=disable"
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate: connect:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		fmt.Fprintln(os.Stderr, "migrate: ensure schema_migrations:", err)
		os.Exit(1)
	}

	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate: glob:", err)
		os.Exit(1)
	}
	sort.Strings(entries)

	// Does the connected role bypass RLS? Superusers and BYPASSRLS roles do; a
	// managed-Postgres owner does not. This single fact selects the code path.
	var bypass bool
	if err := conn.QueryRow(ctx,
		`SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		fmt.Fprintln(os.Stderr, "migrate: role check:", err)
		os.Exit(1)
	}

	// Non-bypass path: lift FORCE on every currently-FORCE-enabled table so that
	// (a) inline FORCE stripped below and (b) already-applied migrations on a
	// resume don't block pending global seeds. FORCE is re-established from the
	// live catalog after the run (self-healing — see below).
	if !bypass {
		lifted := 0
		if _, e := conn.Exec(ctx, `DO $$
			DECLARE r record;
			BEGIN
			  FOR r IN SELECT c.relname FROM pg_class c
			    WHERE c.relkind='r' AND c.relnamespace='public'::regnamespace
			      AND c.relrowsecurity AND c.relforcerowsecurity
			  LOOP EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', r.relname); END LOOP;
			END$$;`); e != nil {
			fmt.Fprintln(os.Stderr, "migrate: lift FORCE:", e)
			os.Exit(1)
		}
		_ = lifted
		fmt.Printf("migrate: role %q does not bypass RLS — FORCE lifted for the migration session\n",
			currentUser(ctx, conn))
	}

	applied := 0
	for _, name := range entries {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&exists); err != nil {
			fmt.Fprintln(os.Stderr, "migrate: check:", err)
			os.Exit(1)
		}
		if exists {
			continue
		}
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "migrate: read", name, err)
			os.Exit(1)
		}
		sqlText := string(sqlBytes)
		if !bypass {
			// Defer inline FORCE so the owner can seed global rows; restored below.
			sqlText = forceStmtRe.ReplaceAllString(sqlText, "-- [migrate] FORCE deferred (non-bypass role): $0")
		}
		// Simple query protocol allows multiple statements per migration file.
		if mrr := conn.PgConn().Exec(ctx, sqlText); mrr != nil {
			if _, err := mrr.ReadAll(); err != nil {
				fmt.Fprintln(os.Stderr, "migrate: apply", name, err)
				os.Exit(1)
			}
		}
		if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			fmt.Fprintln(os.Stderr, "migrate: record", name, err)
			os.Exit(1)
		}
		fmt.Println("applied", name)
		applied++
	}

	// Restore FORCE (self-healing). The schema invariant — asserted in CI by
	// schemacheck.TestTenantForceRLS — is: every RLS-ENABLED table carries FORCE,
	// EXCEPT the three system tables in forceRLSAllowlist (they hold tenant_id but
	// have no tenant-facing reader, so FORCE would break their pool-level access).
	// Restoring from the live catalog (rather than a scanned set) covers static
	// AND dynamic FORCE declarations and heals a prior interrupted run.
	if !bypass {
		var restored int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM pg_class c
			WHERE c.relkind='r' AND c.relnamespace='public'::regnamespace
			  AND c.relrowsecurity AND NOT c.relforcerowsecurity
			  AND c.relname <> ALL($1::text[])`, forceRLSAllowlist).Scan(&restored); err != nil {
			fmt.Fprintln(os.Stderr, "migrate: restore count:", err)
			os.Exit(1)
		}
		if _, e := conn.Exec(ctx, `DO $$
			DECLARE r record;
			BEGIN
			  FOR r IN SELECT c.relname FROM pg_class c
			    WHERE c.relkind='r' AND c.relnamespace='public'::regnamespace
			      AND c.relrowsecurity AND NOT c.relforcerowsecurity
			      AND c.relname NOT IN ('ingest_jobs','syslog_sources','tenant_offboarding')
			  LOOP EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', r.relname); END LOOP;
			END$$;`); e != nil {
			fmt.Fprintln(os.Stderr, "migrate: restore FORCE:", e)
			os.Exit(1)
		}
		fmt.Printf("migrate: FORCE ROW LEVEL SECURITY restored on %d table(s)\n", restored)
	}

	fmt.Printf("migrate: done (%d applied, %d total)\n", applied, len(entries))
}

func currentUser(ctx context.Context, conn *pgx.Conn) string {
	var u string
	_ = conn.QueryRow(ctx, `SELECT current_user`).Scan(&u)
	return u
}
