// Command migrate applies embedded SQL migrations. It connects as a privileged
// (owner/superuser) role so it can create the app role, tables, RLS policies and
// SECURITY DEFINER functions. The application itself connects as nirvet_app.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/ArowuTest/nirvet/migrations"
	"github.com/jackc/pgx/v5"
)

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
		// Simple query protocol allows multiple statements per migration file.
		if mrr := conn.PgConn().Exec(ctx, string(sqlBytes)); mrr != nil {
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
	fmt.Printf("migrate: done (%d applied, %d total)\n", applied, len(entries))
}
