// Command migrate applies the embedded SQL migrations as the privileged owner role. The actual runner lives in
// internal/platform/dbmigrate (shared with the API's boot-time self-migration path — see dbmigrate's doc for the
// FORCE-RLS / non-superuser-owner rationale). This binary is kept for local/CI use and manual ops runs.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ArowuTest/nirvet/internal/platform/dbmigrate"
)

func main() {
	dsn := os.Getenv("NIRVET_MIGRATE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/nirvet?sslmode=disable"
	}
	if _, err := dbmigrate.Run(context.Background(), dsn, func(f string, a ...any) { fmt.Printf(f+"\n", a...) }); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}
