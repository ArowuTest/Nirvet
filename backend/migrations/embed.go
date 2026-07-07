// Package migrations embeds the SQL migration files so the migrate binary is
// self-contained.
package migrations

import "embed"

// FS holds the ordered *.sql migration files.
//
//go:embed *.sql
var FS embed.FS
