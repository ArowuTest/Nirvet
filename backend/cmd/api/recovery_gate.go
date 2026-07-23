package main

import (
	"fmt"

	"github.com/ArowuTest/nirvet/internal/platform/recovery"
)

// init runs before any listener, migration, connector, queue, or actioner is
// started. A restored instance therefore cannot accidentally serve or replay
// work while recovery certification is missing or malformed.
func init() {
	if err := recovery.RequireServingFromEnv(); err != nil {
		panic(fmt.Sprintf("refusing restored startup: %v", err))
	}
}
