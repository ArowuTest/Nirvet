// Package safe runs background work with panic recovery, so a single panic in a
// long-lived loop cannot silently kill the goroutine — and the subsystem it drives —
// for the lifetime of the process (SEC review R2 H-E). It is the loop-level analogue of
// the ingest worker's per-job processGuarded.
package safe

import "log/slog"

// Do runs fn, recovering from any panic and logging it under name. Wrap the body of
// every long-lived background tick in it: a poison input (nil map, bad type, driver
// fault) is contained to that tick, and the loop keeps running.
func Do(log *slog.Logger, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil && log != nil {
			log.Error("background loop recovered from panic", "loop", name, "panic", r)
		}
	}()
	fn()
}
