// Package logger provides a structured slog logger for the platform.
// NEVER log secrets, tokens, or connector credentials (ADR-0004).
package logger

import (
	"log/slog"
	"os"
)

// New returns a JSON structured logger. In development it uses text for readability.
func New(env string) *slog.Logger {
	level := slog.LevelInfo
	if env == "development" {
		level = slog.LevelDebug
	}
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if env == "development" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}
