package audit

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
)

// Mutations records an immutable audit event for every SUCCESSFUL authenticated
// mutating request (NFR-003). It is placed after authentication so the principal
// is available. High-volume ingestion is excluded (raw_events is its evidence
// trail); domain code may still write richer, action-specific audit entries.
func Mutations(db *database.DB) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isMutation(r.Method) || strings.HasPrefix(r.URL.Path, "/ingest") {
				next.ServeHTTP(w, r)
				return
			}
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if rec.status >= 400 {
				return
			}
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				return
			}
			// R6: a swallowed write here means a SUCCESSFUL mutation went un-audited (NFR-003) with no
			// trace. We cannot fail the (already-committed) response, but the gap must be diagnosable.
			if aerr := db.WithTenant(r.Context(), p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
				return Record(ctx, tx, Entry{
					ActorID:    p.UserID,
					ActorEmail: p.Email,
					Action:     r.Method + " " + r.URL.Path,
					Metadata:   map[string]any{"status": rec.status},
					RequestID:  httpx.RequestIDFrom(r.Context()),
				})
			}); aerr != nil {
				slog.Error("audit middleware failed to record mutation (NFR-003 gap)",
					"tenant", p.TenantID, "actor", p.UserID,
					"action", r.Method+" "+r.URL.Path, "err", aerr)
			}
		})
	}
}

func isMutation(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
