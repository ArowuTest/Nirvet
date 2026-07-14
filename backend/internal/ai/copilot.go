package ai

// AI copilot investigation workspace (§6.12 AI-001, UI-depth Bucket B / B1). A persisted, multi-turn, assistive
// analyst copilot. It reuses the SINGLE egress chokepoint Service.completeExternal — customer telemetry (the
// grounding case context) is passed as `evidence` and REDACTED there; the analyst's own conversation is passed as
// the raw `instruction` (their words, not monitored-system data). It therefore adds NO new prov.Complete call, so
// scripts/check-ai-egress-redaction.sh stays green. Sessions are private to the creating analyst within a tenant
// (RLS + user_id). The copilot never takes actions (systemPrompt enforces assistive-only).

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

const (
	maxCopilotMessageLen = 4000 // per-message input cap (safety bound, not a policy threshold)
	maxCopilotHistory    = 20   // last N turns fed back as context (cost/latency bound)
	copilotDisabledReply = "The AI provider is not configured for this tenant, so I can't answer right now. A platform admin can enable a provider under Administration → AI config. (No customer data left the platform.)"
)

// CopilotSession is one private investigation conversation.
type CopilotSession struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Title       string     `json:"title"`
	IncidentRef *uuid.UUID `json:"incident_ref,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CopilotTurn is one message in a session. Model is set on assistant turns; user turns carry the analyst's text.
type CopilotTurn struct {
	ID        uuid.UUID `json:"id"`
	Role      string    `json:"role"` // user | assistant
	Content   string    `json:"content"`
	Model     string    `json:"model,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// StartCopilotSession creates a private session for the caller, optionally grounded in an incident.
func (s *Service) StartCopilotSession(ctx context.Context, p auth.Principal, title string, incidentRef *uuid.UUID) (*CopilotSession, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "New investigation"
	}
	if len(title) > 200 {
		return nil, httpx.ErrBadRequest("title too long")
	}
	sess := &CopilotSession{ID: uuid.New(), UserID: p.UserID, Title: title, IncidentRef: incidentRef}
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO ai_copilot_sessions (id, user_id, title, incident_ref)
			 VALUES ($1,$2,$3,$4) RETURNING created_at, updated_at`,
			sess.ID, sess.UserID, sess.Title, sess.IncidentRef).Scan(&sess.CreatedAt, &sess.UpdatedAt)
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not create session")
	}
	return sess, nil
}

// ListCopilotSessions returns the caller's own sessions, most-recently-updated first.
func (s *Service) ListCopilotSessions(ctx context.Context, p auth.Principal) ([]CopilotSession, error) {
	var out []CopilotSession
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, user_id, title, incident_ref, created_at, updated_at
			   FROM ai_copilot_sessions WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 100`, p.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CopilotSession
			if err := rows.Scan(&c.ID, &c.UserID, &c.Title, &c.IncidentRef, &c.CreatedAt, &c.UpdatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list sessions")
	}
	return out, nil
}

// getCopilotSession loads a session the caller owns (RLS scopes the tenant; user_id scopes ownership → not-found
// for a peer or another tenant, never a cross-user read).
func (s *Service) getCopilotSession(ctx context.Context, tx pgx.Tx, p auth.Principal, id uuid.UUID) (*CopilotSession, error) {
	var c CopilotSession
	err := tx.QueryRow(ctx,
		`SELECT id, user_id, title, incident_ref, created_at, updated_at
		   FROM ai_copilot_sessions WHERE id = $1 AND user_id = $2`, id, p.UserID).
		Scan(&c.ID, &c.UserID, &c.Title, &c.IncidentRef, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, httpx.ErrNotFound("session not found")
	}
	return &c, nil
}

// GetCopilotSession returns a session the caller owns plus its turns in order.
func (s *Service) GetCopilotSession(ctx context.Context, p auth.Principal, id uuid.UUID) (*CopilotSession, []CopilotTurn, error) {
	var sess *CopilotSession
	var turns []CopilotTurn
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		c, err := s.getCopilotSession(ctx, tx, p, id)
		if err != nil {
			return err
		}
		sess = c
		ts, err := loadTurns(ctx, tx, id, 0)
		if err != nil {
			return err
		}
		turns = ts
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return sess, turns, nil
}

// loadTurns returns a session's turns oldest-first. limit>0 keeps only the most recent N (still oldest-first).
func loadTurns(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, limit int) ([]CopilotTurn, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, role, content, model, created_at FROM ai_copilot_turns
		   WHERE session_id = $1 ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CopilotTurn
	for rows.Next() {
		var t CopilotTurn
		var model *string
		if err := rows.Scan(&t.ID, &t.Role, &t.Content, &model, &t.CreatedAt); err != nil {
			return nil, err
		}
		if model != nil {
			t.Model = *model
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// buildCopilotInstruction flattens the prior turns + the new question into the raw instruction string (outside the
// redaction fence — it is the analyst's own words). The trailing "Copilot:" cues the model to answer.
func buildCopilotInstruction(history []CopilotTurn, message string) string {
	var b strings.Builder
	b.WriteString("\n\nYou are in a multi-turn investigation chat with a SOC analyst. Any DATA block above is redacted case context. Answer the latest analyst question concisely and assistively; never instruct anyone to take destructive action.\n\n")
	for _, t := range history {
		who := "Analyst"
		if t.Role == "assistant" {
			who = "Copilot"
		}
		b.WriteString(who + ": " + t.Content + "\n")
	}
	b.WriteString("Analyst: " + message + "\nCopilot:")
	return b.String()
}

// Ask appends the analyst's message to a session, generates an assistive reply through the redaction chokepoint,
// persists both turns, and audits the call. When no provider is configured it stores a truthful "not configured"
// reply rather than fabricating an answer (and nothing egresses).
func (s *Service) Ask(ctx context.Context, p auth.Principal, sessionID uuid.UUID, message string) (*CopilotTurn, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, httpx.ErrBadRequest("message is required")
	}
	if len(message) > maxCopilotMessageLen {
		return nil, httpx.ErrBadRequest("message too long")
	}

	// Load the session (ownership) + recent history for context.
	var sess *CopilotSession
	var history []CopilotTurn
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		c, err := s.getCopilotSession(ctx, tx, p, sessionID)
		if err != nil {
			return err
		}
		sess = c
		history, err = loadTurns(ctx, tx, sessionID, maxCopilotHistory)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Grounding: build redactable case-context evidence from the session's incident (customer telemetry → the
	// Redactor masks it at completeExternal). Fail-open to no context if the incident can't be read.
	var evidence []string
	if sess.IncidentRef != nil && s.incidents != nil {
		if inc, ierr := s.incidents.Get(ctx, p.TenantID, *sess.IncidentRef); ierr == nil && inc != nil {
			evidence = []string{
				"incident_title=" + inc.Title,
				"severity=" + inc.Severity,
				"stage=" + string(inc.Stage),
			}
		}
	}

	instruction := buildCopilotInstruction(history, message)

	prov, res := s.resolve(ctx, p.TenantID)
	model := prov.Model()
	var reply string
	var rr RedactionResult
	if prov.Available() {
		text, r, cerr := s.completeExternal(ctx, p.TenantID, prov, evidence, instruction)
		rr = r
		if cerr == nil && strings.TrimSpace(text) != "" {
			reply = text
		} else {
			reply = "I couldn't reach the AI provider just now — please retry. (No customer data was exposed.)"
			model = "offline-fallback (llm error)"
		}
	} else {
		reply = copilotDisabledReply
		model = "offline (no provider)"
	}

	assistant := &CopilotTurn{ID: uuid.New(), Role: "assistant", Content: reply, Model: model}
	err = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO ai_copilot_turns (session_id, role, content) VALUES ($1,'user',$2)`, sessionID, message); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO ai_copilot_turns (session_id, role, content, model, redaction)
			 VALUES ($1,'assistant',$2,$3,$4) RETURNING id, created_at`,
			sessionID, assistant.Content, assistant.Model, withRedactionMeta(map[string]any{}, rr)).
			Scan(&assistant.ID, &assistant.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_copilot_sessions SET updated_at = now() WHERE id = $1`, sessionID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.copilot_message",
			Target:   "copilot_session:" + sessionID.String(),
			Metadata: withRedactionMeta(withProviderMeta(auditMeta(model, reply), res), rr),
		})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not record conversation")
	}
	return assistant, nil
}
