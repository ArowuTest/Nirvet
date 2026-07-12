package reporting

// §6.13 #188 — the regulatory breach-notification report. A per-incident structured compliance artifact (the owner's
// "there should always be a breach report" requirement) that a customer or regulator can lodge. It rides the entire
// reporting spine already hardened in slice A:
//   - a typed-Cell Dataset ⇒ formula-injection-proof at serialize (R-3): analyst narrative is a KindString cell that
//     can never be interpreted as a spreadsheet formula; timeline dates are native KindTime cells (a regulator reads
//     real dates, never attacker-controlled text);
//   - the same row/cell/byte caps, OPAQUE-key blob store, session-authorized download and REP-008 audit via
//     finalizeReport — so a new report type cannot bypass any of those controls.
//
// The incident content is read through the NARROW BreachIncidentReader interface (implemented by a thin adapter over
// incident.Service in main). Reporting therefore keeps ZERO import of the incident package — no cycle — and the reader
// runs under WithTenant so RLS confines the read to the caller's tenant: a foreign-tenant incident id resolves to
// not-found, never a cross-tenant disclosure.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// BreachIncident is the reporting-owned projection of an incident needed to lodge a breach notification. The adapter
// in main fills it from incident.Service.Get; reporting never sees the incident package's own types.
type BreachIncident struct {
	ID             uuid.UUID
	Title          string
	Severity       string
	Category       string
	Stage          string
	CreatedAt      time.Time  // detection/opening time
	AcknowledgedAt *time.Time // first ownership (nil until acknowledged)
	ClosedAt       *time.Time // resolution/closure (nil until closed)
	Disposition    string     // closure narrative — empty until the incident is closed
	RootCause      string
	Impact         string
	ActionsTaken   string
	LessonsLearned string
	CustomerAck    bool
}

// BreachIncidentReader fetches one incident projection, tenant-scoped. The adapter reads under WithTenant so RLS
// confines it (a foreign-tenant or absent id must resolve to not-found). Deliberately narrow to keep reporting free
// of an incident import.
type BreachIncidentReader interface {
	BreachIncident(ctx context.Context, tenantID, incidentID uuid.UUID) (BreachIncident, error)
}

// WithBreachSource wires the incident reader. Optional dependency: if nil, breach reports are unavailable (the
// generator fails closed with a clear error rather than emitting an empty artifact).
func (rs *ReportService) WithBreachSource(src BreachIncidentReader) *ReportService {
	rs.breach = src
	return rs
}

// WithSigner wires the Ed25519 key that signs the breach report (the same platform key that signs evidence packs).
// Optional: with no signer the report is emitted unsigned. A signature gives a regulator-lodged notification
// non-repudiation + tamper-evidence.
func (rs *ReportService) WithSigner(signer ed25519.PrivateKey) *ReportService {
	rs.signer = signer
	return rs
}

// breachSig is the detached signature over the canonical breach payload (empty when unsigned).
type breachSig struct{ Sig, Pub string }

// signBreach signs the CANONICAL breach payload (a fixed-field-order JSON of the incident facts, independent of the
// output format) so a verifier can reconstruct the payload from the visible fields and check it against the
// in-band public key. Returns empty when no signer is wired.
func (rs *ReportService) signBreach(inc BreachIncident) breachSig {
	if rs.signer == nil {
		return breachSig{}
	}
	payload := canonicalBreachPayload(inc)
	sig := ed25519.Sign(rs.signer, payload)
	pub := rs.signer.Public().(ed25519.PublicKey)
	return breachSig{Sig: base64.StdEncoding.EncodeToString(sig), Pub: base64.StdEncoding.EncodeToString(pub)}
}

// canonicalBreachPayload is the deterministic byte string that gets signed. Field ORDER is fixed by the struct
// declaration (Go marshals struct fields in order, no maps), and timestamps are RFC3339 UTC (empty when absent) —
// so a verifier reconstructs exactly these bytes from the report's fields. Do NOT reorder or rename these fields.
func canonicalBreachPayload(inc BreachIncident) []byte {
	ts := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	type payload struct {
		ID             string `json:"id"`
		Title          string `json:"title"`
		Severity       string `json:"severity"`
		Category       string `json:"category"`
		Stage          string `json:"stage"`
		DetectedAt     string `json:"detected_at"`
		AcknowledgedAt string `json:"acknowledged_at"`
		ResolvedAt     string `json:"resolved_at"`
		Disposition    string `json:"disposition"`
		RootCause      string `json:"root_cause"`
		Impact         string `json:"impact"`
		ActionsTaken   string `json:"actions_taken"`
		LessonsLearned string `json:"lessons_learned"`
		CustomerAck    bool   `json:"customer_acknowledged"`
	}
	b, _ := json.Marshal(payload{
		ID: inc.ID.String(), Title: inc.Title, Severity: inc.Severity, Category: inc.Category, Stage: inc.Stage,
		DetectedAt: inc.CreatedAt.UTC().Format(time.RFC3339), AcknowledgedAt: ts(inc.AcknowledgedAt), ResolvedAt: ts(inc.ClosedAt),
		Disposition: inc.Disposition, RootCause: inc.RootCause, Impact: inc.Impact, ActionsTaken: inc.ActionsTaken,
		LessonsLearned: inc.LessonsLearned, CustomerAck: inc.CustomerAck,
	})
	return b
}

// GenerateBreachReport assembles, serializes, and stores a regulatory breach-notification report for one incident in
// the caller's tenant. It shares the exact caps/serialize/store/audit spine as Generate (finalizeReport); the only
// new surface is the RLS-confined incident projection read and the breach dataset. The type "breach_report" is NOT
// reachable through the generic Generate entry point (which has no incident id and hardcodes the service-review
// body) — a breach report can only be produced here, with an incident id.
func (rs *ReportService) GenerateBreachReport(ctx context.Context, p auth.Principal, incidentID uuid.UUID, format Format) (*Report, error) {
	if rs.breach == nil {
		return nil, httpx.ErrInternal("breach reporting is not configured")
	}
	if incidentID == uuid.Nil {
		return nil, httpx.ErrBadRequest("incident id is required")
	}
	if format != FormatJSON && format != FormatCSV && format != FormatXLSX && format != FormatPDF {
		return nil, httpx.ErrBadRequest("unsupported format (docx is deferred): " + string(format))
	}
	// Read the incident FIRST (RLS-confined) so an unknown/foreign id fails before any report record is created —
	// no orphan 'running' rows for ids the caller can't see.
	inc, err := rs.breach.BreachIncident(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, err // already an httpx error (not-found on foreign/absent id)
	}
	lim := rs.limits(ctx)
	params, _ := json.Marshal(map[string]string{"type": "breach_report", "incident": incidentID.String()})
	id, err := rs.repo.Create(ctx, p.TenantID, p.UserID, "breach_report", format, params)
	if err != nil {
		return nil, err
	}
	ds := buildBreachReport(p.TenantID, inc, rs.signBreach(inc))
	return rs.finalizeReport(ctx, p, id, ds, format, lim)
}

// buildBreachReport turns the incident projection into a field/value breach-notification dataset. Every value is a
// TYPED cell: identity/classification and analyst narrative are KindString (formula-proof at serialize); the
// regulatory timeline uses native KindTime cells and durations are native KindNumber — so the compliance timeline
// cannot be forged via crafted incident text and a spreadsheet never mis-parses a date as a formula.
func buildBreachReport(tenantID uuid.UUID, inc BreachIncident, sg breachSig) Dataset {
	ds := Dataset{
		Title:   "Regulatory Breach Notification",
		Columns: []string{"field", "value"},
		Meta: map[string]string{
			"tenant":       tenantID.String(),
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"scope":        "incident",
			"report_type":  "breach_report",
			"incident_id":  inc.ID.String(),
		},
	}
	// Non-repudiation: a detached Ed25519 signature over the canonical breach payload, plus the in-band public key
	// and the exact field list it covers, so a regulator can verify the notification is unaltered.
	if sg.Sig != "" {
		ds.Meta["signature_alg"] = "ed25519"
		ds.Meta["signature"] = sg.Sig
		ds.Meta["signing_public_key"] = sg.Pub
		ds.Meta["signed_fields"] = "id,title,severity,category,stage,detected_at,acknowledged_at,resolved_at,disposition,root_cause,impact,actions_taken,lessons_learned,customer_acknowledged"
	}
	// str emits a string field only when non-empty, so a still-open incident's blank closure narrative doesn't
	// clutter the notification with empty rows.
	str := func(field, v string) {
		if v == "" {
			return
		}
		ds.Rows = append(ds.Rows, []Cell{Str(field), Str(v)})
	}

	// Identity + classification (always present).
	ds.Rows = append(ds.Rows, []Cell{Str("incident_id"), Str(inc.ID.String())})
	str("title", inc.Title)
	str("severity", inc.Severity)
	str("category", inc.Category)
	str("stage", inc.Stage)

	// Regulatory timeline — native time/number cells.
	ds.Rows = append(ds.Rows, []Cell{Str("detected_at"), TimeCell(inc.CreatedAt)})
	if inc.AcknowledgedAt != nil {
		ds.Rows = append(ds.Rows, []Cell{Str("acknowledged_at"), TimeCell(*inc.AcknowledgedAt)})
		ds.Rows = append(ds.Rows, []Cell{Str("time_to_acknowledge_seconds"), Num(inc.AcknowledgedAt.Sub(inc.CreatedAt).Seconds())})
	}
	if inc.ClosedAt != nil {
		ds.Rows = append(ds.Rows, []Cell{Str("resolved_at"), TimeCell(*inc.ClosedAt)})
		ds.Rows = append(ds.Rows, []Cell{Str("time_to_resolve_seconds"), Num(inc.ClosedAt.Sub(inc.CreatedAt).Seconds())})
	}

	// Closure narrative (populated only once the incident is closed) — untrusted analyst text, formula-proof.
	str("disposition", inc.Disposition)
	str("root_cause", inc.RootCause)
	str("impact", inc.Impact)
	str("actions_taken", inc.ActionsTaken)
	str("lessons_learned", inc.LessonsLearned)
	ds.Rows = append(ds.Rows, []Cell{Str("customer_acknowledged"), BoolCell(inc.CustomerAck)})
	return ds
}
