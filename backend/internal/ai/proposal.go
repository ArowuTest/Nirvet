package ai

// AI response proposals (§6.12 S2b i3 — the HEAVY security half). The copilot may PROPOSE a response; it may never
// RUN one. A proposal is a DATA record written here in internal/ai. A HUMAN (senior/soc_manager) accepts it OUTSIDE
// this package (internal/airesponse), which promotes it into the EXISTING soar RunPendingApproval pipeline. This file
// therefore references NO soar/execution symbol — check-ai-no-direct-execution.sh keeps that structural (non-negotiable
// #1). The recommended action is validated against the tenant's action catalog at create (fail-closed): the AI can
// never propose an action the catalog + authority model doesn't already govern.

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

const (
	maxRationaleLen      = 4000
	maxImpactLen         = 2000
	maxProposalCitations = 40
	maxCitationLen       = 64
)

// validProposalRisk mirrors soar's §9.5 risk classes (kept as a local string set so internal/ai does not import
// soar — the fence). The DB CHECK (mig 0137) enforces the same set as a second line.
var validProposalRisk = map[string]bool{
	"informational": true, "low": true, "medium": true, "high": true, "business_critical": true,
}

// Proposal is an AI-recommended response to an incident — a data record, never a run. accepted_by/accepted_run_id are
// set only once a senior promotes it to a run through the soar pipeline (outside this package).
type Proposal struct {
	ID                uuid.UUID  `json:"id"`
	IncidentRef       uuid.UUID  `json:"incident_ref"`
	ProposedBy        string     `json:"proposed_by"` // always "ai" this slice
	RequestedBy       uuid.UUID  `json:"requested_by"`
	RecommendedAction string     `json:"recommended_action"`
	ConnectorKey      string     `json:"connector_key,omitempty"`
	Rationale         string     `json:"rationale,omitempty"`
	EvidenceCitations []string   `json:"evidence_citations"`
	RiskClass         string     `json:"risk_class"`
	Reversible        bool       `json:"reversible"`
	ExpectedImpact    string     `json:"expected_impact,omitempty"`
	Status            string     `json:"status"`
	AcceptedBy        *uuid.UUID `json:"accepted_by,omitempty"`
	AcceptedRunID     *uuid.UUID `json:"accepted_run_id,omitempty"`
}

// ActionCatalogReader resolves the tenant's valid (enabled) action keys. It is INJECTED (adapter lives in
// cmd/api/main.go wrapping soar.Service.ListActionCatalog) so internal/ai never imports soar — the AI can validate a
// proposed action against the catalog without a path to execution. nil → CreateProposal fails closed.
type ActionCatalogReader interface {
	ValidActionKeys(ctx context.Context, tenantID uuid.UUID) (map[string]bool, error)
}

// WithActionCatalog wires the catalog validator used to reject an unknown proposed action (fail-closed).
func (s *Service) WithActionCatalog(r ActionCatalogReader) *Service {
	s.actionCatalog = r
	return s
}

// ProposalInput is the analyst-initiated create payload. incident_ref + recommended_action are required; the action
// is validated against the tenant's catalog.
type ProposalInput struct {
	IncidentRef       uuid.UUID
	RecommendedAction string
	ConnectorKey      string
	Rationale         string
	EvidenceCitations []string
	RiskClass         string
	Reversible        bool
	ExpectedImpact    string
}

// CreateProposal records an AI-recommended response as a DATA row (status=pending). It NEVER executes: no soar/actioner
// reference exists in this package. Guards: the incident must be real + in the caller's tenant; the recommended action
// must resolve to an ENABLED catalog action_key (fail-closed — unknown action or unwired validator → invalid); fields
// are bounded. Audited.
func (s *Service) CreateProposal(ctx context.Context, p auth.Principal, in ProposalInput) (*Proposal, error) {
	action := strings.ToLower(strings.TrimSpace(in.RecommendedAction))
	if action == "" {
		return nil, httpx.ErrBadRequest("recommended_action is required")
	}
	if in.IncidentRef == uuid.Nil {
		return nil, httpx.ErrBadRequest("incident_ref is required")
	}
	risk := strings.ToLower(strings.TrimSpace(in.RiskClass))
	if !validProposalRisk[risk] {
		return nil, httpx.ErrBadRequest("invalid risk_class: informational|low|medium|high|business_critical")
	}
	// The incident must be a real incident in the caller's own tenant (integrity — never persist a dangling/foreign
	// ref). incidents.Get is tenant-scoped, so a foreign/non-existent id fails here.
	if s.incidents == nil {
		return nil, httpx.ErrBadRequest("incident grounding is not available")
	}
	if _, err := s.incidents.Get(ctx, p.TenantID, in.IncidentRef); err != nil {
		return nil, httpx.ErrBadRequest("incident not found")
	}
	// recommended_action ∈ catalog (fail-closed): the AI cannot propose an action the catalog + authority model does
	// not already govern. No validator wired → reject (a misconfigured deploy must not let un-governed actions in).
	if s.actionCatalog == nil {
		return nil, httpx.ErrInternal("action catalog validator not configured")
	}
	keys, err := s.actionCatalog.ValidActionKeys(ctx, p.TenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not resolve action catalog")
	}
	if !keys[action] {
		return nil, httpx.ErrBadRequest("recommended_action is not a known catalog action")
	}

	cites := boundCitations(in.EvidenceCitations)
	prop := &Proposal{
		ID:                uuid.New(),
		IncidentRef:       in.IncidentRef,
		ProposedBy:        "ai",
		RequestedBy:       p.UserID,
		RecommendedAction: action,
		ConnectorKey:      strings.ToLower(strings.TrimSpace(in.ConnectorKey)),
		Rationale:         truncateUTF8(strings.TrimSpace(in.Rationale), maxRationaleLen),
		EvidenceCitations: cites,
		RiskClass:         risk,
		Reversible:        in.Reversible,
		ExpectedImpact:    truncateUTF8(strings.TrimSpace(in.ExpectedImpact), maxImpactLen),
		Status:            "pending",
	}
	err = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO ai_response_proposals
			   (id, incident_ref, proposed_by, requested_by, recommended_action, connector_key, rationale,
			    evidence_citations, risk_class, reversible, expected_impact, status)
			 VALUES ($1,$2,'ai',$3,$4,$5,$6,$7,$8,$9,$10,'pending')`,
			prop.ID, prop.IncidentRef, prop.RequestedBy, prop.RecommendedAction, prop.ConnectorKey, prop.Rationale,
			prop.EvidenceCitations, prop.RiskClass, prop.Reversible, prop.ExpectedImpact); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.proposal_create",
			Target: "incident:" + prop.IncidentRef.String(), Metadata: map[string]any{
				"proposal_id": prop.ID.String(), "action": prop.RecommendedAction, "risk_class": prop.RiskClass}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not create proposal")
	}
	return prop, nil
}

// boundCitations trims, drops empties, length-bounds each id, and caps the count — a proposal cannot carry an
// unbounded/huge citation list.
func boundCitations(in []string) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		out = append(out, truncateUTF8(c, maxCitationLen))
		if len(out) >= maxProposalCitations {
			break
		}
	}
	return out
}

// GetProposal returns one proposal in the caller's tenant (RLS-scoped).
func (s *Service) GetProposal(ctx context.Context, p auth.Principal, id uuid.UUID) (*Proposal, error) {
	var prop *Proposal
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		pr, e := scanProposal(tx.QueryRow(ctx, proposalSelect+` WHERE id = $1`, id))
		if e != nil {
			return e
		}
		prop = pr
		return nil
	})
	if err != nil {
		return nil, httpx.ErrNotFound("proposal not found")
	}
	return prop, nil
}

// ListProposalsByIncident returns an incident's proposals (newest first), tenant-scoped.
func (s *Service) ListProposalsByIncident(ctx context.Context, p auth.Principal, incidentID uuid.UUID) ([]Proposal, error) {
	var out []Proposal
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, proposalSelect+` WHERE incident_ref = $1 ORDER BY created_at DESC LIMIT 200`, incidentID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			pr, se := scanProposalRows(rows)
			if se != nil {
				return se
			}
			out = append(out, *pr)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list proposals")
	}
	return out, nil
}

// MarkProposalAccepted transitions a proposal pending->accepted, recording the promoting senior and the soar run that
// was created. It is the atomic double-promotion guard: the UPDATE keys on status='pending', so a proposal can be
// promoted to a run exactly once (a second concurrent accept affects zero rows → ErrConflict). Called by the accept
// usecase OUTSIDE internal/ai AFTER the run is created. This is a DATA transition — it references no execution symbol.
func (s *Service) MarkProposalAccepted(ctx context.Context, p auth.Principal, id, runID uuid.UUID) error {
	var affected int64
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE ai_response_proposals
			    SET status='accepted', accepted_by=$2, accepted_run_id=$3, decided_at=now()
			  WHERE id=$1 AND status='pending'`, id, p.UserID, runID)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		if affected == 0 {
			return nil // not pending (or not visible) — reported as conflict below, no audit
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.proposal_accept",
			Target: "proposal:" + id.String(), Metadata: map[string]any{"run_id": runID.String()}})
	})
	if err != nil {
		return httpx.ErrInternal("could not accept proposal")
	}
	if affected == 0 {
		return httpx.ErrConflict("proposal is not pending")
	}
	return nil
}

// RejectProposal transitions a proposal pending->rejected. Harmless (removes nothing, runs nothing); the creator or a
// senior may reject. Idempotent-ish: rejecting a non-pending proposal is a conflict.
func (s *Service) RejectProposal(ctx context.Context, p auth.Principal, id uuid.UUID) (*Proposal, error) {
	var affected int64
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE ai_response_proposals SET status='rejected', decided_at=now() WHERE id=$1 AND status='pending'`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		if affected == 0 {
			return nil
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.proposal_reject",
			Target: "proposal:" + id.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not reject proposal")
	}
	if affected == 0 {
		return nil, httpx.ErrConflict("proposal is not pending")
	}
	return s.GetProposal(ctx, p, id)
}

const proposalSelect = `SELECT id, incident_ref, proposed_by, requested_by, recommended_action, connector_key,
	rationale, evidence_citations, risk_class, reversible, expected_impact, status, accepted_by, accepted_run_id
	FROM ai_response_proposals`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanProposal(row rowScanner) (*Proposal, error) { return scanProposalRows(row) }

func scanProposalRows(row rowScanner) (*Proposal, error) {
	var pr Proposal
	if err := row.Scan(&pr.ID, &pr.IncidentRef, &pr.ProposedBy, &pr.RequestedBy, &pr.RecommendedAction,
		&pr.ConnectorKey, &pr.Rationale, &pr.EvidenceCitations, &pr.RiskClass, &pr.Reversible, &pr.ExpectedImpact,
		&pr.Status, &pr.AcceptedBy, &pr.AcceptedRunID); err != nil {
		return nil, err
	}
	return &pr, nil
}
