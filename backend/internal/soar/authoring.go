package soar

// LAUNCH #4 (#187) slice A — playbook authoring. Tenants author their own containment playbooks through the API.
// A playbook drives real isolate/disable actions, so authoring is a privileged control-plane action gated to a
// senior role floor (soc_manager+, the same seniority that approves destructive runs). Author-time validation
// moves the run-path's fail-closed catalog check LEFT: an author gets a 400 for an unknown action rather than a
// silently-un-runnable step.
//
// REVIEWER CONDITION 1 (author-`risk` trap): the authored step schema carries a `risk` field, but the run path
// derives risk from the admin action catalog (service.go:217 — author `requires_approval` is ANDed, tighten-only;
// risk is `act.RiskClass`). To ensure a stored author-authoritative risk can never drift into an approval bypass
// after a future refactor, authoring OVERWRITES each step's risk from the catalog at author time, making it a
// display-only mirror. `requires_approval` is kept as the safe tighten-only ratchet.

import (
	"context"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

const (
	maxPlaybookSteps = 50
	maxNameLen       = 200
	maxDescLen       = 2000
	maxStepNameLen   = 200
)

// PlaybookInput is the authoring payload (create/update). tenant_id/enabled/version are server-controlled and
// never taken from the body.
type PlaybookInput struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	TriggerCategory string `json:"trigger_category"`
	Steps           []Step `json:"steps"`
}

// requireAuthor enforces the authoring role floor defensively in the service (defense-in-depth behind the route
// middleware): only soc_manager+ may author/alter a containment playbook. Authoring and approving are separate
// axes — a soc_manager who authors a playbook still cannot self-approve its destructive run (run approval keeps
// four-eyes + catalog-governed risk), so this floor does not create a self-approval path.
func requireAuthor(p auth.Principal) error {
	if auth.RoleRank(p.Role) < auth.RoleRank(auth.RoleSOCManager) {
		return httpx.ErrForbidden("authoring a playbook requires soc_manager or higher")
	}
	return nil
}

// validateAndNormalizeSteps checks the authored steps and returns a normalized copy: every action MUST resolve to
// a catalog action_key (else 400 — no silently-un-runnable step), each step's risk is OVERWRITTEN from the catalog
// (condition 1: display-only, can never drift), and the connector_key is filled from the catalog when the author
// left it blank (mirrors the run path). requires_approval is preserved (tighten-only). Bounds are enforced.
func (s *Service) validateAndNormalizeSteps(ctx context.Context, tenantID uuid.UUID, steps []Step) ([]Step, error) {
	if len(steps) == 0 {
		return nil, httpx.ErrBadRequest("a playbook needs at least one step")
	}
	if len(steps) > maxPlaybookSteps {
		return nil, httpx.ErrBadRequest("too many steps (max 50)")
	}
	// Pass 1: resolve every action (catalog-govern risk + validate existence), and learn whether the playbook
	// contains ANY connector step. A single connector step routes the WHOLE run through the two-phase supervised
	// path (supervisedNeeded), which does NOT evaluate conditions — so an inline-step condition in such a playbook
	// would be SILENTLY IGNORED at run time. A silently-dropped gating condition on a destructive action is an
	// unintended-containment footgun, strictly worse than none. So the fail-closed boundary (reviewer must-add)
	// is: NO conditions in any playbook that contains a connector action. Supervised-step conditions are #181.
	out := make([]Step, 0, len(steps))
	acts := make([]ActionCatalog, len(steps))
	seenName := map[string]bool{}
	hasConnector := false
	for i := range steps {
		steps[i].Name = strings.TrimSpace(steps[i].Name)
		if steps[i].Name == "" || len(steps[i].Name) > maxStepNameLen {
			return nil, httpx.ErrBadRequest("each step needs a name (<=200 chars)")
		}
		if seenName[steps[i].Name] {
			return nil, httpx.ErrBadRequest("duplicate step name '" + steps[i].Name + "' — step names must be unique (conditions reference them)")
		}
		seenName[steps[i].Name] = true
		steps[i].Action = strings.TrimSpace(steps[i].Action)
		act, found := s.repo.resolveAction(ctx, tenantID, steps[i].Action)
		if !found {
			return nil, httpx.ErrBadRequest("unknown action '" + steps[i].Action + "' — not in the SOAR action catalog")
		}
		acts[i] = act
		if act.Executor == ExecutorConnector {
			hasConnector = true
		}
	}

	// Pass 2: normalize + validate control-flow against the fail-closed boundary.
	priorNames := map[string]bool{}
	for i := range steps {
		st := steps[i]
		act := acts[i]
		// Condition 1: risk is ALWAYS catalog-derived, never author-authoritative. Overwrite to a display mirror.
		st.Risk = act.RiskClass
		if st.ConnectorKey == "" {
			st.ConnectorKey = act.ConnectorKey
		}
		if st.Condition != nil {
			if hasConnector {
				return nil, httpx.ErrBadRequest("conditions are not supported in a playbook that contains a connector action (#181): step '" + st.Name + "'")
			}
			c := st.Condition
			c.WhenStep = strings.TrimSpace(c.WhenStep)
			c.EqualsStatus = strings.TrimSpace(c.EqualsStatus)
			if c.WhenStep == "" || c.EqualsStatus == "" {
				return nil, httpx.ErrBadRequest("a condition needs when_step + equals_status: step '" + st.Name + "'")
			}
			if !priorNames[c.WhenStep] {
				return nil, httpx.ErrBadRequest("condition when_step '" + c.WhenStep + "' must name a PRIOR step in this playbook")
			}
		}
		// requires_approval stays as authored — it can only ADD approval friction (tighten-only ratchet); the run
		// path ANDs it with the catalog-governed gate, so it can never REMOVE approval.
		priorNames[st.Name] = true
		out = append(out, st)
	}
	return out, nil
}

func validateMeta(in PlaybookInput) error {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > maxNameLen {
		return httpx.ErrBadRequest("playbook name is required (<=200 chars)")
	}
	if len(in.Description) > maxDescLen {
		return httpx.ErrBadRequest("description too long (<=2000 chars)")
	}
	return nil
}

// CreatePlaybook authors a new tenant-owned playbook (soc_manager+). Steps are validated + normalized; risk is
// catalog-derived. Snapshots v1 + audits, atomically.
func (s *Service) CreatePlaybook(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in PlaybookInput) (*Playbook, error) {
	if err := requireAuthor(p); err != nil {
		return nil, err
	}
	if err := validateMeta(in); err != nil {
		return nil, err
	}
	steps, err := s.validateAndNormalizeSteps(ctx, tenantID, in.Steps)
	if err != nil {
		return nil, err
	}
	tc := strings.TrimSpace(in.TriggerCategory)
	if tc == "" {
		tc = "*"
	}
	pb := &Playbook{
		ID: uuid.New(), TenantID: &tenantID, Name: strings.TrimSpace(in.Name), Description: in.Description,
		TriggerCategory: tc, Steps: steps, Enabled: true,
	}
	if err := s.repo.CreatePlaybookTx(ctx, tenantID, pb, p); err != nil {
		return nil, httpx.ErrInternal("could not create playbook")
	}
	return pb, nil
}

// UpdatePlaybook replaces a tenant-owned playbook's body (soc_manager+), snapshotting the prior version. Global
// playbooks (tenant_id NULL) are provider-managed and not found on this path (404), so a tenant can never edit
// shipped content.
func (s *Service) UpdatePlaybook(ctx context.Context, p auth.Principal, tenantID, id uuid.UUID, in PlaybookInput) (*Playbook, error) {
	if err := requireAuthor(p); err != nil {
		return nil, err
	}
	if err := validateMeta(in); err != nil {
		return nil, err
	}
	steps, err := s.validateAndNormalizeSteps(ctx, tenantID, in.Steps)
	if err != nil {
		return nil, err
	}
	tc := strings.TrimSpace(in.TriggerCategory)
	if tc == "" {
		tc = "*"
	}
	pb := &Playbook{ID: id, TenantID: &tenantID, Name: strings.TrimSpace(in.Name), Description: in.Description, TriggerCategory: tc, Steps: steps, Enabled: true}
	found, err := s.repo.UpdatePlaybookTx(ctx, tenantID, pb, p)
	if err != nil {
		return nil, httpx.ErrInternal("could not update playbook")
	}
	if !found {
		return nil, httpx.ErrNotFound("tenant playbook not found")
	}
	return pb, nil
}

// SetPlaybookEnabled enables/disables a tenant-owned playbook (soc_manager+). A disabled playbook cannot be run.
func (s *Service) SetPlaybookEnabled(ctx context.Context, p auth.Principal, tenantID, id uuid.UUID, enabled bool) error {
	if err := requireAuthor(p); err != nil {
		return err
	}
	found, err := s.repo.SetPlaybookEnabledTx(ctx, tenantID, id, enabled, p)
	if err != nil {
		return httpx.ErrInternal("could not update playbook")
	}
	if !found {
		return httpx.ErrNotFound("tenant playbook not found")
	}
	return nil
}
