package compliance

// §6.14 slice B — tenant-custom framework + control AUTHORING (COMP-002 refinements) and the audit-readiness pack.
//
// mig 0082's design intent: a sovereign customer's country-specifics (Ghana CSA 24h reporting window, the named
// regulator, Act-1038/Act-843 statute refs, a fuller control catalogue) are added as TENANT-CUSTOM data via THIS API
// — never as core migrations ("Adding a new sovereign never requires SQL or code, only data"). The DB already isolates
// it (mig 0042: global rows are read-only to tenants; INSERT/UPDATE/DELETE are WITH CHECK tenant_id=current). This
// file is the missing service that surfaces that authoring, with the guardrails that keep the assessment honest:
//   - auto_signal must be a REAL resolver (or manual / rollup) — a typo'd signal silently never resolves.
//   - a tenant refinement is ADDITIVE: it may add controls under a global framework key or under its own framework,
//     but may NOT shadow a global framework key or a global control_ref (which would double-count / mislead an auditor).
//   - nesting stays ≤2 levels (Assess's rollup is two-level and fails loud beyond it) — rejected at authoring time so a
//     tenant can never create an un-assessable framework.

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	maxFwKeyLen   = 64
	maxNameLen    = 200
	maxRefLen     = 64
	maxTitleLen   = 200
	maxDescLen    = 2000
	maxVersionLen = 32
)

// keyRe bounds a framework key to a safe slug (lower snake/dash) — it appears in URLs + joins.
var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// refRe bounds a control_ref to a safe token (the catalogues use dotted refs like RESP.2 / A.8.15 / CIS-17).
var refRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// validAutoSignal reports whether an authored auto_signal is one the engine actually honours: a registered live
// resolver, 'manual' (officer-assessed → gap until overridden), or ” (a rollup/function). Anything else is rejected
// so an author cannot create a control that silently never resolves. The `signals` registry is the single source.
func validAutoSignal(s string) bool {
	if s == "" || s == "manual" {
		return true
	}
	_, ok := signals[s]
	return ok
}

// ================= repository (authoring) =================

// globalFrameworkExists reports whether a GLOBAL (tenant_id IS NULL) framework with this key exists — a tenant may not
// create a framework that shadows a global one.
func (r *Repository) globalFrameworkExists(ctx context.Context, tenantID uuid.UUID, key string) (bool, error) {
	var exists bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM compliance_frameworks WHERE key = $1 AND tenant_id IS NULL)`, key).Scan(&exists)
	})
	return exists, err
}

// frameworkVisible reports whether a framework key is visible to the tenant (global OR own) — controls may only be
// authored under a framework the tenant can see.
func (r *Repository) frameworkVisible(ctx context.Context, tenantID uuid.UUID, key string) (bool, error) {
	var exists bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM compliance_frameworks
			   WHERE key = $1 AND (tenant_id = app_current_tenant() OR tenant_id IS NULL))`, key).Scan(&exists)
	})
	return exists, err
}

// globalControlExists reports whether a GLOBAL control with this (framework, ref) exists — a tenant refinement may not
// shadow it (that would double-count in Assess and mislead an auditor).
func (r *Repository) globalControlExists(ctx context.Context, tenantID uuid.UUID, fwKey, ref string) (bool, error) {
	var exists bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM compliance_controls
			   WHERE framework_key = $1 AND control_ref = $2 AND tenant_id IS NULL)`, fwKey, ref).Scan(&exists)
	})
	return exists, err
}

func (r *Repository) insertFramework(ctx context.Context, tenantID uuid.UUID, f Framework) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO compliance_frameworks (tenant_id, key, name, version, description, enabled)
			 VALUES (app_current_tenant(), $1,$2,$3,$4,$5) RETURNING id`,
			f.Key, f.Name, f.Version, f.Description, f.Enabled).Scan(&id)
	})
	return id, err
}

// updateOwnFramework updates a TENANT-owned framework's metadata (RLS blocks a global). Returns rows affected.
func (r *Repository) updateOwnFramework(ctx context.Context, tenantID uuid.UUID, f Framework) (int64, error) {
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE compliance_frameworks SET name=$2, version=$3, description=$4, enabled=$5
			  WHERE key=$1 AND tenant_id = app_current_tenant()`,
			f.Key, f.Name, f.Version, f.Description, f.Enabled)
		if e != nil {
			return e
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

// deleteOwnFramework removes a tenant framework and its own controls + statuses (RLS scopes each to the tenant; a
// global framework/control is never touched). Returns whether the framework existed.
func (r *Repository) deleteOwnFramework(ctx context.Context, tenantID uuid.UUID, key string) (int64, error) {
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM compliance_control_status WHERE framework_key=$1 AND tenant_id = app_current_tenant()`, key); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM compliance_controls WHERE framework_key=$1 AND tenant_id = app_current_tenant()`, key); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx, `DELETE FROM compliance_frameworks WHERE key=$1 AND tenant_id = app_current_tenant()`, key)
		if e != nil {
			return e
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

// upsertControl inserts or updates a TENANT control (RLS WITH CHECK blocks writing a global row).
func (r *Repository) upsertControl(ctx context.Context, tenantID uuid.UUID, c Control) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO compliance_controls
			   (tenant_id, framework_key, control_ref, parent_ref, title, description, weight, auto_signal, auto_config)
			 VALUES (app_current_tenant(), $1,$2,$3,$4,$5,$6,$7,'{}'::jsonb)
			 ON CONFLICT (tenant_id, framework_key, control_ref) DO UPDATE SET
			   parent_ref=EXCLUDED.parent_ref, title=EXCLUDED.title, description=EXCLUDED.description,
			   weight=EXCLUDED.weight, auto_signal=EXCLUDED.auto_signal`,
			c.FrameworkKey, c.ControlRef, c.ParentRef, c.Title, c.Description, c.Weight, c.AutoSignal)
		return e
	})
}

// deleteOwnControl removes a tenant control + its status (RLS scoped). Returns rows affected on the control.
func (r *Repository) deleteOwnControl(ctx context.Context, tenantID uuid.UUID, fwKey, ref string) (int64, error) {
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM compliance_control_status WHERE framework_key=$1 AND control_ref=$2 AND tenant_id = app_current_tenant()`, fwKey, ref); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx, `DELETE FROM compliance_controls WHERE framework_key=$1 AND control_ref=$2 AND tenant_id = app_current_tenant()`, fwKey, ref)
		if e != nil {
			return e
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

// ================= service (authoring) =================

// FrameworkInput authors a tenant-custom framework.
type FrameworkInput struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

// CreateFramework adds a NEW tenant-custom framework. The key must be a safe slug and must NOT collide with a global
// framework key (no shadowing). Audited by the mutation middleware.
func (s *Service) CreateFramework(ctx context.Context, tenantID uuid.UUID, in FrameworkInput) (*Framework, error) {
	key := strings.ToLower(strings.TrimSpace(in.Key))
	if !keyRe.MatchString(key) || len(key) > maxFwKeyLen {
		return nil, httpx.ErrBadRequest("key must be a lowercase slug (a-z0-9._-), up to 64 chars")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxNameLen {
		return nil, httpx.ErrBadRequest("name is required (<=200 chars)")
	}
	if len(in.Version) > maxVersionLen || len(in.Description) > maxDescLen {
		return nil, httpx.ErrBadRequest("version/description too long")
	}
	shadows, err := s.repo.globalFrameworkExists(ctx, tenantID, key)
	if err != nil {
		return nil, httpx.ErrInternal("could not validate framework key")
	}
	if shadows {
		return nil, httpx.ErrConflict("that key is a built-in framework; add your controls under it instead of redefining it")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	f := Framework{Key: key, Name: name, Version: strings.TrimSpace(in.Version), Description: strings.TrimSpace(in.Description), Enabled: enabled}
	id, err := s.repo.insertFramework(ctx, tenantID, f)
	if err != nil {
		// UNIQUE(tenant_id,key) → the tenant already has this framework.
		return nil, httpx.ErrConflict("a framework with that key already exists for this tenant (use PUT to update it)")
	}
	f.ID = id
	return &f, nil
}

// UpdateFramework edits an OWN framework's metadata/enabled (RLS blocks a global).
func (s *Service) UpdateFramework(ctx context.Context, tenantID uuid.UUID, key string, in FrameworkInput) (*Framework, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxNameLen {
		return nil, httpx.ErrBadRequest("name is required (<=200 chars)")
	}
	if len(in.Version) > maxVersionLen || len(in.Description) > maxDescLen {
		return nil, httpx.ErrBadRequest("version/description too long")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	f := Framework{Key: key, Name: name, Version: strings.TrimSpace(in.Version), Description: strings.TrimSpace(in.Description), Enabled: enabled}
	n, err := s.repo.updateOwnFramework(ctx, tenantID, f)
	if err != nil {
		return nil, httpx.ErrInternal("could not update framework")
	}
	if n == 0 {
		return nil, httpx.ErrNotFound("framework not found (built-in frameworks cannot be edited)")
	}
	return &f, nil
}

// DeleteFramework removes an OWN framework + its own controls/statuses (RLS scoped; a built-in is never touched).
func (s *Service) DeleteFramework(ctx context.Context, tenantID uuid.UUID, key string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	n, err := s.repo.deleteOwnFramework(ctx, tenantID, key)
	if err != nil {
		return httpx.ErrInternal("could not delete framework")
	}
	if n == 0 {
		return httpx.ErrNotFound("framework not found (built-in frameworks cannot be deleted)")
	}
	return nil
}

// ControlInput authors a tenant-custom control (a refinement under any visible framework, or under an own framework).
type ControlInput struct {
	FrameworkKey string `json:"framework_key"`
	ControlRef   string `json:"control_ref"`
	ParentRef    string `json:"parent_ref"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Weight       int    `json:"weight"`
	AutoSignal   string `json:"auto_signal"`
}

// UpsertControl adds/updates a tenant-custom control. Guardrails keep the assessment honest and assessable:
//   - the framework must be visible (global or own);
//   - control_ref must not shadow a GLOBAL control (additive refinement only);
//   - auto_signal must be a real resolver / manual / rollup;
//   - nesting stays ≤2 levels: parent_ref is ” (top-level) or an EXISTING top-level control (never a leaf).
func (s *Service) UpsertControl(ctx context.Context, tenantID uuid.UUID, in ControlInput) (*Control, error) {
	fwKey := strings.ToLower(strings.TrimSpace(in.FrameworkKey))
	ref := strings.TrimSpace(in.ControlRef)
	parent := strings.TrimSpace(in.ParentRef)
	if !keyRe.MatchString(fwKey) {
		return nil, httpx.ErrBadRequest("framework_key must be a lowercase slug")
	}
	if !refRe.MatchString(ref) || len(ref) > maxRefLen {
		return nil, httpx.ErrBadRequest("control_ref must be a token (A-Za-z0-9._-), up to 64 chars")
	}
	title := strings.TrimSpace(in.Title)
	if title == "" || len(title) > maxTitleLen {
		return nil, httpx.ErrBadRequest("title is required (<=200 chars)")
	}
	if len(in.Description) > maxDescLen {
		return nil, httpx.ErrBadRequest("description too long")
	}
	if in.Weight < 1 || in.Weight > 100 {
		return nil, httpx.ErrBadRequest("weight must be 1..100")
	}
	if !validAutoSignal(in.AutoSignal) {
		return nil, httpx.ErrBadRequest("auto_signal must be one of the platform resolvers, 'manual', or '' (rollup)")
	}
	visible, err := s.repo.frameworkVisible(ctx, tenantID, fwKey)
	if err != nil {
		return nil, httpx.ErrInternal("could not validate framework")
	}
	if !visible {
		return nil, httpx.ErrNotFound("unknown framework")
	}
	// Additive refinement only — never shadow a built-in control ref (would double-count in Assess).
	if shadow, err := s.repo.globalControlExists(ctx, tenantID, fwKey, ref); err != nil {
		return nil, httpx.ErrInternal("could not validate control")
	} else if shadow {
		return nil, httpx.ErrConflict("that control_ref is a built-in control; use a distinct ref for your refinement")
	}
	if parent != "" {
		if parent == ref {
			return nil, httpx.ErrBadRequest("a control cannot be its own parent")
		}
		// ≤2-level nesting: the parent must exist in the framework AND itself be top-level (parent_ref='').
		controls, lerr := s.repo.ListControls(ctx, tenantID, fwKey)
		if lerr != nil {
			return nil, httpx.ErrInternal("could not load framework controls")
		}
		if !isTopLevel(controls, parent) {
			return nil, httpx.ErrBadRequest("parent_ref must be an existing top-level control (nesting is limited to 2 levels)")
		}
		// Reviewer LOW-2: re-parenting an EXISTING control that already has children would create depth-3 (this
		// control becomes a child while its own children hang below it). Assess fails loud on >2 levels; reject here
		// too so a tenant can never author an un-assessable framework via an update.
		if hasChildren(controls, ref) {
			return nil, httpx.ErrBadRequest("this control already has child controls; giving it a parent would create 3-level nesting")
		}
	}
	c := Control{FrameworkKey: fwKey, ControlRef: ref, ParentRef: parent, Title: title,
		Description: strings.TrimSpace(in.Description), Weight: in.Weight, AutoSignal: in.AutoSignal}
	if err := s.repo.upsertControl(ctx, tenantID, c); err != nil {
		return nil, httpx.ErrInternal("could not save control")
	}
	return &c, nil
}

// DeleteControl removes a tenant-custom control (RLS scoped; a built-in is never touched).
func (s *Service) DeleteControl(ctx context.Context, tenantID uuid.UUID, fwKey, ref string) error {
	fwKey = strings.ToLower(strings.TrimSpace(fwKey))
	ref = strings.TrimSpace(ref)
	if fwKey == "" || ref == "" {
		return httpx.ErrBadRequest("framework and ref are required")
	}
	n, err := s.repo.deleteOwnControl(ctx, tenantID, fwKey, ref)
	if err != nil {
		return httpx.ErrInternal("could not delete control")
	}
	if n == 0 {
		return httpx.ErrNotFound("control not found (built-in controls cannot be deleted)")
	}
	return nil
}

// isTopLevel reports whether ref names a control in the set whose own parent_ref is ” (a function/top-level control).
func isTopLevel(controls []Control, ref string) bool {
	for _, c := range controls {
		if c.ControlRef == ref {
			return c.ParentRef == ""
		}
	}
	return false
}

// hasChildren reports whether any control in the set is parented on ref (i.e. ref is a top-level control with leaves).
func hasChildren(controls []Control, ref string) bool {
	for _, c := range controls {
		if c.ParentRef == ref {
			return true
		}
	}
	return false
}

// ================= audit-readiness pack (COMP-005) =================

// AuditPack is the auditor-facing artifact for a framework: the framework metadata, the full per-control assessment
// (status/score/source/note/evidence — nothing fabricated), the coverage summary, and provenance (tenant + when).
type AuditPack struct {
	Framework   Framework `json:"framework"`
	GeneratedAt time.Time `json:"generated_at"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Coverage    *Coverage `json:"coverage"`
}

// BuildAuditPack assembles the audit-readiness pack for a framework: it runs the same honest Assess() the coverage
// endpoint uses, plus the framework metadata + provenance, into one downloadable record. Read-only.
func (s *Service) BuildAuditPack(ctx context.Context, tenantID uuid.UUID, frameworkKey string) (*AuditPack, error) {
	frameworkKey = strings.TrimSpace(frameworkKey)
	if frameworkKey == "" {
		return nil, httpx.ErrBadRequest("framework is required")
	}
	fws, err := s.repo.ListFrameworks(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load frameworks")
	}
	var meta *Framework
	for i := range fws {
		if fws[i].Key == frameworkKey {
			meta = &fws[i]
			break
		}
	}
	if meta == nil {
		return nil, httpx.ErrNotFound("unknown framework")
	}
	cov, err := s.Assess(ctx, tenantID, frameworkKey)
	if err != nil {
		return nil, err
	}
	return &AuditPack{Framework: *meta, GeneratedAt: time.Now().UTC(), TenantID: tenantID, Coverage: cov}, nil
}
