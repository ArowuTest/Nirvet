package incident

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ── Repository: tasks (CASE-005) ────────────────────────────────────────────────────────────────────

func (r *Repository) insertTask(ctx context.Context, tenantID uuid.UUID, t *Task) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO incident_tasks (id, tenant_id, incident_id, title, description, assignee_id, status, due_at, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at`,
			t.ID, tenantID, t.IncidentID, t.Title, t.Description, t.AssigneeID, t.Status, t.DueAt, t.CreatedBy,
		).Scan(&t.CreatedAt)
	})
}

func (r *Repository) listTasks(ctx context.Context, tenantID, incidentID uuid.UUID) ([]Task, error) {
	var out []Task
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, incident_id, title, description, assignee_id, status, due_at, created_by, created_at, completed_at
			   FROM incident_tasks WHERE incident_id=$1 ORDER BY created_at ASC`, incidentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Task
			if err := rows.Scan(&t.ID, &t.IncidentID, &t.Title, &t.Description, &t.AssigneeID,
				&t.Status, &t.DueAt, &t.CreatedBy, &t.CreatedAt, &t.CompletedAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// updateTaskStatus sets a task's status (and completed_at when moving to done), returning the task's
// incident id so the service can record it on the incident timeline. applied=false if the task is not
// in this tenant.
func (r *Repository) updateTaskStatus(ctx context.Context, tenantID, taskID uuid.UUID, status string) (incidentID uuid.UUID, applied bool, err error) {
	err = r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var completed any
		if status == TaskDone {
			completed = time.Now()
		}
		return tx.QueryRow(ctx,
			`UPDATE incident_tasks
			    SET status=$2,
			        completed_at = CASE WHEN $2='done' THEN COALESCE(completed_at, $3::timestamptz) ELSE NULL END
			  WHERE id=$1 RETURNING incident_id`, taskID, status, completed).Scan(&incidentID)
	})
	if err == pgx.ErrNoRows {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return incidentID, true, nil
}

// ── Repository: categories (CASE-007) ───────────────────────────────────────────────────────────────

func (r *Repository) listCategories(ctx context.Context, tenantID uuid.UUID) ([]Category, error) {
	var out []Category
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, key, name, description, default_severity, enabled
			   FROM incident_categories WHERE enabled = true ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Category
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Key, &c.Name, &c.Description, &c.DefaultSeverity, &c.Enabled); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) categoryExists(ctx context.Context, tenantID uuid.UUID, key string) (bool, error) {
	var n int
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM incident_categories WHERE key=$1 AND enabled=true`, key).Scan(&n)
	})
	return n > 0, err
}

// setCategory updates an incident's category and records a timeline entry atomically. applied=false if
// the incident is not in this tenant.
func (r *Repository) setCategory(ctx context.Context, tenantID, incidentID uuid.UUID, key string, entry *TimelineEntry) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE incidents SET category=$2 WHERE id=$1`, incidentID, key)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil
		}
		applied = true
		return r.AddTimelineTx(ctx, tx, entry)
	})
	return applied, err
}

// ── Repository: parent/child (CASE-006) ─────────────────────────────────────────────────────────────

// setParent sets (or clears when parentID is nil) an incident's parent within a tx that also records the
// change on both incidents' timelines. applied=false if the child is not in this tenant.
func (r *Repository) setParent(ctx context.Context, tenantID, childID uuid.UUID, parentID *uuid.UUID, childEntry, parentEntry *TimelineEntry) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE incidents SET parent_id=$2 WHERE id=$1`, childID, parentID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil
		}
		applied = true
		if err := r.AddTimelineTx(ctx, tx, childEntry); err != nil {
			return err
		}
		if parentEntry != nil {
			return r.AddTimelineTx(ctx, tx, parentEntry)
		}
		return nil
	})
	return applied, err
}

// setMajor flags/unflags an incident as a major (umbrella) incident. applied=false if not in this tenant.
func (r *Repository) setMajor(ctx context.Context, tenantID, id uuid.UUID, isMajor bool, entry *TimelineEntry) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE incidents SET is_major=$2 WHERE id=$1`, id, isMajor)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil
		}
		applied = true
		return r.AddTimelineTx(ctx, tx, entry)
	})
	return applied, err
}

// ancestorsContains walks the parent chain up from startID and reports whether targetID appears in it.
// Used to reject a parent link that would create a cycle. Bounded to avoid an infinite loop on any
// pre-existing bad data.
func (r *Repository) ancestorsContains(ctx context.Context, tenantID, startID, targetID uuid.UUID) (bool, error) {
	found := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur := startID
		for i := 0; i < 64; i++ {
			var parent *uuid.UUID
			e := tx.QueryRow(ctx, `SELECT parent_id FROM incidents WHERE id=$1`, cur).Scan(&parent)
			if e == pgx.ErrNoRows || parent == nil {
				return nil
			}
			if e != nil {
				return e
			}
			if *parent == targetID {
				found = true
				return nil
			}
			cur = *parent
		}
		return nil
	})
	return found, err
}

// ListChildren returns the child incidents of a parent (SLA-breach status NOT computed here; caller
// enriches if needed).
func (r *Repository) ListChildren(ctx context.Context, tenantID, parentID uuid.UUID) ([]Incident, error) {
	var out []Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at,
			        acknowledged_at, ack_due_at, resolve_due_at, parent_id, is_major
			   FROM incidents WHERE parent_id=$1 ORDER BY created_at DESC`, parentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Incident
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category, &i.Stage, &i.OwnerID,
				&i.CreatedAt, &i.ClosedAt, &i.AcknowledgedAt, &i.AckDueAt, &i.ResolveDueAt, &i.ParentID, &i.IsMajor); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// ── Service: tasks ──────────────────────────────────────────────────────────────────────────────────

// TaskInput creates a task on an incident.
type TaskInput struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	AssigneeID  *uuid.UUID `json:"assignee_id"`
	DueAt       *time.Time `json:"due_at"`
}

// CreateTask adds an investigation task to an incident (CASE-005). The incident must be in the tenant;
// an assignee, if given, must be a user in the tenant.
func (s *Service) CreateTask(ctx context.Context, p auth.Principal, incidentID uuid.UUID, in TaskInput) (*Task, error) {
	if in.Title == "" {
		return nil, httpx.ErrBadRequest("task title is required")
	}
	if _, err := s.repo.Get(ctx, p.TenantID, incidentID); err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	assigneeLabel := ""
	if in.AssigneeID != nil {
		if s.assignees != nil {
			email, err := s.assignees.LookupInTenant(ctx, p.TenantID, *in.AssigneeID)
			if err != nil {
				return nil, httpx.ErrBadRequest("assignee is not a user in this tenant")
			}
			assigneeLabel = email
		} else {
			assigneeLabel = in.AssigneeID.String()
		}
	}
	t := &Task{ID: uuid.New(), IncidentID: incidentID, Title: in.Title, Description: in.Description,
		AssigneeID: in.AssigneeID, Status: TaskOpen, DueAt: in.DueAt, CreatedBy: &p.UserID}
	if err := s.repo.insertTask(ctx, p.TenantID, t); err != nil {
		return nil, httpx.ErrInternal("could not create task")
	}
	note := "Task added: " + in.Title
	if assigneeLabel != "" {
		note += " (assigned to " + assigneeLabel + ")"
	}
	_ = s.repo.AddNote(ctx, p.TenantID, &TimelineEntry{ID: uuid.New(), IncidentID: incidentID, Author: p.Email, Kind: "action", Note: note})
	return t, nil
}

// ListTasks returns an incident's tasks.
func (s *Service) ListTasks(ctx context.Context, tenantID, incidentID uuid.UUID) ([]Task, error) {
	return s.repo.listTasks(ctx, tenantID, incidentID)
}

// UpdateTaskStatus moves a task through its lifecycle and records the change on the incident timeline.
func (s *Service) UpdateTaskStatus(ctx context.Context, p auth.Principal, taskID uuid.UUID, status string) error {
	if !validTaskStatus[status] {
		return httpx.ErrBadRequest("status must be open|in_progress|done|cancelled")
	}
	incidentID, applied, err := s.repo.updateTaskStatus(ctx, p.TenantID, taskID, status)
	if err != nil {
		return httpx.ErrInternal("could not update task")
	}
	if !applied {
		return httpx.ErrNotFound("task not found")
	}
	_ = s.repo.AddNote(ctx, p.TenantID, &TimelineEntry{ID: uuid.New(), IncidentID: incidentID, Author: p.Email, Kind: "action", Note: "Task " + status})
	return nil
}

// ── Service: categories ─────────────────────────────────────────────────────────────────────────────

// ListCategories returns the configured category templates (global + tenant).
func (s *Service) ListCategories(ctx context.Context, tenantID uuid.UUID) ([]Category, error) {
	return s.repo.listCategories(ctx, tenantID)
}

// SetCategory sets an incident's category, validated against the configured set (CASE-007).
func (s *Service) SetCategory(ctx context.Context, p auth.Principal, incidentID uuid.UUID, key string) error {
	if key == "" {
		return httpx.ErrBadRequest("category key is required")
	}
	ok, err := s.repo.categoryExists(ctx, p.TenantID, key)
	if err != nil {
		return httpx.ErrInternal("could not validate category")
	}
	if !ok {
		return httpx.ErrBadRequest("unknown category")
	}
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: incidentID, Author: p.Email, Kind: "status", Note: "Category set to " + key}
	applied, err := s.repo.setCategory(ctx, p.TenantID, incidentID, key, entry)
	if err != nil {
		return httpx.ErrInternal("could not set category")
	}
	if !applied {
		return httpx.ErrNotFound("incident not found")
	}
	return nil
}

// ── Service: parent/child + major (CASE-006) ────────────────────────────────────────────────────────

// LinkParent links a child incident under a parent (umbrella) incident. Both must be in the tenant; the
// link must not create a cycle (a parent cannot be the child itself, nor a descendant of the child).
func (s *Service) LinkParent(ctx context.Context, p auth.Principal, childID, parentID uuid.UUID) error {
	if childID == parentID {
		return httpx.ErrBadRequest("an incident cannot be its own parent")
	}
	if _, err := s.repo.Get(ctx, p.TenantID, parentID); err != nil {
		return httpx.ErrBadRequest("parent incident not found in tenant")
	}
	if _, err := s.repo.Get(ctx, p.TenantID, childID); err != nil {
		return httpx.ErrNotFound("child incident not found")
	}
	// Cycle guard: setting child.parent = parent creates a cycle iff parent is already a descendant of
	// child, i.e. child appears in parent's ancestor chain.
	cycle, err := s.repo.ancestorsContains(ctx, p.TenantID, parentID, childID)
	if err != nil {
		return httpx.ErrInternal("could not validate link")
	}
	if cycle {
		return httpx.ErrBadRequest("link would create a parent/child cycle")
	}
	childEntry := &TimelineEntry{ID: uuid.New(), IncidentID: childID, Author: p.Email, Kind: "status", Note: "Linked under parent incident " + parentID.String()}
	parentEntry := &TimelineEntry{ID: uuid.New(), IncidentID: parentID, Author: p.Email, Kind: "status", Note: "Child incident " + childID.String() + " linked"}
	applied, err := s.repo.setParent(ctx, p.TenantID, childID, &parentID, childEntry, parentEntry)
	if err != nil {
		return httpx.ErrInternal("could not link incident")
	}
	if !applied {
		return httpx.ErrNotFound("child incident not found")
	}
	return nil
}

// UnlinkParent removes a child's parent link.
func (s *Service) UnlinkParent(ctx context.Context, p auth.Principal, childID uuid.UUID) error {
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: childID, Author: p.Email, Kind: "status", Note: "Unlinked from parent incident"}
	applied, err := s.repo.setParent(ctx, p.TenantID, childID, nil, entry, nil)
	if err != nil {
		return httpx.ErrInternal("could not unlink incident")
	}
	if !applied {
		return httpx.ErrNotFound("incident not found")
	}
	return nil
}

// SetMajor flags or unflags an incident as a major (umbrella) incident (CASE-006).
func (s *Service) SetMajor(ctx context.Context, p auth.Principal, id uuid.UUID, isMajor bool) error {
	verb := "unflagged as major"
	if isMajor {
		verb = "flagged as major incident"
	}
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "status", Note: "Incident " + verb}
	applied, err := s.repo.setMajor(ctx, p.TenantID, id, isMajor, entry)
	if err != nil {
		return httpx.ErrInternal("could not update incident")
	}
	if !applied {
		return httpx.ErrNotFound("incident not found")
	}
	return nil
}

// Children returns an incident's child incidents (with SLA-breach status computed).
func (s *Service) Children(ctx context.Context, tenantID, parentID uuid.UUID) ([]Incident, error) {
	kids, err := s.repo.ListChildren(ctx, tenantID, parentID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range kids {
		computeBreach(&kids[i], now)
	}
	return kids, nil
}
