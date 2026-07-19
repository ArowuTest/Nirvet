package investigation

// Investigation notebooks (§6.9 slice B, UI-depth Bucket B / B2). A private, persisted analyst working surface:
// a titled notebook of ordered cells (a markdown note, or a saved hunt-query text). Notebooks are private to the
// creating analyst within their tenant (RLS + user_id). A 'query' cell only STORES text — it is never executed
// here; execution stays the allow-list-compiled RunHunt path. Every mutation is audited.

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
	maxCellContentLen = 20000 // per-cell content cap (safety bound)
	maxCellsPerBook   = 200   // cell-count cap per notebook (safety bound)
)

// Notebook is a private investigation notebook.
type Notebook struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Title       string     `json:"title"`
	IncidentRef *uuid.UUID `json:"incident_ref,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Cell is one ordered cell within a notebook.
type Cell struct {
	ID        uuid.UUID `json:"id"`
	Position  int       `json:"position"`
	Kind      string    `json:"kind"` // note | query
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateNotebook creates a private notebook for the caller.
func (r *Repository) CreateNotebook(ctx context.Context, p auth.Principal, title string, incidentRef *uuid.UUID) (*Notebook, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Untitled investigation"
	}
	if len(title) > 200 {
		return nil, httpx.ErrBadRequest("title too long")
	}
	nb := &Notebook{ID: uuid.New(), UserID: p.UserID, Title: title, IncidentRef: incidentRef}
	err := r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO investigation_notebooks (id, user_id, title, incident_ref)
			 VALUES ($1,$2,$3,$4) RETURNING created_at, updated_at`,
			nb.ID, nb.UserID, nb.Title, nb.IncidentRef).Scan(&nb.CreatedAt, &nb.UpdatedAt); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "investigation.notebook_create", Target: "notebook:" + nb.ID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not create notebook")
	}
	return nb, nil
}

// ListNotebooks returns the caller's own notebooks, most-recently-updated first.
func (r *Repository) ListNotebooks(ctx context.Context, p auth.Principal) ([]Notebook, error) {
	var out []Notebook
	err := r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, user_id, title, incident_ref, created_at, updated_at
			   FROM investigation_notebooks WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 200`, p.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Notebook
			if err := rows.Scan(&n.ID, &n.UserID, &n.Title, &n.IncidentRef, &n.CreatedAt, &n.UpdatedAt); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list notebooks")
	}
	return out, nil
}

// ownedNotebook loads a notebook the caller owns (RLS scopes tenant; user_id scopes ownership → not-found for a
// peer or another tenant).
func ownedNotebook(ctx context.Context, tx pgx.Tx, p auth.Principal, id uuid.UUID) (*Notebook, error) {
	var n Notebook
	err := tx.QueryRow(ctx,
		`SELECT id, user_id, title, incident_ref, created_at, updated_at
		   FROM investigation_notebooks WHERE id = $1 AND user_id = $2`, id, p.UserID).
		Scan(&n.ID, &n.UserID, &n.Title, &n.IncidentRef, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return nil, httpx.ErrNotFound("notebook not found")
	}
	return &n, nil
}

// GetNotebook returns a notebook the caller owns plus its cells in position order.
func (r *Repository) GetNotebook(ctx context.Context, p auth.Principal, id uuid.UUID) (*Notebook, []Cell, error) {
	var nb *Notebook
	var cells []Cell
	err := r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		n, err := ownedNotebook(ctx, tx, p, id)
		if err != nil {
			return err
		}
		nb = n
		cs, err := listCells(ctx, tx, id)
		if err != nil {
			return err
		}
		cells = cs
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return nb, cells, nil
}

func listCells(ctx context.Context, tx pgx.Tx, notebookID uuid.UUID) ([]Cell, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, position, kind, content, created_at, updated_at FROM investigation_notebook_cells
		   WHERE notebook_id = $1 ORDER BY position ASC, created_at ASC`, notebookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cell
	for rows.Next() {
		var c Cell
		if err := rows.Scan(&c.ID, &c.Position, &c.Kind, &c.Content, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddCell appends a cell (note|query) to a notebook the caller owns.
func (r *Repository) AddCell(ctx context.Context, p auth.Principal, notebookID uuid.UUID, kind, content string) (*Cell, error) {
	if kind != "note" && kind != "query" {
		return nil, httpx.ErrBadRequest("kind must be note or query")
	}
	if len(content) > maxCellContentLen {
		return nil, httpx.ErrBadRequest("cell content too long")
	}
	c := &Cell{ID: uuid.New(), Kind: kind, Content: content}
	err := r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := ownedNotebook(ctx, tx, p, notebookID); err != nil {
			return err
		}
		// Serialise position allocation on this notebook. `position` is assigned max()+1, so two concurrent
		// AddCell calls could both read the same max and insert the SAME position — colliding cells with a
		// corrupted order. Locking the notebook row makes the read-then-insert atomic per notebook. (A
		// UNIQUE(notebook_id, position) is NOT usable here: MoveCell swaps two positions with two UPDATEs, which
		// would transiently violate it mid-swap without deferred constraints.)
		if _, err := tx.Exec(ctx, `SELECT 1 FROM investigation_notebooks WHERE id = $1 FOR UPDATE`, notebookID); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM investigation_notebook_cells WHERE notebook_id = $1`, notebookID).Scan(&count); err != nil {
			return err
		}
		if count >= maxCellsPerBook {
			return httpx.ErrBadRequest("notebook has reached its cell limit")
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO investigation_notebook_cells (notebook_id, position, kind, content)
			 VALUES ($1, COALESCE((SELECT max(position)+1 FROM investigation_notebook_cells WHERE notebook_id=$1), 0), $2, $3)
			 RETURNING id, position, created_at, updated_at`,
			notebookID, kind, content).Scan(&c.ID, &c.Position, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE investigation_notebooks SET updated_at = now() WHERE id = $1`, notebookID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "investigation.notebook_cell_add", Target: "notebook:" + notebookID.String()})
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateCell edits a cell's content in a notebook the caller owns.
func (r *Repository) UpdateCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID, content string) error {
	if len(content) > maxCellContentLen {
		return httpx.ErrBadRequest("cell content too long")
	}
	return r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := ownedNotebook(ctx, tx, p, notebookID); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx,
			`UPDATE investigation_notebook_cells SET content = $3, updated_at = now()
			   WHERE id = $2 AND notebook_id = $1`, notebookID, cellID, content)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return httpx.ErrNotFound("cell not found")
		}
		_, _ = tx.Exec(ctx, `UPDATE investigation_notebooks SET updated_at = now() WHERE id = $1`, notebookID)
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "investigation.notebook_cell_update", Target: "notebook:" + notebookID.String()})
	})
}

// DeleteCell removes a cell from a notebook the caller owns.
func (r *Repository) DeleteCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID) error {
	return r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := ownedNotebook(ctx, tx, p, notebookID); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `DELETE FROM investigation_notebook_cells WHERE id = $2 AND notebook_id = $1`, notebookID, cellID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return httpx.ErrNotFound("cell not found")
		}
		_, _ = tx.Exec(ctx, `UPDATE investigation_notebooks SET updated_at = now() WHERE id = $1`, notebookID)
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "investigation.notebook_cell_delete", Target: "notebook:" + notebookID.String()})
	})
}

// MoveCell swaps a cell with its neighbour in the given direction ("up" | "down") within a notebook the caller
// owns — a simple, honest reorder.
func (r *Repository) MoveCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID, dir string) error {
	if dir != "up" && dir != "down" {
		return httpx.ErrBadRequest("dir must be up or down")
	}
	return r.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := ownedNotebook(ctx, tx, p, notebookID); err != nil {
			return err
		}
		// Serialise position mutation on this notebook — SAME lock AddCell takes. The read-two-positions /
		// swap-two-UPDATEs below is a read-then-write on `position`; without this lock a concurrent AddCell
		// (max()+1) or MoveCell could interleave and corrupt the ordering (duplicate/gapped positions).
		if _, err := tx.Exec(ctx, `SELECT 1 FROM investigation_notebooks WHERE id = $1 FOR UPDATE`, notebookID); err != nil {
			return err
		}
		var pos int
		if err := tx.QueryRow(ctx, `SELECT position FROM investigation_notebook_cells WHERE id = $2 AND notebook_id = $1`, notebookID, cellID).Scan(&pos); err != nil {
			return httpx.ErrNotFound("cell not found")
		}
		cmp := "<"
		order := "DESC"
		if dir == "down" {
			cmp, order = ">", "ASC"
		}
		var neighID uuid.UUID
		var neighPos int
		err := tx.QueryRow(ctx,
			`SELECT id, position FROM investigation_notebook_cells
			   WHERE notebook_id = $1 AND position `+cmp+` $2 ORDER BY position `+order+` LIMIT 1`,
			notebookID, pos).Scan(&neighID, &neighPos)
		if err != nil {
			return nil // already at the edge — no-op
		}
		if _, err := tx.Exec(ctx, `UPDATE investigation_notebook_cells SET position = $2 WHERE id = $1`, cellID, neighPos); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE investigation_notebook_cells SET position = $2 WHERE id = $1`, neighID, pos); err != nil {
			return err
		}
		_, _ = tx.Exec(ctx, `UPDATE investigation_notebooks SET updated_at = now() WHERE id = $1`, notebookID)
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "investigation.notebook_cell_move", Target: "notebook:" + notebookID.String()})
	})
}

// --- Service passthroughs (thin — the notebook logic + audit live on the repo tx) ---

func (s *Service) CreateNotebook(ctx context.Context, p auth.Principal, title string, ref *uuid.UUID) (*Notebook, error) {
	return s.repo.CreateNotebook(ctx, p, title, ref)
}
func (s *Service) ListNotebooks(ctx context.Context, p auth.Principal) ([]Notebook, error) {
	return s.repo.ListNotebooks(ctx, p)
}
func (s *Service) GetNotebook(ctx context.Context, p auth.Principal, id uuid.UUID) (*Notebook, []Cell, error) {
	return s.repo.GetNotebook(ctx, p, id)
}
func (s *Service) AddCell(ctx context.Context, p auth.Principal, notebookID uuid.UUID, kind, content string) (*Cell, error) {
	return s.repo.AddCell(ctx, p, notebookID, kind, content)
}
func (s *Service) UpdateCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID, content string) error {
	return s.repo.UpdateCell(ctx, p, notebookID, cellID, content)
}
func (s *Service) DeleteCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID) error {
	return s.repo.DeleteCell(ctx, p, notebookID, cellID)
}
func (s *Service) MoveCell(ctx context.Context, p auth.Principal, notebookID, cellID uuid.UUID, dir string) error {
	return s.repo.MoveCell(ctx, p, notebookID, cellID, dir)
}
