package incident

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// hasControlChar reports whether s contains an ASCII control character (used to reject unsafe filenames).
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// BlobPutter stores an evidence blob for a tenant and returns its URI. Narrow interface so incident does
// not depend on the blobstore package (implemented by blobstore.Store).
type BlobPutter interface {
	Put(ctx context.Context, tenantID uuid.UUID, key string, data []byte) (string, error)
}

// WithBlobStore wires the evidence blob store used for attachment chain-of-custody (CASE-008).
func (s *Service) WithBlobStore(b BlobPutter) *Service { s.blobs = b; return s }

// ── Repository: attachments (CASE-008) ──────────────────────────────────────────────────────────────

func (r *Repository) insertAttachment(ctx context.Context, tenantID uuid.UUID, a *Attachment) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO incident_attachments (id, tenant_id, incident_id, filename, content_type, size_bytes, sha256, blob_uri, note, uploaded_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING uploaded_at`,
			a.ID, tenantID, a.IncidentID, a.Filename, a.ContentType, a.SizeBytes, a.SHA256, a.BlobURI, a.Note, a.UploadedBy,
		).Scan(&a.UploadedAt)
	})
}

func (r *Repository) listAttachments(ctx context.Context, tenantID, incidentID uuid.UUID) ([]Attachment, error) {
	var out []Attachment
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, incident_id, filename, content_type, size_bytes, sha256, blob_uri, note, uploaded_by, uploaded_at
			   FROM incident_attachments WHERE incident_id=$1 ORDER BY uploaded_at ASC`, incidentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Attachment
			if err := rows.Scan(&a.ID, &a.IncidentID, &a.Filename, &a.ContentType, &a.SizeBytes,
				&a.SHA256, &a.BlobURI, &a.Note, &a.UploadedBy, &a.UploadedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ── Repository: knowledge base (CASE-010) ───────────────────────────────────────────────────────────

func (r *Repository) insertArticle(ctx context.Context, tenantID uuid.UUID, a *KBArticle, createdBy uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO knowledge_articles (id, tenant_id, title, body, url, category, tags, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			a.ID, tenantID, a.Title, a.Body, a.URL, a.Category, a.Tags, createdBy,
		).Scan(&a.CreatedAt)
	})
}

func (r *Repository) listArticles(ctx context.Context, tenantID uuid.UUID) ([]KBArticle, error) {
	return r.scanArticles(ctx, tenantID,
		`SELECT id, tenant_id, title, body, url, category, tags, created_at
		   FROM knowledge_articles ORDER BY title`, nil)
}

func (r *Repository) listLinkedArticles(ctx context.Context, tenantID, incidentID uuid.UUID) ([]KBArticle, error) {
	return r.scanArticles(ctx, tenantID,
		`SELECT a.id, a.tenant_id, a.title, a.body, a.url, a.category, a.tags, a.created_at
		   FROM knowledge_articles a
		   JOIN incident_kb_links l ON l.article_id = a.id
		  WHERE l.incident_id = $1 ORDER BY a.title`, []any{incidentID})
}

func (r *Repository) scanArticles(ctx context.Context, tenantID uuid.UUID, q string, args []any) ([]KBArticle, error) {
	var out []KBArticle
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a KBArticle
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Title, &a.Body, &a.URL, &a.Category, &a.Tags, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// articleVisible reports whether an article (global or own) is visible to the tenant — used to reject
// linking an article the tenant cannot see.
func (r *Repository) articleVisible(ctx context.Context, tenantID, articleID uuid.UUID) (bool, error) {
	var n int
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM knowledge_articles WHERE id=$1`, articleID).Scan(&n)
	})
	return n > 0, err
}

// linkArticle links an article to an incident and records it on the timeline (idempotent via UNIQUE).
func (r *Repository) linkArticle(ctx context.Context, tenantID, incidentID, articleID uuid.UUID, linkedBy uuid.UUID, entry *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_kb_links (tenant_id, incident_id, article_id, linked_by)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id, incident_id, article_id) DO NOTHING`,
			tenantID, incidentID, articleID, linkedBy); err != nil {
			return err
		}
		return r.AddTimelineTx(ctx, tx, entry)
	})
}

func (r *Repository) unlinkArticle(ctx context.Context, tenantID, incidentID, articleID uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM incident_kb_links WHERE incident_id=$1 AND article_id=$2`, incidentID, articleID)
		return err
	})
}

// ── Service: attachments ────────────────────────────────────────────────────────────────────────────

// RegisterAttachment stores an evidence file for an incident with chain-of-custody: the bytes go to the
// blob store, and the SHA256 digest is recorded so a later retrieval can be verified (CASE-008).
func (s *Service) RegisterAttachment(ctx context.Context, p auth.Principal, incidentID uuid.UUID, filename, contentType string, data []byte, note string) (*Attachment, error) {
	if s.blobs == nil {
		return nil, httpx.ErrInternal("attachment store not configured")
	}
	if filename == "" {
		return nil, httpx.ErrBadRequest("filename is required")
	}
	// Round-5 observation: reject a filename with path separators or control chars (path-traversal /
	// stored-XSS when a UI renders it verbatim), and cap the length.
	if len(filename) > 255 || strings.ContainsAny(filename, "/\\") || hasControlChar(filename) {
		return nil, httpx.ErrBadRequest("filename contains illegal characters or is too long")
	}
	if len(data) == 0 {
		return nil, httpx.ErrBadRequest("empty attachment")
	}
	if _, err := s.repo.Get(ctx, p.TenantID, incidentID); err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	id := uuid.New()
	key := "attachments/" + incidentID.String() + "/" + id.String()
	uri, err := s.blobs.Put(ctx, p.TenantID, key, data)
	if err != nil {
		return nil, httpx.ErrInternal("could not store attachment")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	a := &Attachment{ID: id, IncidentID: incidentID, Filename: filename, ContentType: contentType,
		SizeBytes: int64(len(data)), SHA256: digest, BlobURI: uri, Note: note, UploadedBy: &p.UserID}
	if err := s.repo.insertAttachment(ctx, p.TenantID, a); err != nil {
		return nil, httpx.ErrInternal("could not record attachment")
	}
	// Chain-of-custody entry on the timeline: filename + digest, marked as evidence.
	_ = s.repo.AddNote(ctx, p.TenantID, &TimelineEntry{ID: uuid.New(), IncidentID: incidentID, Author: p.Email,
		Kind: "evidence", Note: "Attachment added: " + filename + " (sha256 " + digest[:16] + "…)"})
	return a, nil
}

// ListAttachments returns an incident's attachments (metadata + custody digest).
func (s *Service) ListAttachments(ctx context.Context, tenantID, incidentID uuid.UUID) ([]Attachment, error) {
	return s.repo.listAttachments(ctx, tenantID, incidentID)
}

// ── Service: knowledge base ─────────────────────────────────────────────────────────────────────────

// ArticleInput creates a tenant knowledge-base article.
type ArticleInput struct {
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	URL      string   `json:"url"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
}

// CreateArticle adds a tenant-owned knowledge-base article (CASE-010).
func (s *Service) CreateArticle(ctx context.Context, p auth.Principal, in ArticleInput) (*KBArticle, error) {
	if in.Title == "" {
		return nil, httpx.ErrBadRequest("title is required")
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	tid := p.TenantID
	a := &KBArticle{ID: uuid.New(), TenantID: &tid, Title: in.Title, Body: in.Body, URL: in.URL, Category: in.Category, Tags: in.Tags}
	if err := s.repo.insertArticle(ctx, p.TenantID, a, p.UserID); err != nil {
		return nil, httpx.ErrInternal("could not create article")
	}
	return a, nil
}

// ListArticles returns global + tenant knowledge-base articles.
func (s *Service) ListArticles(ctx context.Context, tenantID uuid.UUID) ([]KBArticle, error) {
	return s.repo.listArticles(ctx, tenantID)
}

// LinkArticle links a visible article to an incident (CASE-010).
func (s *Service) LinkArticle(ctx context.Context, p auth.Principal, incidentID, articleID uuid.UUID) error {
	if _, err := s.repo.Get(ctx, p.TenantID, incidentID); err != nil {
		return httpx.ErrNotFound("incident not found")
	}
	ok, err := s.repo.articleVisible(ctx, p.TenantID, articleID)
	if err != nil {
		return httpx.ErrInternal("could not validate article")
	}
	if !ok {
		return httpx.ErrBadRequest("article not found")
	}
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: incidentID, Author: p.Email, Kind: "action", Note: "Knowledge article linked: " + articleID.String()}
	if err := s.repo.linkArticle(ctx, p.TenantID, incidentID, articleID, p.UserID, entry); err != nil {
		return httpx.ErrInternal("could not link article")
	}
	return nil
}

// UnlinkArticle removes an article link from an incident.
func (s *Service) UnlinkArticle(ctx context.Context, p auth.Principal, incidentID, articleID uuid.UUID) error {
	if err := s.repo.unlinkArticle(ctx, p.TenantID, incidentID, articleID); err != nil {
		return httpx.ErrInternal("could not unlink article")
	}
	return nil
}

// LinkedArticles returns the knowledge articles linked to an incident.
func (s *Service) LinkedArticles(ctx context.Context, tenantID, incidentID uuid.UUID) ([]KBArticle, error) {
	return s.repo.listLinkedArticles(ctx, tenantID, incidentID)
}
