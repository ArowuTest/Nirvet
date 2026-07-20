package reporting

// §6.13 #125 R-1/R-2/R-4/R-5 — the report record, generation, and session-authorized download.
//
// Security posture:
//   - Generation runs under WithTenant(tenant) with a HARD row/cell/byte ceiling enforced BEFORE serialize and store
//     (refinement #5). Report params are fixed to the session tenant — there is no scope-widening input in slice A.
//   - The artifact is stored in blobstore under an OPAQUE UUID key (refinement #4), never a tenant-name-derived path.
//   - Download is NOT a bearer capability: it is an authenticated, role-gated GET whose service reads under
//     WithTenant, so RLS confines it to the caller's own tenant (refinement #3). A leaked report id from another
//     tenant resolves to not-found; a same-tenant id still requires an authenticated provider session.
//   - Every generate / download is recorded in the append-only report_audit (REP-008).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Report is a generated report record.
type Report struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Type         string     `json:"type"`
	Format       Format     `json:"format"`
	Status       string     `json:"status"`
	ReviewStatus string     `json:"review_status"` // none | pending_review | approved | rejected (#173)
	ReviewedBy   *uuid.UUID `json:"reviewed_by,omitempty"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote   string     `json:"review_note,omitempty"`
	RowCount     int        `json:"row_count"`
	ByteSize     int        `json:"byte_size"`
	Error        string     `json:"error,omitempty"`
	CreatedBy    uuid.UUID  `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ReadyAt      *time.Time `json:"ready_at,omitempty"`
	artifactURI  string     // internal — never serialized to the client
}

// reportTypes is the code-owned set of report types slice A can generate (config-extensible later).
var reportTypes = map[string]bool{"service_review": true}

// Limits is the report cost ceiling.
type Limits struct{ MaxRows, MaxCells, MaxBytes int }

// DefaultLimits is the seeded default (used if the config row is missing/broken — fail-safe toward the bound).
func DefaultLimits() Limits {
	return Limits{MaxRows: 50000, MaxCells: 500000, MaxBytes: 25 * 1024 * 1024}
}

// ReportRepository persists report records + the audit trail.
type ReportRepository struct{ db *database.DB }

// NewReportRepository builds the repository.
func NewReportRepository(db *database.DB) *ReportRepository { return &ReportRepository{db: db} }

// Create inserts a pending report and returns its id (tenant-scoped).
func (r *ReportRepository) Create(ctx context.Context, tenantID, actorID uuid.UUID, typ string, format Format, params []byte) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO reports (tenant_id, type, format, params, status, created_by)
			 VALUES ($1,$2,$3,$4,'running',$5) RETURNING id`,
			tenantID, typ, string(format), params, actorID).Scan(&id)
	})
	return id, err
}

// MarkReady finalizes a generated report AND sets its review_status from the operator review policy in the SAME
// write (#173). The policy lookup is inline so review-required is decided in ONE place and cannot be bypassed by a
// second code path: COALESCE(..., true) makes an UNSEEDED/unknown type default to review-REQUIRED (fail-closed
// toward sign-off). report_review_policy is a global GRANT-SELECT table, so the subquery reads under WithTenant.
func (r *ReportRepository) MarkReady(ctx context.Context, tenantID, id uuid.UUID, uri string, rowCount, byteSize int) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE reports
			SET status='ready', artifact_uri=$2, row_count=$3, byte_size=$4, ready_at=now(),
			    review_status = CASE WHEN COALESCE(
			        (SELECT review_required FROM report_review_policy WHERE type = reports.type), true)
			      THEN 'pending_review' ELSE 'none' END
			WHERE id=$1`,
			id, uri, rowCount, byteSize)
		return e
	})
}

// MarkFailed records a generation failure.
func (r *ReportRepository) MarkFailed(ctx context.Context, tenantID, id uuid.UUID, msg string) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE reports SET status='failed', error=$2 WHERE id=$1`, id, msg)
		return e
	})
}

// Get reads a report record (RLS confines it to the tenant).
func (r *ReportRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Report, error) {
	var rep Report
	var format string
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, type, format, status, review_status, reviewed_by, reviewed_at, review_note,
			        artifact_uri, row_count, byte_size, error, created_by, created_at, ready_at
			   FROM reports WHERE id=$1`, id).
			Scan(&rep.ID, &rep.TenantID, &rep.Type, &format, &rep.Status,
				&rep.ReviewStatus, &rep.ReviewedBy, &rep.ReviewedAt, &rep.ReviewNote, &rep.artifactURI,
				&rep.RowCount, &rep.ByteSize, &rep.Error, &rep.CreatedBy, &rep.CreatedAt, &rep.ReadyAt)
	})
	if err == pgx.ErrNoRows {
		return nil, httpx.ErrNotFound("report not found")
	}
	if err != nil {
		return nil, err
	}
	rep.Format = Format(format)
	return &rep, nil
}

// WriteAudit records a report action (REP-008; append-only, tenant-scoped).
func (r *ReportRepository) WriteAudit(ctx context.Context, tenantID uuid.UUID, reportID *uuid.UUID, actorID uuid.UUID, action string, format Format, rowCount int) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO report_audit (tenant_id, report_id, actor_id, action, format, row_count) VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID, reportID, actorID, action, string(format), rowCount)
		return e
	})
}

// LoadLimits reads the seeded global cost ceiling; any error → the code default (fail-safe toward the bound).
func (r *ReportRepository) LoadLimits(ctx context.Context) Limits {
	var rows, cells, bytesN int
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT max_rows, max_cells, max_bytes FROM report_limits WHERE scope='global'`).
			Scan(&rows, &cells, &bytesN)
	})
	if err != nil || rows <= 0 || cells <= 0 || bytesN <= 0 {
		return DefaultLimits()
	}
	return Limits{MaxRows: rows, MaxCells: cells, MaxBytes: bytesN}
}

// ReportService generates + serves reports. It composes the content Service (which reads under WithTenant), the
// repository, and blobstore.
type ReportService struct {
	repo     *ReportRepository
	blobs    blobstore.Store
	content  *Service
	breach   BreachIncidentReader // optional #188 incident reader for regulatory breach reports (nil ⇒ unavailable)
	signer   ed25519.PrivateKey   // optional #188 Ed25519 key to sign the breach report (nil ⇒ unsigned)
	capsOnce *Limits              // optional override of the DB-loaded caps (config/test seam)
}

// NewReportService builds the service.
func NewReportService(repo *ReportRepository, blobs blobstore.Store, content *Service) *ReportService {
	return &ReportService{repo: repo, blobs: blobs, content: content}
}

// WithLimits overrides the DB-loaded cost ceiling (used to pin caps without a DB write).
func (rs *ReportService) WithLimits(l Limits) *ReportService { rs.capsOnce = &l; return rs }

func (rs *ReportService) limits(ctx context.Context) Limits {
	if rs.capsOnce != nil {
		return *rs.capsOnce
	}
	return rs.repo.LoadLimits(ctx)
}

// Generate assembles, serializes, and stores a report for the caller's tenant. Hard caps are enforced BEFORE store.
func (rs *ReportService) Generate(ctx context.Context, p auth.Principal, typ string, format Format) (*Report, error) {
	if !reportTypes[typ] {
		return nil, httpx.ErrBadRequest("unknown report type: " + typ)
	}
	if format != FormatJSON && format != FormatCSV && format != FormatXLSX && format != FormatPDF && format != FormatDOCX {
		return nil, httpx.ErrBadRequest("unsupported format: " + string(format))
	}
	lim := rs.limits(ctx)
	params, _ := json.Marshal(map[string]string{"type": typ}) // tenant-fixed; no scope-widening input
	id, err := rs.repo.Create(ctx, p.TenantID, p.UserID, typ, format, params)
	if err != nil {
		return nil, err
	}

	ds, err := rs.buildServiceReview(ctx, p.TenantID)
	if err != nil {
		_ = rs.repo.MarkFailed(ctx, p.TenantID, id, err.Error())
		return nil, httpx.ErrInternal("report assembly failed")
	}
	return rs.finalizeReport(ctx, p, id, ds, format, lim)
}

// finalizeReport caps → serialize/render → byte-cap → store → mark-ready → audit → return, the shared tail for
// every report type. PDF goes through the fenced pdfrender sub-package; all other formats through the serializer
// choke point (both bounded by the row/cell caps above and the byte cap here).
func (rs *ReportService) finalizeReport(ctx context.Context, p auth.Principal, id uuid.UUID, ds Dataset, format Format, lim Limits) (*Report, error) {
	if len(ds.Rows) > lim.MaxRows || len(ds.Rows)*len(ds.Columns) > lim.MaxCells {
		_ = rs.repo.MarkFailed(ctx, p.TenantID, id, "report exceeds row/cell ceiling")
		return nil, httpx.ErrBadRequest("report exceeds the configured row/cell ceiling")
	}
	var data []byte
	var err error
	if format == FormatPDF {
		data, err = renderReportPDF(ds)
	} else {
		data, err = Serialize(ds, format)
	}
	if err != nil {
		_ = rs.repo.MarkFailed(ctx, p.TenantID, id, err.Error())
		return nil, httpx.ErrInternal("serialize failed")
	}
	if len(data) > lim.MaxBytes {
		_ = rs.repo.MarkFailed(ctx, p.TenantID, id, "report exceeds byte ceiling")
		return nil, httpx.ErrBadRequest("report exceeds the configured size ceiling")
	}
	uri, err := rs.blobs.Put(ctx, p.TenantID, uuid.NewString(), data) // OPAQUE key
	if err != nil {
		_ = rs.repo.MarkFailed(ctx, p.TenantID, id, "artifact store failed")
		return nil, httpx.ErrInternal("artifact store failed")
	}
	if err := rs.repo.MarkReady(ctx, p.TenantID, id, uri, len(ds.Rows), len(data)); err != nil {
		return nil, err
	}
	// REP-008: every generate is recorded in the append-only report_audit. Do NOT swallow this — a report the
	// platform generated but cannot show it generated is a compliance gap. The report row is already 'ready', so a
	// retry (which re-generates) is an acceptable cost against silently losing the audit.
	if err := rs.repo.WriteAudit(ctx, p.TenantID, &id, p.UserID, "generate", format, len(ds.Rows)); err != nil {
		return nil, httpx.ErrInternal("report generated but its audit record failed; retry")
	}
	return rs.repo.Get(ctx, p.TenantID, id)
}

// Get returns a report record (tenant-scoped).
func (rs *ReportService) Get(ctx context.Context, p auth.Principal, id uuid.UUID) (*Report, error) {
	return rs.repo.Get(ctx, p.TenantID, id)
}

// Download returns the artifact bytes + format after re-checking tenant scope via RLS (session authz — refinement
// #3) and records a download audit. Only a 'ready' report in the caller's tenant is downloadable.
func (rs *ReportService) Download(ctx context.Context, p auth.Principal, id uuid.UUID) ([]byte, Format, error) {
	rep, err := rs.repo.Get(ctx, p.TenantID, id)
	if err != nil {
		return nil, "", err
	}
	if rep.Status != "ready" || rep.artifactURI == "" {
		return nil, "", httpx.ErrConflict("report is not ready for download")
	}
	// #173 release gate: a review-required report is not downloadable until a senior actor (≠ creator) approves it.
	// This is the SAME session-authorized, RLS-confined download path (refinement #3) with one added release
	// precondition — no new authz surface. 'none' (no review policy) and 'approved' release; the others hold.
	switch rep.ReviewStatus {
	case "pending_review":
		return nil, "", httpx.ErrConflict("report is awaiting review approval before it can be released")
	case "rejected":
		return nil, "", httpx.ErrConflict("report was rejected in review and cannot be released")
	}
	data, err := rs.blobs.Get(ctx, rep.artifactURI)
	if err != nil {
		return nil, "", httpx.ErrInternal("artifact read failed")
	}
	// REP-008: every download is recorded. Fail CLOSED — do not hand out a compliance artifact if we cannot record
	// who took it and when. A transient audit-DB failure blocks the download; the caller retries.
	if err := rs.repo.WriteAudit(ctx, p.TenantID, &id, p.UserID, "download", rep.Format, rep.RowCount); err != nil {
		return nil, "", httpx.ErrInternal("could not record the download audit; retry")
	}
	return data, rep.Format, nil
}

// buildServiceReview assembles the REP-004 monthly service-review dataset from the existing summary readers (all
// under WithTenant). Numbers are native cells; MITRE technique labels are string cells (formula-proof at serialize).
func (rs *ReportService) buildServiceReview(ctx context.Context, tenantID uuid.UUID) (Dataset, error) {
	sum, err := rs.content.Summary(ctx, tenantID)
	if err != nil {
		return Dataset{}, err
	}
	ds := Dataset{
		Title:   "Service Review",
		Columns: []string{"metric", "value"},
		Meta: map[string]string{
			"tenant":       tenantID.String(),
			"generated_at": sum.GeneratedAt.UTC().Format(time.RFC3339),
			"scope":        "tenant",
			"report_type":  "service_review",
		},
	}
	add := func(metric string, n int) { ds.Rows = append(ds.Rows, []Cell{Str(metric), Num(float64(n))}) }
	add("open_alerts", sum.OpenAlerts)
	add("open_incidents", sum.OpenIncidents)
	add("events_last_24h", sum.EventsLast24h)
	add("sla_ack_breaching", sum.SLA.AckBreaching)
	add("sla_resolve_breaching", sum.SLA.ResolveBreaching)
	add("sla_resolved_late", sum.SLA.ResolvedLate)
	// Mean-time KPIs (MTTA/MTTR) over the rolling window — only emitted when a sample exists (nil ⇒ omit,
	// never a misleading 0). Numeric cells (seconds); the window/sample-size travel as metadata.
	if sum.MeanTimes.MTTASeconds != nil {
		ds.Rows = append(ds.Rows, []Cell{Str("mtta_seconds"), Num(*sum.MeanTimes.MTTASeconds)})
	}
	if sum.MeanTimes.MTTRSeconds != nil {
		ds.Rows = append(ds.Rows, []Cell{Str("mttr_seconds"), Num(*sum.MeanTimes.MTTRSeconds)})
	}
	ds.Meta["mean_time_window_days"] = strconv.Itoa(sum.MeanTimes.WindowDays)
	ds.Meta["mtta_sample_count"] = strconv.Itoa(sum.MeanTimes.AcknowledgedCount)
	ds.Meta["mttr_sample_count"] = strconv.Itoa(sum.MeanTimes.ResolvedCount)
	for sev, n := range sum.AlertsBySeverity {
		add("alerts_severity_"+sev, n)
	}
	for stage, n := range sum.IncidentsByStage {
		add("incidents_stage_"+stage, n)
	}
	for _, m := range sum.TopMITRE {
		ds.Rows = append(ds.Rows, []Cell{Str("mitre_" + m.Technique), Num(float64(m.Count))})
	}
	return ds, nil
}

// safeFilename strips CR/LF and other control/path characters so the Content-Disposition header cannot be injected
// (refinement #4). The name is server-constructed, but this is belt-and-suspenders for any future title use.
func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '"' || r == '\\' || r == '/' || r < 0x20:
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
