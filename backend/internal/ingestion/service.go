package ingestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/google/uuid"
)

var validSeverities = map[string]bool{
	"informational": true, "low": true, "medium": true, "high": true, "critical": true,
}

// QuotaChecker gates ingestion by tenant entitlement (ADR-0003 backpressure).
// Implemented by the billing module; optional (nil = no quota enforcement).
type QuotaChecker interface {
	WithinIngestQuota(ctx context.Context, tenantID uuid.UUID, addBytes int64) (bool, error)
}

// Service handles event intake: persist raw evidence (blob store) then enqueue
// normalization.
type Service struct {
	repo  *Repository
	q     queue.Queue
	quota QuotaChecker
	blobs blobstore.Store
}

// NewService builds the service. quota may be nil to disable quota enforcement.
func NewService(repo *Repository, q queue.Queue, quota QuotaChecker, blobs blobstore.Store) *Service {
	return &Service{repo: repo, q: q, quota: quota, blobs: blobs}
}

// Ingest persists the raw event and enqueues normalization. Idempotent via the
// dedupe key (ADR-0003); the raw event is stored before the work is acknowledged.
func (s *Service) Ingest(ctx context.Context, tenantID uuid.UUID, in IngestInput) (string, error) {
	if in.Source == "" {
		return "", httpx.ErrBadRequest("source is required")
	}
	if in.Severity == "" {
		in.Severity = "informational"
	}
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	// Reject invalid severity at the door (clear 400) rather than dead-lettering
	// it later against the events severity CHECK constraint.
	if !validSeverities[in.Severity] {
		return "", httpx.ErrBadRequest("invalid severity: must be informational|low|medium|high|critical")
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	// Per-tenant ingest quota / backpressure (ADR-0003).
	if s.quota != nil {
		ok, qerr := s.quota.WithinIngestQuota(ctx, tenantID, int64(len(payload)))
		if qerr == nil && !ok {
			return "", httpx.ErrTooManyRequests("ingest quota exceeded for tenant")
		}
	}
	sum := sha256.Sum256(payload)
	checksum := hex.EncodeToString(sum[:])
	nid := in.NativeID
	if nid == "" {
		nid = checksum
	}
	dedupeKey := in.Source + ":" + nid

	raw := &RawEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Source:    in.Source,
		DedupeKey: dedupeKey,
		Checksum:  checksum,
	}
	// Persist the raw payload to the cloud-agnostic blob store (evidence), keeping
	// only the URI + checksum in Postgres. Portable across local / GCS / S3.
	uri, berr := s.blobs.Put(ctx, tenantID, "raw/"+raw.ID.String()+".json", payload)
	if berr != nil {
		return "", httpx.ErrInternal("could not store raw evidence")
	}
	raw.BlobURI = uri

	inserted, err := s.repo.StoreRaw(ctx, raw)
	if err != nil {
		return "", httpx.ErrInternal("could not persist raw event")
	}
	// Idempotency: a duplicate re-ingest is a no-op — do not re-enqueue, so
	// normalization and detection never run twice for the same event.
	if !inserted {
		return dedupeKey, nil
	}

	job := normalizeJob{RawID: raw.ID, DedupeKey: dedupeKey, Checksum: checksum, Input: in}
	jb, _ := json.Marshal(job)
	if err := s.q.Enqueue(ctx, tenantID, "normalize", jb); err != nil {
		return "", httpx.ErrInternal("could not enqueue normalization")
	}
	return dedupeKey, nil
}
