package ingestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
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
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	// A PROVIDED severity must be valid (reject at the door with a clear 400). An
	// EMPTY severity is intentionally left empty so the source normalizer can derive
	// it from vendor fields (e.g. CrowdStrike/GuardDuty numeric scales); Normalize
	// finalizes any still-empty severity to "informational". Defaulting it here —
	// before the mappers run — would make their `if severity == ""` derivation dead
	// code and silently under-fire severity-gated detections.
	if in.Severity != "" && !validSeverities[in.Severity] {
		return "", httpx.ErrBadRequest("invalid severity: must be informational|low|medium|high|critical")
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	// Per-tenant ingest quota / backpressure (ADR-0003).
	if s.quota != nil {
		ok, qerr := s.quota.WithinIngestQuota(ctx, tenantID, int64(len(payload)))
		if qerr != nil {
			// R6: the quota check fails OPEN (availability), but the error must not be silent — a broken
			// billing backend silently disabling per-tenant backpressure should be diagnosable.
			slog.Warn("ingest quota check failed; admitting event (fail-open)", "tenant", tenantID, "err", qerr)
		} else if !ok {
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
		// The raw event is durably persisted; the reconciler will re-enqueue it
		// (enqueued_at is still NULL), so nothing is lost even though we 500 here.
		return "", httpx.ErrInternal("could not enqueue normalization")
	}
	// Close the durability marker: the normalize job exists, so the reconciler will
	// not re-enqueue this event. Best-effort — a lost marker only costs one idempotent
	// re-enqueue on the next sweep.
	_ = s.repo.MarkEnqueued(ctx, tenantID, raw.ID)
	metrics.EventsIngested.Inc()
	return dedupeKey, nil
}

// Reconcile re-enqueues raw events whose normalize job was never enqueued — the
// durability backstop for the non-atomic StoreRaw→Enqueue sequence (SEC Critical #4).
// It runs at the system level (spans tenants) and is at-least-once: the payload is
// re-read from the blob store and a fresh normalize job is enqueued; a raw event that
// WAS actually processed but whose marker was lost is re-normalized harmlessly (the
// event Append dedupes on dedupe_key). Returns the number re-enqueued.
func (s *Service) Reconcile(ctx context.Context, olderThan time.Duration, limit int) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	pending, err := s.repo.FindUnenqueued(ctx, cutoff, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range pending {
		payload, gerr := s.blobs.Get(ctx, u.BlobURI)
		if gerr != nil {
			// Evidence temporarily unreadable — leave the marker unset so the next
			// sweep retries rather than dropping the event.
			continue
		}
		var in IngestInput
		if uerr := json.Unmarshal(payload, &in); uerr != nil {
			continue
		}
		job := normalizeJob{RawID: u.ID, DedupeKey: u.DedupeKey, Checksum: u.Checksum, Input: in}
		jb, _ := json.Marshal(job)
		if eerr := s.q.Enqueue(ctx, u.TenantID, "normalize", jb); eerr != nil {
			continue
		}
		_ = s.repo.MarkEnqueued(ctx, u.TenantID, u.ID)
		n++
	}
	return n, nil
}

// StartReconciler runs Reconcile on a ticker until ctx is cancelled. grace is how long
// a raw event may sit unenqueued before it is considered orphaned (kept above the
// worker tick so an in-flight enqueue is not raced). Runs in exactly one process.
func (s *Service) StartReconciler(ctx context.Context, log *slog.Logger, interval, grace time.Duration, limit int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "ingest-reconciler", func() {
				if n, err := s.Reconcile(ctx, grace, limit); err != nil {
					log.Warn("ingest reconcile failed", "err", err)
				} else if n > 0 {
					log.Warn("ingest reconcile re-enqueued orphaned raw events", "count", n)
				}
			})
		}
	}
}
