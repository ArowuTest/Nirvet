// Package blobstore is a cloud-agnostic object store for raw event evidence and
// report artifacts (ADR-0002). It is the seam that keeps Nirvet portable: the
// local filesystem backs development and single-node deploys; GCS/S3 back cloud.
// No caller depends on a provider SDK — only on this interface.
//
// Portability strategy (ADR-0005): every cloud-coupled capability sits behind an
// interface — EventStore, queue.Queue, crypto.SecretCipher (KMS), and this
// BlobStore — so the platform runs on local, Render, or GCP by swapping the
// implementation, never the callers.
package blobstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// Store persists and retrieves immutable blobs by key, returning a URI.
type Store interface {
	// Put writes data for a tenant under key and returns a storage URI.
	Put(ctx context.Context, tenantID uuid.UUID, key string, data []byte) (string, error)
	// Get retrieves a blob by its URI.
	Get(ctx context.Context, uri string) ([]byte, error)
	// Delete removes a blob by its URI.
	//
	// CONTRACT — Delete MUST be idempotent: deleting a missing or already-deleted object
	// returns nil, never an error. This is load-bearing, not a convenience: retention deletes
	// the payload blob BEFORE its raw_events row (so a blob is never retained past its row), and
	// a crash between those two steps leaves an orphaned row whose blob is already gone. The next
	// retention sweep re-selects that row and calls Delete again — an idempotent Delete lets the
	// row finally be removed (self-heal), whereas a Delete that errored on "not found" would
	// strand the row permanently. Every implementation (local, S3, and any future GCS/Azure)
	// must satisfy this; blobstore_test.go asserts it.
	Delete(ctx context.Context, uri string) error
	// Backend identifies the implementation (for health/diagnostics).
	Backend() string
}

// localStore writes blobs under a root directory (dev / single-node).
type localStore struct{ root string }

// NewLocal builds a filesystem-backed store rooted at dir.
func NewLocal(dir string) (Store, error) {
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "nirvet-blobs")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &localStore{root: dir}, nil
}

func (s *localStore) Backend() string { return "local" }

func (s *localStore) Put(_ context.Context, tenantID uuid.UUID, key string, data []byte) (string, error) {
	rel := filepath.Join("tenant", tenantID.String(), filepath.Clean("/"+key))
	full := filepath.Join(s.root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, data, 0o640); err != nil {
		return "", err
	}
	return "file://" + filepath.ToSlash(rel), nil
}

func (s *localStore) Get(_ context.Context, uri string) ([]byte, error) {
	full, err := s.resolve(uri)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(full)
}

func (s *localStore) Delete(_ context.Context, uri string) error {
	full, err := s.resolve(uri)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil // already gone / removed — best-effort
}

// resolve maps a stored file:// URI to an absolute on-disk path and CONFIRMS it stays under the storage
// root — defence in depth against a path-traversal read if a client-supplied pointer ever reaches Get
// (today all URIs are produced by Put, but the invariant should be enforced, not assumed). It rejects a
// non-file:// scheme and any path that escapes the root after cleaning (e.g. an embedded `../`).
func (s *localStore) resolve(uri string) (string, error) {
	if !strings.HasPrefix(uri, "file://") {
		return "", fmt.Errorf("blobstore: unsupported blob URI scheme")
	}
	rel := strings.TrimPrefix(uri, "file://")
	full := filepath.Clean(filepath.Join(s.root, filepath.FromSlash(rel)))
	root := filepath.Clean(s.root)
	if full != root && !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("blobstore: resolved path escapes the storage root")
	}
	return full, nil
}

// The GCP (GCS) backend is not yet implemented (ADR-0005). It is intentionally absent rather
// than a runtime-erroring stub — New() fails fast when a bucket is configured (see below).
// When implemented, add a gcsStore satisfying Store and return it from New().

// New selects the backend: GCS when a bucket is configured, else local. The GCS backend is
// not yet implemented (ADR-0005), so — like the KMS cipher — a configured-but-unimplemented
// GCS bucket FAILS FAST at startup rather than returning a store that errors on every Put/Get
// at runtime (which would silently break evidence capture in production).
func New(gcsBucket, localDir string) (Store, error) {
	// S3-compatible store (Backblaze B2 / R2 / AWS S3 / MinIO / GCS-interop) — selected when NIRVET_S3_*
	// is configured. This is the durable interim store AND the production path (ADR-0005).
	if c, ok := s3ConfigFromEnv(); ok {
		return newS3(c)
	}
	if gcsBucket != "" {
		// Native GCS is not implemented; use the S3 adapter against the GCS S3-interoperability endpoint
		// (NIRVET_S3_* with the GCS HMAC key), or the local disk store.
		return nil, fmt.Errorf("blobstore: native GCS backend not implemented (ADR-0005); use NIRVET_S3_* (S3-compatible, incl. the GCS interop endpoint), or unset NIRVET_GCS_BUCKET for the local store")
	}
	return NewLocal(localDir)
}
