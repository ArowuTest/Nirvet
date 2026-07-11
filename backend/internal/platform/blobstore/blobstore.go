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
	// Delete removes a blob by its URI (best-effort cleanup of an orphaned write — e.g. a blob
	// written for a raw event that turned out to be a duplicate). Missing is not an error.
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
	rel := strings.TrimPrefix(uri, "file://")
	return os.ReadFile(filepath.Join(s.root, filepath.FromSlash(rel)))
}

func (s *localStore) Delete(_ context.Context, uri string) error {
	rel := strings.TrimPrefix(uri, "file://")
	err := os.Remove(filepath.Join(s.root, filepath.FromSlash(rel)))
	if os.IsNotExist(err) {
		return nil // already gone — best-effort
	}
	return err
}

// The GCP (GCS) backend is not yet implemented (ADR-0005). It is intentionally absent rather
// than a runtime-erroring stub — New() fails fast when a bucket is configured (see below).
// When implemented, add a gcsStore satisfying Store and return it from New().

// New selects the backend: GCS when a bucket is configured, else local. The GCS backend is
// not yet implemented (ADR-0005), so — like the KMS cipher — a configured-but-unimplemented
// GCS bucket FAILS FAST at startup rather than returning a store that errors on every Put/Get
// at runtime (which would silently break evidence capture in production).
func New(gcsBucket, localDir string) (Store, error) {
	if gcsBucket != "" {
		return nil, fmt.Errorf("blobstore: GCS backend not yet implemented (ADR-0005); unset NIRVET_GCS_BUCKET to use the local disk store, or wire the GCS backend before configuring a bucket")
	}
	return NewLocal(localDir)
}
