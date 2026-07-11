package blobstore

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestS3_RoundTrip is a LIVE integration test against a real S3-compatible store (Backblaze B2 / R2 / S3 /
// MinIO). Skipped unless NIRVET_S3_* is configured, so it never runs in normal CI without credentials.
func TestS3_RoundTrip(t *testing.T) {
	c, ok := s3ConfigFromEnv()
	if !ok {
		t.Skip("set NIRVET_S3_ENDPOINT/BUCKET/KEY_ID/APP_KEY to run the live S3 round-trip test")
	}
	s, err := newS3(c)
	if err != nil {
		t.Fatalf("newS3: %v", err)
	}
	ctx := context.Background()
	tid := uuid.New()
	body := []byte(`{"nirvet":"s3-roundtrip"}`)
	uri, err := s.Put(ctx, tid, "raw/roundtrip.json", body)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(ctx, uri)
	if err != nil || string(got) != string(body) {
		t.Fatalf("get: got %q err=%v", got, err)
	}
	if err := s.Delete(ctx, uri); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// TestObjectKey_TenantScopedAndTraversalSafe proves the S3 object key is tenant-prefixed and that an embedded
// "../" can't escape the tenant path — the same defence the local store's resolve() gives.
func TestObjectKey_TenantScopedAndTraversalSafe(t *testing.T) {
	tid := uuid.New()
	prefix := "tenant/" + tid.String() + "/"

	if got := objectKey(tid, "raw/x.json"); got != prefix+"raw/x.json" {
		t.Fatalf("unexpected key: %q", got)
	}
	// Traversal attempts stay inside the tenant prefix.
	for _, k := range []string{"../../etc/passwd", "raw/../../../secret", "/../../x"} {
		got := objectKey(tid, k)
		if !strings.HasPrefix(got, prefix) {
			t.Fatalf("key %q escaped tenant prefix: %q", k, got)
		}
	}
}
