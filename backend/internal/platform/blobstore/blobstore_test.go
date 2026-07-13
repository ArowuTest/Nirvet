package blobstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestLocalStore_RoundTripAndTraversal(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	uri, err := s.Put(ctx, uuid.New(), "raw/x.json", []byte("hello"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(ctx, uri)
	if err != nil || string(got) != "hello" {
		t.Fatalf("get round-trip: %q err=%v", got, err)
	}
	// Path traversal and a non-file scheme are refused (defence in depth: a client-supplied pointer must
	// never escape the storage root).
	if _, err := s.Get(ctx, "file://../../etc/passwd"); err == nil {
		t.Fatal("a traversal URI must be rejected")
	}
	if _, err := s.Get(ctx, "http://evil/x"); err == nil {
		t.Fatal("a non-file:// scheme must be rejected")
	}
}

// The Store.Delete contract requires idempotency: deleting a missing/already-deleted object returns nil.
// Retention relies on this to self-heal an orphaned row (blob gone, metadata row present) on a later sweep —
// a Delete that errored on "not found" would strand the row permanently. Every backend must conform.
func TestLocalStore_DeleteMissingIsIdempotent(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	// Never written, then delete twice — both must succeed.
	if err := s.Delete(ctx, "file://never/written.json"); err != nil {
		t.Fatalf("Delete of a missing object must be nil (contract), got %v", err)
	}
	uri, err := s.Put(ctx, uuid.New(), "k/x.json", []byte("x"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.Delete(ctx, uri); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := s.Delete(ctx, uri); err != nil {
		t.Fatalf("second delete of the same (now-gone) object must be nil (idempotent), got %v", err)
	}
}
