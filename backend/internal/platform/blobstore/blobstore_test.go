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
