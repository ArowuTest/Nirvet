package asset

// Pure unit tests (no DB) for the asset Create input guards (GC-3). All invalid-input branches return before
// any repository call, so a Service with a nil repo exercises them safely.

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

func badRequest(t *testing.T, err error) {
	t.Helper()
	var api *httpx.APIError
	if !errors.As(err, &api) || api.Code != "bad_request" {
		t.Fatalf("expected bad_request APIError, got %v", err)
	}
}

func TestAssetCreate_InputGuards(t *testing.T) {
	svc := NewService(nil, nil) // repo never dereferenced on the invalid-input paths
	ctx := context.Background()
	p := auth.Principal{TenantID: uuid.New(), UserID: uuid.New(), Email: "a@b.c"}

	cases := map[string]CreateInput{
		"empty ref":           {Ref: "   ", Name: "n"},
		"empty name":          {Ref: "host:1", Name: "  "},
		"invalid kind":        {Ref: "host:1", Name: "n", Kind: "toaster"},
		"invalid criticality": {Ref: "host:1", Name: "n", Kind: "host", Criticality: "apocalyptic"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Create(ctx, p, in); err == nil {
				t.Fatal("expected error")
			} else {
				badRequest(t, err)
			}
		})
	}
}
