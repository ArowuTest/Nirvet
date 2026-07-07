package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Name is mandatory: creation must fail closed (before any DB write) on an empty
// or whitespace-only name. Uses a nil repo — validation returns before repo use.
func TestCreate_RequiresName(t *testing.T) {
	svc := NewService(nil)
	for _, name := range []string{"", "   ", "\t\n"} {
		_, err := svc.Create(context.Background(), CreateInput{Name: name})
		if err == nil {
			t.Fatalf("Create with name %q must fail", name)
		}
		var apiErr *httpx.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 400 {
			t.Fatalf("expected 400 APIError for empty name, got %v", err)
		}
	}
}
