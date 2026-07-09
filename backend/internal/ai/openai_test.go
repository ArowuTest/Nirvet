package ai

// §6.12 #117 A-3 — openai_compatible provider unit tests (httptest, no DB): request/response mapping, keyless omits
// the Authorization header, and the hardened client REFUSES a redirect (SSRF containment).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func oaiHandler(t *testing.T, content string, capAuth *string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if capAuth != nil {
			*capAuth = r.Header.Get("Authorization")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": content}}},
		})
	}
}

func TestOpenAIProvider_Completes(t *testing.T) {
	var auth string
	srv := httptest.NewServer(oaiHandler(t, "triage summary", &auth))
	defer srv.Close()
	p := newOpenAICompatibleProvider(srv.URL, "local-model", "sk-secret", nil)
	got, err := p.Complete(context.Background(), "system", "user")
	if err != nil || got != "triage summary" {
		t.Fatalf("Complete = %q err=%v", got, err)
	}
	if auth != "Bearer sk-secret" {
		t.Fatalf("expected bearer auth, got %q", auth)
	}
	if p.Model() != "local-model" {
		t.Fatalf("model=%q", p.Model())
	}
}

func TestOpenAIProvider_KeylessOmitsAuth(t *testing.T) {
	var auth string
	srv := httptest.NewServer(oaiHandler(t, "ok", &auth))
	defer srv.Close()
	p := newOpenAICompatibleProvider(srv.URL, "m", "", nil) // keyless local model
	if _, err := p.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if auth != "" {
		t.Fatalf("keyless provider must not send Authorization, got %q", auth)
	}
}

func TestOpenAIProvider_RefusesRedirect(t *testing.T) {
	// A 3xx off the (allowlisted) host must NOT be followed — the hardened client refuses it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	p := newOpenAICompatibleProvider(srv.URL, "m", "", nil)
	if _, err := p.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("Complete must fail when the endpoint redirects (redirect refused)")
	}
}
