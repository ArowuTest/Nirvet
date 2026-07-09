package ticketing_test

// Outbound ticketing against mock ServiceNow/Jira endpoints, plus the MirrorIncident
// DB path (per-tenant connection, vault-sealed credential). Gated on
// NIRVET_TEST_DATABASE_URL for the DB path; the provider tests need no DB.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/ticketing"
	"github.com/google/uuid"
)

func TestServiceNowProvider(t *testing.T) {
	defer ticketing.SetHTTPClient(&http.Client{})() // reach the loopback mock (SafeClient blocks it)
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/now/table/incident" || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]string{"sys_id": "abc123", "number": "INC0012345"},
		})
	}))
	defer srv.Close()

	p, _ := ticketing.ProviderFor(ticketing.ProviderServiceNow)
	conn := &ticketing.Connection{Provider: ticketing.ProviderServiceNow, BaseURL: srv.URL, AuthUser: "svc"}
	ref, err := p.Create(context.Background(), conn, "pw", ticketing.Ticket{Title: "Breach", Severity: "critical", Description: "d"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.ID != "INC0012345" || !strings.Contains(ref.URL, "abc123") {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("expected basic auth, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, "Breach") {
		t.Fatalf("body missing title: %s", gotBody)
	}
}

func TestJiraProvider(t *testing.T) {
	defer ticketing.SetHTTPClient(&http.Client{})() // reach the loopback mock (SafeClient blocks it)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue" || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key": "SOC-42"})
	}))
	defer srv.Close()

	p, _ := ticketing.ProviderFor(ticketing.ProviderJira)
	conn := &ticketing.Connection{Provider: ticketing.ProviderJira, BaseURL: srv.URL, AuthUser: "a@b.com",
		Config: map[string]any{"project_key": "SOC"}}
	ref, err := p.Create(context.Background(), conn, "token", ticketing.Ticket{Title: "Phish", Severity: "high"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.ID != "SOC-42" || !strings.Contains(ref.URL, "/browse/SOC-42") {
		t.Fatalf("unexpected ref: %+v", ref)
	}
}

func TestJiraProvider_RequiresProjectKey(t *testing.T) {
	p, _ := ticketing.ProviderFor(ticketing.ProviderJira)
	conn := &ticketing.Connection{Provider: ticketing.ProviderJira, BaseURL: "http://x", Config: map[string]any{}}
	if _, err := p.Create(context.Background(), conn, "t", ticketing.Ticket{Title: "x"}); err == nil {
		t.Fatal("jira create must fail without a project_key")
	}
}

func TestMirrorIncident_DBPath(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run the ticketing DB path")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "tkt-" + uuid.NewString()})
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	repo := ticketing.NewRepository(db)
	svc := ticketing.NewService(repo, cipher)

	// No connection yet → MirrorIncident is a no-op (empty ref, no error).
	if ref, _, err := svc.MirrorIncident(ctx, tn.ID, "t", "high", "b"); err != nil || ref != "" {
		t.Fatalf("no-connection mirror should be a no-op: ref=%q err=%v", ref, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "s1", "number": "INC55"}})
	}))
	defer srv.Close()

	// R6 SEC-carry: CreateConnection rejects a non-https / internal base_url up front (the mock is
	// loopback http → both). This is the SSRF guard at save time.
	if _, err := svc.CreateConnection(ctx, tn.ID, ticketing.CreateInput{
		Provider: ticketing.ProviderServiceNow, BaseURL: srv.URL, AuthUser: "svc", Credential: "secret",
	}); err == nil {
		t.Fatal("CreateConnection must reject a loopback/non-https base_url (SSRF guard)")
	}

	// To exercise the delivery path against the loopback mock, insert the connection via the repo
	// (bypassing the save-time guard) and swap in a plain client (SafeClient blocks loopback).
	defer ticketing.SetHTTPClient(&http.Client{})()
	sealed, _ := cipher.Encrypt(tn.ID, []byte("secret"))
	if err := repo.Create(ctx, &ticketing.Connection{
		ID: uuid.New(), TenantID: tn.ID, Provider: ticketing.ProviderServiceNow, BaseURL: srv.URL,
		AuthUser: "svc", Credential: sealed, Config: map[string]any{}, Enabled: true,
	}); err != nil {
		t.Fatalf("repo insert connection: %v", err)
	}
	ref, url, err := svc.MirrorIncident(ctx, tn.ID, "Ransomware", "critical", "body")
	if err != nil || ref != "INC55" || !strings.Contains(url, "s1") {
		t.Fatalf("mirror: ref=%q url=%q err=%v", ref, url, err)
	}
}
