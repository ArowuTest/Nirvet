package connector

// Connector test-connection probe. Verifies: a valid token → ok + health healthy; rejected creds → failed +
// health degraded + NO secret leak; an inbound push source → not_applicable; and — the SSRF claim, proven not
// assumed — that the prod path actually runs over netsafe.SafeClient (it must REFUSE a reachable loopback mock
// that a plain client would authenticate against).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func probeSvc(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	blobs, _ := blobstore.NewLocal(t.TempDir())
	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), queue.NewPostgres(db.Pool), nil, blobs)
	return NewService(NewRepository(db), NewVault(cipher), ingestSvc), db
}

func tokenServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	})
	return httptest.NewServer(mux)
}

func mkConn(t *testing.T, svc *Service, kind Kind, secret string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	res, err := svc.Create(context.Background(), tenantID, CreateInput{
		Kind: kind, Name: string(kind) + "-probe", Secret: secret,
		Config: map[string]any{"client_id": "cid", "azure_tenant": "az"},
	})
	if err != nil {
		t.Fatalf("create %s: %v", kind, err)
	}
	t.Cleanup(func() { _ = svc.Delete(context.Background(), tenantID, res.Connector.ID) })
	return tenantID, res.Connector.ID
}

func health(t *testing.T, db *database.DB, tid, id uuid.UUID) string {
	t.Helper()
	var h string
	_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT health FROM connector_configs WHERE id=$1`, id).Scan(&h)
	})
	return h
}

func TestProbe_OK(t *testing.T) {
	svc, db := probeSvc(t)
	srv := tokenServer(t, http.StatusOK, `{"access_token":"t","expires_in":3600}`)
	t.Cleanup(srv.Close)
	svc.probeHTTP, svc.probeTokenURL, svc.probeGraphURL = srv.Client(), srv.URL+"/token", srv.URL
	tid, id := mkConn(t, svc, KindDefender, "the-secret")

	res, err := svc.TestConnection(context.Background(), tid, id)
	if err != nil || res.Status != "ok" {
		t.Fatalf("want ok, got res=%+v err=%v", res, err)
	}
	if got := health(t, db, tid, id); got != "healthy" {
		t.Fatalf("health should be healthy, got %q", got)
	}
}

func TestProbe_BadCreds(t *testing.T) {
	svc, db := probeSvc(t)
	srv := tokenServer(t, http.StatusUnauthorized, `{"error":"invalid_client"}`)
	t.Cleanup(srv.Close)
	svc.probeHTTP, svc.probeTokenURL, svc.probeGraphURL = srv.Client(), srv.URL+"/token", srv.URL
	tid, id := mkConn(t, svc, KindDefender, "wrong-secret")

	res, err := svc.TestConnection(context.Background(), tid, id)
	if err != nil || res.Status != "failed" || !strings.Contains(res.Detail, "credentials") {
		t.Fatalf("want failed/credentials, got res=%+v err=%v", res, err)
	}
	if strings.Contains(res.Detail, "wrong-secret") {
		t.Fatal("probe must never leak the secret")
	}
	if got := health(t, db, tid, id); got != "degraded" {
		t.Fatalf("health should be degraded, got %q", got)
	}
}

func TestProbe_NotApplicableForInboundSource(t *testing.T) {
	svc, _ := probeSvc(t)
	tid, id := mkConn(t, svc, KindWebhook, "")
	res, err := svc.TestConnection(context.Background(), tid, id)
	if err != nil || res.Status != "not_applicable" {
		t.Fatalf("inbound source want not_applicable, got res=%+v err=%v", res, err)
	}
}

// The SSRF guarantee, proven not assumed: prod path (probeHTTP nil → netsafe.SafeClient) MUST refuse a reachable
// loopback token server that a plain client would authenticate against. If SafeClient weren't in the path this
// would return "ok" — asserting "failed" proves the probe adds no new egress surface.
func TestProbe_ProdPathUsesSafeClient(t *testing.T) {
	svc, _ := probeSvc(t)
	srv := tokenServer(t, http.StatusOK, `{"access_token":"t","expires_in":3600}`)
	t.Cleanup(srv.Close)
	// probeHTTP intentionally left nil → SafeClient. Point at the reachable loopback mock.
	svc.probeTokenURL, svc.probeGraphURL = srv.URL+"/token", srv.URL
	tid, id := mkConn(t, svc, KindDefender, "s")

	res, err := svc.TestConnection(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Status != "failed" {
		t.Fatalf("SafeClient must block the reachable loopback target (no new egress surface); got %+v", res)
	}
}
