package syslogd

// MA-SYS-1..4 adversarial suite against real TLS handshakes + a migrated Postgres (for syslog_sources). A fake
// Ingester isolates the listener's security behaviour (handshake reject, channel attribution, parse, bounds)
// from the downstream ingest pipeline, which is tested elsewhere. Centerpiece probes: the mTLS handshake-reject
// and the payload-claimed-tenant-ignored (cross-tenant injection) cases.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/time/rate"
)

// fakeIngester records (tenant, input) so a test can assert exactly which tenant a line was attributed to.
type fakeIngester struct {
	mu  sync.Mutex
	got []fakeCall
}
type fakeCall struct {
	tenant uuid.UUID
	in     ingestion.IngestInput
}

func (f *fakeIngester) Ingest(_ context.Context, tenantID uuid.UUID, in ingestion.IngestInput) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, fakeCall{tenant: tenantID, in: in})
	return "ok", nil
}
func (f *fakeIngester) calls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.got...)
}

func genCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(time.Now().UnixNano())),
		Subject:               pkix.Name{CommonName: "syslog-test-" + uuid.NewString()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, fingerprint(der)
}

func syslogDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func mkTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "sys-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func registerSource(t *testing.T, db *database.DB, tid uuid.UUID, fp string, enabled bool) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO syslog_sources (id, tenant_id, cert_fingerprint, enabled) VALUES ($1,$2,$3,$4)
			ON CONFLICT (cert_fingerprint) DO UPDATE SET enabled=EXCLUDED.enabled`, uuid.New(), tid, fp, enabled)
		return e
	}); err != nil {
		t.Fatalf("register source: %v", err)
	}
}

// startListener boots a listener on a random loopback port and returns its address + the fake ingester.
func startListener(t *testing.T, db *database.DB, cfg Config) (string, *fakeIngester) {
	t.Helper()
	server, _ := genCert(t)
	cfg.ServerCert = server
	fake := &fakeIngester{}
	l := New(NewSourceStore(db), fake, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", l.TLSConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go l.serve(ctx, ln)
	return ln.Addr().String(), fake
}

// dial connects with an optional client cert (nil = certless).
func dial(addr string, clientCert *tls.Certificate) (*tls.Conn, error) {
	cfg := &tls.Config{InsecureSkipVerify: true} // test skips SERVER verification; the SERVER enforces client mTLS
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

func sendFrame(conn *tls.Conn, msg string) {
	fmt.Fprintf(conn, "%d %s", len(msg), msg)
}

// rejected reports whether the listener rejects a connection with the given client cert. Robust across TLS
// 1.2/1.3: a rejected mTLS connection either fails at Dial (1.2) or is CLOSED by the server right after the
// handshake (1.3) — so a subsequent Read returns a non-timeout error (EOF/reset). A healthy (accepted)
// connection stays open, so a Read hits the deadline (a timeout) — which is NOT a rejection.
func rejected(addr string, cert *tls.Certificate) bool {
	c, err := dial(addr, cert)
	if err != nil {
		return true // rejected at the handshake (TLS 1.2 synchronous path)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return false // connection stayed open (accepted) — NOT a rejection
		}
		return true // server closed/aborted the connection — rejected
	}
	return false
}

func waitCalls(f *fakeIngester, n int) bool {
	for i := 0; i < 100; i++ {
		if len(f.calls()) >= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return len(f.calls()) >= n
}

// TestSyslog_HandshakeReject (MA-SYS-1): certless and unregistered/disabled client certs are rejected AT THE
// HANDSHAKE — never accepted-then-dropped.
func TestSyslog_HandshakeReject(t *testing.T) {
	db := syslogDB(t)
	addr, fake := startListener(t, db, Config{})

	// (1) Certless connection → rejected by RequireAnyClientCert.
	if !rejected(addr, nil) {
		t.Fatal("MA-SYS-1: a CERTLESS connection must be rejected")
	}
	// (2) Unregistered client cert → VerifyPeerCertificate rejects.
	unreg, _ := genCert(t)
	if !rejected(addr, &unreg) {
		t.Fatal("MA-SYS-1: an UNREGISTERED client cert must be rejected")
	}
	// (3) Registered-but-DISABLED source → also rejected (secure default / revocation).
	disabled, dfp := genCert(t)
	registerSource(t, db, mkTenant(t, db), dfp, false)
	if !rejected(addr, &disabled) {
		t.Fatal("MA-SYS-1: a DISABLED source's cert must be rejected")
	}
	if len(fake.calls()) != 0 {
		t.Fatalf("no rejected connection may ingest, got %d", len(fake.calls()))
	}
}

// TestSyslog_AttributionFromChannel_NotPayload (MA-SYS-2): a line whose payload HOSTNAME names another tenant,
// arriving on tenant A's authenticated channel, is ingested as tenant A. The cross-tenant-injection probe.
func TestSyslog_AttributionFromChannel_NotPayload(t *testing.T) {
	db := syslogDB(t)
	addr, fake := startListener(t, db, Config{})
	tA := mkTenant(t, db)
	tB := mkTenant(t, db)
	cert, fp := genCert(t)
	registerSource(t, db, tA, fp, true)

	conn, err := dial(addr, &cert)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// The payload's HOSTNAME field is tenant B's id — a spoof attempt. Attribution must ignore it.
	sendFrame(conn, "<13>1 2024-01-01T00:00:00Z "+tB.String()+" app - - - hello")
	if !waitCalls(fake, 1) {
		t.Fatal("expected the line to be ingested")
	}
	c := fake.calls()[0]
	if c.tenant != tA {
		t.Fatalf("attribution MUST be the cert's tenant (tA=%s), not the payload's claimed tenant (tB=%s), got %s", tA, tB, c.tenant)
	}
	if c.in.Data["log_source_host"] != tB.String() {
		t.Fatalf("the payload hostname should be kept as informational data only, got %v", c.in.Data["log_source_host"])
	}
}

// TestSyslog_MalformedAndOversized (MA-SYS-3/4 parser): a malformed/oversized frame drops the offending
// connection but the listener keeps serving other connections.
func TestSyslog_MalformedAndOversized(t *testing.T) {
	db := syslogDB(t)
	addr, fake := startListener(t, db, Config{MaxMessageBytes: 128})
	tA := mkTenant(t, db)
	cert, fp := genCert(t)
	registerSource(t, db, tA, fp, true)

	// Oversized length prefix → connection dropped, nothing ingested.
	bad, err := dial(addr, &cert)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(bad, "9999999 x") // claims a huge length over the 128 cap
	time.Sleep(50 * time.Millisecond)
	bad.Close()

	// The listener still serves a fresh, well-formed connection.
	good, err := dial(addr, &cert)
	if err != nil {
		t.Fatalf("dial good: %v", err)
	}
	defer good.Close()
	sendFrame(good, "<14>1 2024-01-01T00:00:00Z h app - - - ok")
	if !waitCalls(fake, 1) {
		t.Fatal("listener must survive a malformed connection and keep serving")
	}
}

// TestSyslog_PerSourceRateCap (MA-SYS-4): a burst from one source is throttled — not every line is ingested.
func TestSyslog_PerSourceRateCap(t *testing.T) {
	db := syslogDB(t)
	addr, fake := startListener(t, db, Config{PerSourceRate: rate.Limit(1), PerSourceBurst: 1})
	tA := mkTenant(t, db)
	cert, fp := genCert(t)
	registerSource(t, db, tA, fp, true)

	conn, err := dial(addr, &cert)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	for i := 0; i < 10; i++ {
		sendFrame(conn, "<13>1 2024-01-01T00:00:00Z h app - - - line")
	}
	time.Sleep(150 * time.Millisecond)
	if n := len(fake.calls()); n > 2 {
		t.Fatalf("per-source rate cap (1/s burst 1) must throttle a 10-line burst to ~1, got %d", n)
	}
}
