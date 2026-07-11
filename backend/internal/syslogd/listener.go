package syslogd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// maxConsecIngestFail bounds how many consecutive ingest failures a single connection tolerates before the
// listener closes it (M6). A short run of failures is a transient backend blip; a sustained run is a real
// outage, and closing the socket makes the sender back off instead of streaming lines into a black hole.
const maxConsecIngestFail = 10

// Ingester is the subset of the ingestion service the listener feeds. The listener passes the VERIFIED tenant
// (from the client cert), never anything from the payload. *ingestion.Service satisfies it.
type Ingester interface {
	Ingest(ctx context.Context, tenantID uuid.UUID, in ingestion.IngestInput) (string, error)
}

// Config holds the listener's seeded bounds (MA-SYS-4) + its server TLS cert. All limits default to safe values.
type Config struct {
	BindAddr        string
	ServerCert      tls.Certificate
	MaxMessageBytes int
	MaxConns        int
	ReadTimeout     time.Duration
	RecheckInterval time.Duration // MA-SYS-3: how often to re-verify a live connection's source is still enabled
	PerSourceRate   rate.Limit
	PerSourceBurst  int
}

// Listener is the mTLS syslog listener. It binds a private port, enforces mTLS at the handshake, attributes each
// connection to a tenant from the verified client cert, and feeds parsed lines to the atomic ingest pipeline.
type Listener struct {
	cfg      Config
	sources  *SourceStore
	ingest   Ingester
	log      *slog.Logger
	limiters sync.Map      // fingerprint(string) -> *rate.Limiter (per-source, MA-SYS-4)
	missLog  *rate.Limiter // platform-scope rate limit for source-miss logging (so a reject flood can't self-DoS the logs)
	sem      chan struct{} // max-connections cap (MA-SYS-4)
}

// New builds a listener, applying safe defaults for any unset bound.
func New(sources *SourceStore, ingest Ingester, log *slog.Logger, cfg Config) *Listener {
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 64 * 1024
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 256
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 5 * time.Minute
	}
	if cfg.RecheckInterval <= 0 {
		cfg.RecheckInterval = 60 * time.Second
	}
	if cfg.PerSourceRate <= 0 {
		cfg.PerSourceRate = 500 // lines/sec/source
	}
	if cfg.PerSourceBurst <= 0 {
		cfg.PerSourceBurst = 1000
	}
	return &Listener{
		cfg: cfg, sources: sources, ingest: ingest, log: log,
		missLog: rate.NewLimiter(1, 5),
		sem:     make(chan struct{}, cfg.MaxConns),
	}
}

// fingerprint is the lowercase hex SHA-256 of a certificate's DER — the source attribution key.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// TLSConfig builds the mTLS server config (exposed for tests). MA-SYS-1: RequireAnyClientCert means a certless
// connection is rejected at the handshake (NOT the RequestClientCert/VerifyClientCertIfGiven footgun that
// silently accepts certless); VerifyPeerCertificate then pins the leaf-cert fingerprint against the registry, so
// an unknown or disabled cert makes the handshake FAIL — rejected, never accepted-then-dropped. (Slice A pins
// the leaf fingerprint; a per-tenant CA + RequireAndVerifyClientCert is the documented scale follow-on.)
func (l *Listener) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{l.cfg.ServerCert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: l.verifyPeer,
	}
}

// verifyPeer runs during the TLS handshake: it fingerprints the presented leaf cert and rejects (aborting the
// handshake) any cert that is not a registered, ENABLED source. Fail-closed on lookup error. A rejected cert is
// logged at platform scope, rate-limited so a flood of bad handshakes can't turn the log into a DoS.
func (l *Listener) verifyPeer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("syslog: no client certificate")
	}
	fp := fingerprint(rawCerts[0])
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	src, ok, err := l.sources.LookupByFingerprint(ctx, fp)
	if err != nil {
		return errors.New("syslog: source lookup failed") // fail-closed
	}
	if !ok {
		// LOW-SYS: an UNREGISTERED cert has no tenant to attribute — keep it a rate-limited PLATFORM-scope
		// Warn (do NOT invent a sentinel tenant to force it into the tenant-scoped audit_log).
		if l.missLog.Allow() {
			l.log.Warn("syslog: rejected unregistered client cert", "fingerprint", fp)
		}
		return errors.New("syslog: client certificate is not a registered source")
	}
	if !src.Enabled {
		// LOW-SYS: a DISABLED/revoked source has a KNOWN tenant — record a data-owner-visible audit (the
		// tenant should see that its disabled source is still trying to connect). Rate-limited.
		if l.missLog.Allow() {
			l.sources.AuditDisabledReject(ctx, src.TenantID, fp)
		}
		return errors.New("syslog: source is disabled")
	}
	return nil
}

// Serve binds the private port and accepts connections until ctx is cancelled.
func (l *Listener) Serve(ctx context.Context) error {
	ln, err := tls.Listen("tcp", l.cfg.BindAddr, l.TLSConfig())
	if err != nil {
		return err
	}
	return l.serve(ctx, ln)
}

// serve runs the accept loop over an already-bound listener. Each connection runs in its own panic-guarded
// goroutine, so a listener-side panic can never take down the HTTP server sharing the process.
func (l *Listener) serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		select {
		case l.sem <- struct{}{}:
			go l.handleConn(ctx, conn.(*tls.Conn))
		default:
			_ = conn.Close() // MA-SYS-4: over the max-connections cap — refuse
		}
	}
}

// handleConn drives one connection: complete the (mTLS-enforced) handshake, bind the tenant from the verified
// cert, then read/parse/ingest lines with per-source rate limiting and periodic source re-checks.
func (l *Listener) handleConn(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()
	defer func() { <-l.sem }()
	safe.Do(l.log, "syslog-conn", func() {
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := conn.HandshakeContext(hctx); err != nil {
			return // MA-SYS-1: certless / unknown-cert / disabled-source rejected HERE, at the handshake
		}
		st := conn.ConnectionState()
		if len(st.PeerCertificates) == 0 {
			return
		}
		fp := fingerprint(st.PeerCertificates[0].Raw)
		src, ok, err := l.sources.LookupByFingerprint(ctx, fp)
		if err != nil || !ok || !src.Enabled {
			return // belt (handshake already enforced); the tenant binding must be authoritative
		}
		tenantID := src.TenantID // MA-SYS-2: attribution is the cert, fixed for the connection's life
		lim := l.limiterFor(fp)
		br := bufio.NewReaderSize(conn, 64*1024)
		lastCheck := time.Now()
		consecFail := 0 // M6: consecutive ingest failures → close on persistent backend outage (backpressure)
		for {
			if ctx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(l.cfg.ReadTimeout))
			msg, rerr := readFrame(br, l.cfg.MaxMessageBytes)
			if rerr != nil {
				if errors.Is(rerr, errOversized) || errors.Is(rerr, errFraming) {
					l.log.Warn("syslog: dropping connection on malformed/oversized frame", "tenant", tenantID)
				}
				return // framing error / EOF / read timeout → close (a byte stream can't be resynced)
			}
			if !lim.Allow() {
				continue // MA-SYS-4: over per-source budget — drop this line, keep serving others
			}
			// MA-SYS-3: re-verify the source is still enabled on a long-lived connection.
			if time.Since(lastCheck) > l.cfg.RecheckInterval {
				if s2, ok2, e2 := l.sources.LookupByFingerprint(ctx, fp); e2 != nil || !ok2 || !s2.Enabled {
					l.log.Warn("syslog: source disabled/removed — closing live connection", "tenant", tenantID)
					return
				}
				lastCheck = time.Now()
			}
			in := parse(msg) // the payload never sets the tenant
			if _, err := l.ingest.Ingest(ctx, tenantID, in); err != nil {
				// M6: never drop a line silently. A TCP syslog source can't retry a line already read off
				// the socket, so a swallowed error = permanent invisible detection-data loss. Count it,
				// log it (rate-limited so a backend blip can't self-DoS the logs), and on a PERSISTENT
				// backend failure close the connection so the sender/queue backs off (TCP backpressure)
				// rather than firehosing into a black hole.
				metrics.SyslogDropped.Inc()
				if l.missLog.Allow() {
					l.log.Warn("syslog: dropping line, ingest failed", "tenant", tenantID, "err", err)
				}
				consecFail++
				if consecFail >= maxConsecIngestFail {
					l.log.Error("syslog: closing connection after repeated ingest failures (backpressure)",
						"tenant", tenantID, "failures", consecFail)
					return
				}
				continue
			}
			consecFail = 0
		}
	})
}

// limiterFor returns the per-source token-bucket limiter, creating it on first use.
func (l *Listener) limiterFor(fp string) *rate.Limiter {
	if v, ok := l.limiters.Load(fp); ok {
		return v.(*rate.Limiter)
	}
	lim := rate.NewLimiter(l.cfg.PerSourceRate, l.cfg.PerSourceBurst)
	actual, _ := l.limiters.LoadOrStore(fp, lim)
	return actual.(*rate.Limiter)
}
