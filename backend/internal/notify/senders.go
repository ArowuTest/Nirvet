package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// hasHeaderInjection reports whether s carries a CR/LF or other control char that could inject SMTP
// headers when placed in an email Subject/To/From line (CWE-93). Round-5 H2.
func hasHeaderInjection(s string) bool {
	for _, r := range s {
		if r == '\r' || r == '\n' || (r < 0x20 && r != '\t') {
			return true
		}
	}
	return false
}

// Sender is a tenant's per-channel sender configuration (COMM-001). The secret (SMTP password / SMS API
// key) is stored vault-encrypted and never populated on reads returned to callers.
type Sender struct {
	Channel      string `json:"channel"` // email | sms
	FromAddress  string `json:"from_address"`
	SMTPHost     string `json:"smtp_host,omitempty"`
	SMTPPort     int    `json:"smtp_port,omitempty"`
	SMTPUsername string `json:"smtp_username,omitempty"`
	ProviderURL  string `json:"provider_url,omitempty"`
	Enabled      bool   `json:"enabled"`
	HasSecret    bool   `json:"has_secret"` // whether a secret is configured (never the secret itself)

	secret []byte // decrypted secret; only populated internally at send time
}

// SenderRepo persists tenant sender configuration (tenant-scoped).
type SenderRepo struct{ db *database.DB }

// NewSenderRepo builds the repository.
func NewSenderRepo(db *database.DB) *SenderRepo { return &SenderRepo{db: db} }

// Upsert stores a tenant's sender config for a channel (ciphertext already vault-encrypted).
func (r *SenderRepo) Upsert(ctx context.Context, tenantID uuid.UUID, s Sender, ciphertext []byte) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO notification_senders
			   (tenant_id, channel, from_address, smtp_host, smtp_port, smtp_username, provider_url, secret_ciphertext, enabled, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
			 ON CONFLICT (tenant_id, channel) DO UPDATE SET
			   from_address=EXCLUDED.from_address, smtp_host=EXCLUDED.smtp_host, smtp_port=EXCLUDED.smtp_port,
			   smtp_username=EXCLUDED.smtp_username, provider_url=EXCLUDED.provider_url,
			   secret_ciphertext=COALESCE(EXCLUDED.secret_ciphertext, notification_senders.secret_ciphertext),
			   enabled=EXCLUDED.enabled, updated_at=now()`,
			tenantID, s.Channel, s.FromAddress, s.SMTPHost, s.SMTPPort, s.SMTPUsername, s.ProviderURL, ciphertext, s.Enabled)
		return err
	})
}

// List returns a tenant's sender configs (secret omitted; HasSecret set).
func (r *SenderRepo) List(ctx context.Context, tenantID uuid.UUID) ([]Sender, error) {
	var out []Sender
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT channel, from_address, smtp_host, smtp_port, smtp_username, provider_url, enabled,
			        (secret_ciphertext IS NOT NULL)
			   FROM notification_senders ORDER BY channel`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s Sender
			if err := rows.Scan(&s.Channel, &s.FromAddress, &s.SMTPHost, &s.SMTPPort, &s.SMTPUsername,
				&s.ProviderURL, &s.Enabled, &s.HasSecret); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// get loads a tenant's enabled sender for a channel, decrypting the secret via the cipher. Returns
// (nil, nil) when no enabled sender is configured.
func (r *SenderRepo) get(ctx context.Context, cipher crypto.SecretCipher, tenantID uuid.UUID, channel string) (*Sender, error) {
	var s Sender
	var ct []byte
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT channel, from_address, smtp_host, smtp_port, smtp_username, provider_url, enabled, secret_ciphertext
			   FROM notification_senders WHERE channel=$1 AND enabled=true`, channel).
			Scan(&s.Channel, &s.FromAddress, &s.SMTPHost, &s.SMTPPort, &s.SMTPUsername, &s.ProviderURL, &s.Enabled, &ct)
	})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(ct) > 0 {
		plain, derr := cipher.Decrypt(tenantID, ct)
		if derr != nil {
			return nil, fmt.Errorf("decrypt sender secret: %w", derr)
		}
		s.secret = plain
		s.HasSecret = true
	}
	return &s, nil
}

// emailChannel delivers over SMTP using the tenant's configured sender (COMM-001).
type emailChannel struct {
	repo   *SenderRepo
	cipher crypto.SecretCipher
	send   func(addr string, a smtp.Auth, from string, to []string, msg []byte) error // injectable for tests
}

func (c *emailChannel) Key() string { return "email" }

func (c *emailChannel) Send(ctx context.Context, m Message) error {
	if m.TenantID == uuid.Nil {
		return fmt.Errorf("email requires a tenant context")
	}
	s, err := c.repo.get(ctx, c.cipher, m.TenantID, "email")
	if err != nil {
		return err
	}
	if s == nil || s.SMTPHost == "" || s.FromAddress == "" {
		return fmt.Errorf("no email sender configured for tenant")
	}
	if m.To == "" {
		return fmt.Errorf("email has no recipient")
	}
	// Round-5 H2: the Subject/To/From flow into the SMTP DATA header block; a CR/LF in any of them
	// (the Subject derives from untrusted event telemetry via the SLA-breach producer) would inject
	// arbitrary MIME headers (CWE-93). Reject rather than deliver a header-spoofed message.
	if hasHeaderInjection(m.Subject) || hasHeaderInjection(m.To) || hasHeaderInjection(s.FromAddress) {
		return fmt.Errorf("email subject/recipient/from contains illegal control characters")
	}
	addr := s.SMTPHost + ":" + strconv.Itoa(s.SMTPPort)
	var auth smtp.Auth
	if s.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.SMTPUsername, string(s.secret), s.SMTPHost)
	}
	msg := []byte("From: " + s.FromAddress + "\r\n" +
		"To: " + m.To + "\r\n" +
		"Subject: " + m.Subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" +
		m.Body + "\r\n")
	send := c.send
	if send == nil {
		send = boundedSendMail // STARTTLS when advertised, with a hard connection deadline
	}
	return send(addr, auth, s.FromAddress, []string{m.To}, msg)
}

// emailSendDeadline bounds the whole SMTP exchange. It is deliberately below the outbox reclaim
// window (120s) so a hung/slow SMTP server aborts the connection BEFORE a second instance reclaims
// the outbox row — otherwise a late delivery from the stalled send would duplicate the email
// (carry-forward Low). A timeout that only stopped waiting wouldn't help: the abort must close the
// connection so no late delivery can happen.
const emailSendDeadline = 90 * time.Second

// boundedSendMail is smtp.SendMail with a dial timeout + a deadline on the whole exchange, so the
// send can never outlive the outbox reclaim window. STARTTLS is used when the server advertises it.
func boundedSendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return err
	}
	if derr := conn.SetDeadline(time.Now().Add(emailSendDeadline)); derr != nil {
		conn.Close()
		return derr
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if a != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(a); err != nil {
				return err
			}
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// smsChannel delivers over a tenant-configured SMS provider (generic JSON POST, COMM-001).
type smsChannel struct {
	repo   *SenderRepo
	cipher crypto.SecretCipher
	client *http.Client
}

func (c *smsChannel) Key() string { return "sms" }

func (c *smsChannel) Send(ctx context.Context, m Message) error {
	if m.TenantID == uuid.Nil {
		return fmt.Errorf("sms requires a tenant context")
	}
	s, err := c.repo.get(ctx, c.cipher, m.TenantID, "sms")
	if err != nil {
		return err
	}
	if s == nil || s.ProviderURL == "" {
		return fmt.Errorf("no sms sender configured for tenant")
	}
	if m.To == "" {
		return fmt.Errorf("sms has no recipient")
	}
	payload, _ := json.Marshal(map[string]string{"from": s.FromAddress, "to": m.To, "message": m.Body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ProviderURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(s.secret) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(s.secret))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sms provider returned %d", resp.StatusCode)
	}
	return nil
}

// WithSenders registers the real email + SMS channels backed by per-tenant sender config, so an
// email/sms outbox row is delivered (not dead-lettered) once a tenant configures a sender (COMM-001).
// The SMS client should be an outbound HTTP client (SafeClient blocks only internal hosts).
func (s *Service) WithSenders(repo *SenderRepo, cipher crypto.SecretCipher, smsClient *http.Client) *Service {
	s.senders = repo
	s.cipher = cipher
	if smsClient == nil {
		smsClient = DefaultSMSClient() // never leave the SMS channel with an unguarded client (R5-H1)
	}
	s.register(&emailChannel{repo: repo, cipher: cipher})
	s.register(&smsChannel{repo: repo, cipher: cipher, client: smsClient})
	return s
}

// SenderInput configures a tenant sender (COMM-001). Secret is optional on update (kept if omitted).
type SenderInput struct {
	Channel      string `json:"channel"`
	FromAddress  string `json:"from_address"`
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	ProviderURL  string `json:"provider_url"`
	Secret       string `json:"secret"`
	Enabled      *bool  `json:"enabled"`
}

// ConfigureSender validates and stores a tenant's sender config, encrypting the secret via the vault.
func (s *Service) ConfigureSender(ctx context.Context, tenantID uuid.UUID, in SenderInput) error {
	if s.senders == nil || s.cipher == nil {
		return httpx.ErrInternal("sender configuration is not available")
	}
	if in.Channel != "email" && in.Channel != "sms" {
		return httpx.ErrBadRequest("channel must be email or sms")
	}
	sender := Sender{Channel: in.Channel, FromAddress: in.FromAddress, SMTPHost: in.SMTPHost,
		SMTPPort: in.SMTPPort, SMTPUsername: in.SMTPUsername, ProviderURL: in.ProviderURL, Enabled: true}
	if sender.SMTPPort == 0 {
		sender.SMTPPort = 587
	}
	if in.Enabled != nil {
		sender.Enabled = *in.Enabled
	}
	switch in.Channel {
	case "email":
		if in.SMTPHost == "" || in.FromAddress == "" {
			return httpx.ErrBadRequest("email sender requires smtp_host and from_address")
		}
	case "sms":
		if in.ProviderURL == "" {
			return httpx.ErrBadRequest("sms sender requires provider_url")
		}
		// Round-5 H1: validate the provider URL at write time (https + non-internal host) so a
		// manager cannot point SMS delivery at cloud metadata / an internal host. The SafeClient's
		// dial-time resolved-IP check is the DNS-rebinding-proof backstop; this rejects the obvious
		// cases up front with a clear error.
		u, perr := url.Parse(in.ProviderURL)
		if perr != nil || u.Scheme != "https" || u.Host == "" {
			return httpx.ErrBadRequest("sms provider_url must be an absolute https URL")
		}
		if netsafe.IsInternalHost(u.Hostname()) {
			return httpx.ErrBadRequest("sms provider_url must not target an internal or metadata address")
		}
	}
	var ciphertext []byte
	if in.Secret != "" {
		ct, err := s.cipher.Encrypt(tenantID, []byte(in.Secret))
		if err != nil {
			return httpx.ErrInternal("could not encrypt secret")
		}
		ciphertext = ct
	}
	if err := s.senders.Upsert(ctx, tenantID, sender, ciphertext); err != nil {
		return httpx.ErrInternal("could not save sender")
	}
	return nil
}

// ListSenders returns a tenant's configured senders (secrets never included).
func (s *Service) ListSenders(ctx context.Context, tenantID uuid.UUID) ([]Sender, error) {
	if s.senders == nil {
		return nil, nil
	}
	return s.senders.List(ctx, tenantID)
}

// DefaultSMSClient is the outbound client for SMS providers. It is SSRF-safe by construction (Round-5
// H1): the same netsafe.SafeClient the webhook/Teams/Slack channels use — a dial-time resolved-IP block
// (DNS-rebinding-proof) plus redirect refusal — so an SMS provider_url can never reach an internal or
// metadata address even if write-time validation is bypassed.
func DefaultSMSClient() *http.Client { return netsafe.SafeClient(10 * time.Second) }
