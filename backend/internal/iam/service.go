package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/totp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Service holds IAM business logic.
type Service struct {
	repo    *Repository
	db      *database.DB
	tokens  *auth.Manager
	cipher  crypto.SecretCipher
	alerter Alerter // optional: break-glass auto-alerting (§6.2 IAM-006)
}

// NewService builds the service. cipher encrypts TOTP secrets (per-tenant).
func NewService(repo *Repository, db *database.DB, tokens *auth.Manager, cipher crypto.SecretCipher) *Service {
	return &Service{repo: repo, db: db, tokens: tokens, cipher: cipher}
}

// Alerter fires an automatic alert (implemented by notify.Service). Kept narrow so iam does
// not depend on the notify package.
type Alerter interface {
	NotifyIncident(ctx context.Context, tenantID uuid.UUID, subject, body string) error
}

// WithAlerter wires break-glass auto-alerting (§6.2 IAM-006).
func (s *Service) WithAlerter(a Alerter) *Service { s.alerter = a; return s }

// CreateInput creates a user.
type CreateInput struct {
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Role     auth.Role `json:"role"`
}

// Create provisions a user in the given tenant.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*User, error) {
	if in.Email == "" || in.Password == "" {
		return nil, httpx.ErrBadRequest("email and password are required")
	}
	if len(in.Password) < 8 {
		return nil, httpx.ErrBadRequest("password must be at least 8 characters")
	}
	if in.Role == "" {
		return nil, httpx.ErrBadRequest("role is required")
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	u := &User{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Email:        in.Email,
		PasswordHash: hash,
		Role:         in.Role,
		Status:       UserActive,
	}
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, httpx.ErrConflict("could not create user (email may already exist)")
	}
	return u, nil
}

// LookupForSSO finds a user by email across tenants for the SSO flow. It returns
// ok=false (nil error) when no user exists, so the caller can JIT-provision.
// Satisfies sso.Directory.
func (s *Service) LookupForSSO(ctx context.Context, email string) (id, tenantID uuid.UUID, role string, ok bool, err error) {
	u, ferr := s.repo.FindForAuth(ctx, email)
	if ferr != nil {
		if errors.Is(ferr, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, "", false, nil
		}
		return uuid.Nil, uuid.Nil, "", false, ferr
	}
	return u.ID, u.TenantID, string(u.Role), true, nil
}

// ProvisionForSSO just-in-time creates an SSO user in the tenant with the given
// role and a random (non-loginable) password — SSO users authenticate at the IdP,
// not with a local password. Satisfies sso.Directory (IAM-008 provisioning).
func (s *Service) ProvisionForSSO(ctx context.Context, tenantID uuid.UUID, email, role string) (uuid.UUID, error) {
	rnd := make([]byte, 24)
	if _, err := rand.Read(rnd); err != nil {
		return uuid.Nil, err
	}
	u, err := s.Create(ctx, tenantID, CreateInput{
		Email:    email,
		Password: base64.RawURLEncoding.EncodeToString(rnd),
		Role:     auth.Role(role),
	})
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

// LoginResult carries the issued token and principal.
type LoginResult struct {
	Token     string         `json:"token"`
	Principal auth.Principal `json:"-"`
	User      *User          `json:"user"`
}

// Brute-force lockout policy (SEC). After maxFailedLogins consecutive failed attempts
// the account is locked for loginLockWindow. This is the durable, instance-independent
// control that catches distributed attacks (many IPs, one account) which per-IP rate
// limiting misses.
const (
	maxFailedLogins = 5
	loginLockWindow = 15 * time.Minute
)

// Login authenticates by email+password (and TOTP MFA when enabled) and issues an
// access token. Repeated failures lock the account for a cool-off window.
func (s *Service) Login(ctx context.Context, email, password, mfaCode, requestID string) (*LoginResult, error) {
	u, err := s.repo.FindForAuth(ctx, email)
	if err != nil || u.Status != UserActive {
		// No such (active) user — generic error, no account enumeration and no lock.
		return nil, httpx.ErrUnauthorized("invalid credentials")
	}
	// If the account is locked, reject WITHOUT checking the password (so an attacker
	// cannot keep probing) until the cool-off elapses.
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		return nil, httpx.ErrTooManyRequests("account temporarily locked due to repeated failed logins; try again later")
	}
	if !auth.ComparePassword(u.PasswordHash, password) {
		_ = s.repo.RecordLoginFailure(ctx, u.TenantID, u.ID, maxFailedLogins, loginLockWindow)
		return nil, httpx.ErrUnauthorized("invalid credentials")
	}
	if u.MFAEnabled {
		secret, derr := s.cipher.Decrypt(u.TenantID, u.MFASecret)
		if derr != nil || !totp.Validate(string(secret), mfaCode, time.Now()) {
			// A wrong/absent MFA code counts toward lockout — brute-forcing the 6-digit
			// code is a login failure just like a wrong password.
			_ = s.repo.RecordLoginFailure(ctx, u.TenantID, u.ID, maxFailedLogins, loginLockWindow)
			return nil, httpx.ErrUnauthorized("invalid or missing MFA code")
		}
	}
	// Success: clear any accumulated failures and the lock.
	_ = s.repo.ResetLoginFailures(ctx, u.TenantID, u.ID)
	p := auth.Principal{UserID: u.ID, TenantID: u.TenantID, Role: u.Role, Email: u.Email}
	// Issue the token with the tenant's configured session TTL (§6.2 IAM-007) — not a
	// hardcoded lifetime. sessionTTL returns 0 (=> manager default) if unconfigured.
	token, err := s.tokens.IssueWithTTL(p, s.sessionTTL(ctx, u.TenantID))
	if err != nil {
		return nil, err
	}
	// Audit the login within the user's tenant context.
	_ = s.db.WithTenant(ctx, u.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: u.ID, ActorEmail: u.Email, Action: "auth.login",
			Target: "user:" + u.ID.String(), RequestID: requestID,
		})
	})
	u.PasswordHash = ""
	return &LoginResult{Token: token, Principal: p, User: u}, nil
}

// ChangePassword lets an authenticated user rotate their own password. The current
// password must be supplied and verified (so a stolen session token alone cannot
// silently reset it), the new one must meet the length policy and differ from the
// old. This is the supported path off the default bootstrap credential (IAM-002).
func (s *Service) ChangePassword(ctx context.Context, p auth.Principal, current, newPassword string) error {
	if current == "" || newPassword == "" {
		return httpx.ErrBadRequest("current_password and new_password are required")
	}
	if len(newPassword) < 8 {
		return httpx.ErrBadRequest("new password must be at least 8 characters")
	}
	if current == newPassword {
		return httpx.ErrBadRequest("new password must differ from the current password")
	}
	u, err := s.repo.GetByID(ctx, p.TenantID, p.UserID)
	if err != nil {
		return httpx.ErrNotFound("user not found")
	}
	if !auth.ComparePassword(u.PasswordHash, current) {
		return httpx.ErrUnauthorized("current password is incorrect")
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return httpx.ErrInternal("could not hash password")
	}
	if err := s.repo.UpdatePassword(ctx, p.TenantID, p.UserID, hash); err != nil {
		return httpx.ErrInternal("could not update password")
	}
	return nil
}

// Me returns the current user.
func (s *Service) Me(ctx context.Context, p auth.Principal) (*User, error) {
	u, err := s.repo.GetByID(ctx, p.TenantID, p.UserID)
	if err != nil {
		return nil, httpx.ErrNotFound("user not found")
	}
	u.PasswordHash = ""
	return u, nil
}

// LookupInTenant returns a user's email if they belong to the given tenant, else
// an error. It satisfies incident.Assignees so an incident can only be assigned to
// an analyst in the same tenant (the GetByID query runs under tenant RLS).
func (s *Service) LookupInTenant(ctx context.Context, tenantID, userID uuid.UUID) (string, error) {
	u, err := s.repo.GetByID(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	return u.Email, nil
}

// EnrollMFA generates a TOTP secret for the user, stores it encrypted (pending),
// and returns the otpauth URI + secret to show once. MFA is not active until the
// user confirms a code via Activate.
func (s *Service) EnrollMFA(ctx context.Context, p auth.Principal) (uri, secret string, err error) {
	secret, err = totp.GenerateSecret()
	if err != nil {
		return "", "", httpx.ErrInternal("could not generate secret")
	}
	sealed, err := s.cipher.Encrypt(p.TenantID, []byte(secret))
	if err != nil {
		return "", "", httpx.ErrInternal("could not seal secret")
	}
	if err := s.repo.SetMFASecret(ctx, p.TenantID, p.UserID, sealed); err != nil {
		return "", "", httpx.ErrInternal("could not store secret")
	}
	return totp.URI(secret, p.Email, "Nirvet"), secret, nil
}

// ActivateMFA verifies a code against the pending secret and enables MFA.
func (s *Service) ActivateMFA(ctx context.Context, p auth.Principal, code string) error {
	u, err := s.repo.GetByID(ctx, p.TenantID, p.UserID)
	if err != nil || len(u.MFASecret) == 0 {
		return httpx.ErrBadRequest("enroll MFA first")
	}
	secret, err := s.cipher.Decrypt(p.TenantID, u.MFASecret)
	if err != nil || !totp.Validate(string(secret), code, time.Now()) {
		return httpx.ErrBadRequest("invalid code")
	}
	if err := s.repo.SetMFAEnabled(ctx, p.TenantID, p.UserID, true); err != nil {
		return httpx.ErrInternal("could not enable MFA")
	}
	return nil
}

// DisableMFA turns MFA off after verifying a current code.
func (s *Service) DisableMFA(ctx context.Context, p auth.Principal, code string) error {
	u, err := s.repo.GetByID(ctx, p.TenantID, p.UserID)
	if err != nil {
		return httpx.ErrNotFound("user not found")
	}
	if u.MFAEnabled {
		secret, derr := s.cipher.Decrypt(p.TenantID, u.MFASecret)
		if derr != nil || !totp.Validate(string(secret), code, time.Now()) {
			return httpx.ErrBadRequest("invalid code")
		}
	}
	if err := s.repo.SetMFAEnabled(ctx, p.TenantID, p.UserID, false); err != nil {
		return httpx.ErrInternal("could not disable MFA")
	}
	return nil
}
