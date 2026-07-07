package iam

import (
	"context"
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
	repo   *Repository
	db     *database.DB
	tokens *auth.Manager
	cipher crypto.SecretCipher
}

// NewService builds the service. cipher encrypts TOTP secrets (per-tenant).
func NewService(repo *Repository, db *database.DB, tokens *auth.Manager, cipher crypto.SecretCipher) *Service {
	return &Service{repo: repo, db: db, tokens: tokens, cipher: cipher}
}

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

// LoginResult carries the issued token and principal.
type LoginResult struct {
	Token     string        `json:"token"`
	Principal auth.Principal `json:"-"`
	User      *User         `json:"user"`
}

// Login authenticates by email+password (and TOTP MFA when enabled) and issues
// an access token.
func (s *Service) Login(ctx context.Context, email, password, mfaCode, requestID string) (*LoginResult, error) {
	u, err := s.repo.FindForAuth(ctx, email)
	if err != nil || u.Status != UserActive || !auth.ComparePassword(u.PasswordHash, password) {
		return nil, httpx.ErrUnauthorized("invalid credentials")
	}
	if u.MFAEnabled {
		secret, derr := s.cipher.Decrypt(u.TenantID, u.MFASecret)
		if derr != nil || !totp.Validate(string(secret), mfaCode, time.Now()) {
			return nil, httpx.ErrUnauthorized("invalid or missing MFA code")
		}
	}
	p := auth.Principal{UserID: u.ID, TenantID: u.TenantID, Role: u.Role, Email: u.Email}
	token, err := s.tokens.Issue(p)
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
