package iam

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Service holds IAM business logic.
type Service struct {
	repo   *Repository
	db     *database.DB
	tokens *auth.Manager
}

// NewService builds the service.
func NewService(repo *Repository, db *database.DB, tokens *auth.Manager) *Service {
	return &Service{repo: repo, db: db, tokens: tokens}
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

// Login authenticates by email+password and issues an access token.
func (s *Service) Login(ctx context.Context, email, password, requestID string) (*LoginResult, error) {
	u, err := s.repo.FindForAuth(ctx, email)
	if err != nil || u.Status != UserActive || !auth.ComparePassword(u.PasswordHash, password) {
		return nil, httpx.ErrUnauthorized("invalid credentials")
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
