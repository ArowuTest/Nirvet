// Package iam manages users, authentication and RBAC (SRS §6.2). Users are
// tenant-scoped (RLS). Login uses a SECURITY DEFINER lookup so authentication can
// find a user by email without weakening tenant isolation elsewhere (ADR-0001).
package iam

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// UserStatus lifecycle.
type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

// User is a platform user (provider staff or customer user).
type User struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"` // never serialised
	Role         auth.Role  `json:"role"`
	Status       UserStatus `json:"status"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	MFASecret    []byte     `json:"-"` // vault-encrypted TOTP secret; never serialised
	CreatedAt    time.Time  `json:"created_at"`
}
