// Package branding is the operator white-label config (Ghana operator L). INSTANCE-level presentation only —
// a singleton (operator name, logo, primary color, support email) served publicly to the login page and app
// chrome, managed by padmin. It is NOT per-tenant data and never touches the tenant isolation model. Inputs are
// validated (https/relative logo only, #RRGGBB color, bounded lengths) so a branding value can't become an
// XSS/CSS-injection vector even though only padmin can set it (defense in depth).
package branding

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
)

// Branding is the instance's white-label presentation config.
type Branding struct {
	OperatorName string    `json:"operator_name"`
	LogoURL      string    `json:"logo_url"`
	PrimaryColor string    `json:"primary_color"`
	SupportEmail string    `json:"support_email"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Input is a branding update (padmin).
type Input struct {
	OperatorName string `json:"operator_name"`
	LogoURL      string `json:"logo_url"`
	PrimaryColor string `json:"primary_color"`
	SupportEmail string `json:"support_email"`
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Service reads/writes the singleton branding row.
type Service struct{ db *database.DB }

// NewService wires the branding service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// Get returns the instance branding (the seeded singleton always exists). Read under WithSystem — instance-level
// config, no per-tenant scope.
func (s *Service) Get(ctx context.Context) (Branding, error) {
	var b Branding
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT operator_name, logo_url, primary_color, support_email, updated_at FROM instance_branding WHERE singleton`).
			Scan(&b.OperatorName, &b.LogoURL, &b.PrimaryColor, &b.SupportEmail, &b.UpdatedAt)
	})
	return b, err
}

// Set validates and updates the singleton branding row (padmin). Returns the new value.
func (s *Service) Set(ctx context.Context, in Input) (Branding, error) {
	if err := validate(in); err != nil {
		return Branding{}, err
	}
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE instance_branding SET operator_name=$1, logo_url=$2, primary_color=$3, support_email=$4, updated_at=now()
			  WHERE singleton`,
			strings.TrimSpace(in.OperatorName), in.LogoURL, in.PrimaryColor, strings.TrimSpace(in.SupportEmail))
		return e
	})
	if err != nil {
		return Branding{}, httpx.ErrInternal("could not update branding")
	}
	return s.Get(ctx)
}

// validate enforces safe, bounded branding values.
func validate(in Input) error {
	if strings.TrimSpace(in.OperatorName) == "" || len(in.OperatorName) > 100 {
		return httpx.ErrBadRequest("operator_name is required and must be <= 100 chars")
	}
	if !validLogoURL(in.LogoURL) {
		return httpx.ErrBadRequest("logo_url must be empty, an https URL, or a site-relative path (no javascript:/data:/http)")
	}
	if in.PrimaryColor != "" && !colorRe.MatchString(in.PrimaryColor) {
		return httpx.ErrBadRequest("primary_color must be a #RRGGBB hex value")
	}
	if in.SupportEmail != "" {
		if len(in.SupportEmail) > 200 || !strings.Contains(in.SupportEmail, "@") || strings.ContainsAny(in.SupportEmail, " \t\r\n") {
			return httpx.ErrBadRequest("support_email is not a valid address")
		}
	}
	return nil
}

// validLogoURL accepts empty, a site-relative path (/logo.png, not //host), or an absolute https URL — but
// never javascript:/data:/http or a protocol-relative // URL (all XSS/mixed-content vectors).
func validLogoURL(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 2048 {
		return false
	}
	if strings.HasPrefix(s, "//") {
		return false // protocol-relative — could load over http
	}
	if strings.HasPrefix(s, "/") {
		return true // site-relative asset path
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}
