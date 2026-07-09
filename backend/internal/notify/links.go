package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Secure expiring links (COMM-009): a stateless, signed token binding a tenant + resource reference to
// an expiry. The token is HMAC-SHA256 over "tenant|resource|exp" with the server link key, so it cannot
// be forged or have its expiry extended without the key, and it needs no server-side storage. Format:
//   base64url(tenant|resource|exp) "." base64url(hmac)
// Use for time-boxed access to an evidence pack / report embedded in a notification.

var errBadLink = errors.New("invalid or expired link")

// maxLinkTTL caps how far in the future a secure link may be valid.
const maxLinkTTL = 7 * 24 * time.Hour

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, s.linkKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// GenerateLink mints a secure expiring link token for a resource, valid for ttl (clamped to maxLinkTTL).
// now is passed in so the caller controls the clock (and tests are deterministic).
func (s *Service) GenerateLink(tenantID uuid.UUID, resource string, ttl time.Duration, now time.Time) (string, error) {
	if len(s.linkKey) == 0 {
		return "", httpx.ErrInternal("secure links are not configured")
	}
	if resource == "" {
		return "", httpx.ErrBadRequest("resource is required")
	}
	if ttl <= 0 || ttl > maxLinkTTL {
		ttl = maxLinkTTL
	}
	exp := now.Add(ttl).Unix()
	payload := tenantID.String() + "|" + resource + "|" + strconv.FormatInt(exp, 10)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + s.sign(payload)
	return token, nil
}

// VerifyLink validates a token and returns the tenant + resource if the signature is valid and the link
// has not expired. Constant-time signature comparison. now is injected for testability.
func (s *Service) VerifyLink(token string, now time.Time) (tenantID uuid.UUID, resource string, err error) {
	if len(s.linkKey) == 0 {
		return uuid.Nil, "", httpx.ErrInternal("secure links are not configured")
	}
	dot := strings.LastIndexByte(token, '.')
	if dot <= 0 {
		return uuid.Nil, "", errBadLink
	}
	raw, derr := base64.RawURLEncoding.DecodeString(token[:dot])
	if derr != nil {
		return uuid.Nil, "", errBadLink
	}
	payload := string(raw)
	if !hmac.Equal([]byte(token[dot+1:]), []byte(s.sign(payload))) {
		return uuid.Nil, "", errBadLink
	}
	// R6: the payload is tenant|resource|exp with tenant first and exp last; the RESOURCE may
	// itself contain '|'. Split on the first and last delimiter (not strings.Split, which would
	// reject an otherwise-valid signed token whose resource has a pipe) so resource is the middle.
	firstPipe := strings.IndexByte(payload, '|')
	lastPipe := strings.LastIndexByte(payload, '|')
	if firstPipe <= 0 || lastPipe <= firstPipe {
		return uuid.Nil, "", errBadLink
	}
	tidStr, resourceStr, expStr := payload[:firstPipe], payload[firstPipe+1:lastPipe], payload[lastPipe+1:]
	exp, cerr := strconv.ParseInt(expStr, 10, 64)
	if cerr != nil || now.Unix() > exp {
		return uuid.Nil, "", errBadLink
	}
	tid, perr := uuid.Parse(tidStr)
	if perr != nil || resourceStr == "" {
		return uuid.Nil, "", errBadLink
	}
	return tid, resourceStr, nil
}
