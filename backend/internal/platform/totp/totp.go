// Package totp implements RFC 6238 time-based one-time passwords using only the
// standard library (no third-party dependency in an auth-critical path).
// 6 digits, 30-second step, SHA-1 (authenticator-app compatible).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new base32-encoded shared secret (160-bit).
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enc.EncodeToString(b), nil
}

// code computes the TOTP for a secret at a given counter.
func code(secret string, counter uint64) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%0*d", digits, val%1_000_000), nil
}

// Code returns the current TOTP for secret at time t (what an authenticator app
// displays). Exposed for clients and tests.
func Code(secret string, t time.Time) (string, error) {
	return code(secret, uint64(t.Unix())/period)
}

// Validate reports whether otp is valid for secret at time t, allowing a ±1 step
// window for clock skew.
func Validate(secret, otp string, t time.Time) bool {
	otp = strings.TrimSpace(otp)
	if len(otp) != digits {
		return false
	}
	counter := uint64(t.Unix()) / period
	for _, c := range []uint64{counter - 1, counter, counter + 1} {
		if want, err := code(secret, c); err == nil && hmacEqual(want, otp) {
			return true
		}
	}
	return false
}

// hmacEqual is a constant-time string compare.
func hmacEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// URI builds an otpauth:// URI for authenticator apps.
func URI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}
