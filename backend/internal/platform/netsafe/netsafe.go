// Package netsafe hardens OUTBOUND HTTP against SSRF. It provides a shared internal-host classifier
// (used at write time to validate a configured URL) and an http.Client whose dialer refuses to
// connect to an internal/loopback/link-local/metadata address AFTER DNS resolution — the send-time,
// post-DNS defence a write-time string check cannot give (it defeats DNS-rebinding, where a name that
// validated as public later resolves to 127.0.0.1 / 169.254.169.254). The notify webhook channels
// dial only through this client; tenant address validation reuses IsInternalHost. Single definition,
// two enforcement points (Round-4 R-5).
package netsafe

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned by the safe dialer when a connection targets an internal address.
var ErrBlockedAddress = errors.New("connection to an internal, loopback, or metadata address is blocked")

// IsInternalHost reports whether a host LITERAL is an internal/loopback/link-local/metadata target.
// A real hostname returns false (its resolved IP is checked at dial time by SafeClient). Numeric
// integer/hex IP encodings (e.g. "2130706433" or "0x7f000001" = 127.0.0.1), which net.ParseIP does
// not recognise, are treated as internal — fail closed.
func IsInternalHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return true
	}
	if isNumericHost(h) {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return isInternalIP(ip)
}

// isInternalIP reports whether a resolved IP is in a blocked range. IsLinkLocalUnicast covers
// 169.254.0.0/16 incl. the 169.254.169.254 cloud metadata endpoint.
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// isNumericHost reports whether a host is an all-digit (decimal integer) or hex (0x…) form that some
// HTTP stacks decode to an IP. A valid dotted IPv4 / IPv6 host contains a dot/colon and is NOT flagged
// here (it parses via net.ParseIP); this only fires on the alternate integer encodings.
func isNumericHost(h string) bool {
	if h == "" || strings.Contains(h, ".") || strings.Contains(h, ":") {
		return false
	}
	if strings.HasPrefix(h, "0x") {
		return true
	}
	for _, c := range h {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SafeClient returns an *http.Client that will not connect to an internal address: the dialer's
// Control hook runs AFTER DNS resolution with the concrete ip:port, and rejects a blocked IP; and
// redirects are disallowed (a 30x to an internal URL is another SSRF vector). timeout bounds the
// whole request.
func SafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip != nil && isInternalIP(ip) {
				return ErrBlockedAddress
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed for outbound notifications")
		},
	}
}
