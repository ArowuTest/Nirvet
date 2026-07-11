package syslogd

import (
	"bufio"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
)

// MA-SYS-3/4 framing + parsing errors. A malformed/oversized frame is dropped and counted; a framing error on
// TCP is unrecoverable (can't resync a byte stream) so the connection is closed.
var (
	errOversized = errors.New("syslog frame exceeds max size")
	errFraming   = errors.New("malformed syslog frame length prefix")
)

// readFrame reads one RFC 6587 octet-counted frame: `MSG-LEN SP SYSLOG-MSG`, where MSG-LEN is the decimal byte
// count of the message. A length that is non-numeric, zero/negative, or exceeds maxBytes is a bounded, fail-safe
// error (never an unbounded read). Octet-counting is used because it is unambiguous and self-bounding — there is
// no oversized-line resync hazard as with newline framing (non-transparent framing = a documented follow-on).
func readFrame(r *bufio.Reader, maxBytes int) ([]byte, error) {
	// Read the length prefix: up to 10 digits then a single space. Anything else is a framing error.
	var digits []byte
	for i := 0; i < 11; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err // EOF / timeout — propagate to close the connection
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' || i == 10 {
			return nil, errFraming
		}
		digits = append(digits, b)
	}
	if len(digits) == 0 {
		return nil, errFraming
	}
	n, err := strconv.Atoi(string(digits))
	if err != nil || n <= 0 {
		return nil, errFraming
	}
	if n > maxBytes {
		// Drain-and-drop is unsafe (we'd have to trust the attacker's length); treat as framing error → close.
		return nil, errOversized
	}
	buf := make([]byte, n)
	if _, err := readFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readFull reads exactly len(buf) bytes or returns the read error.
func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// parse extracts the safe, non-attributional fields of an RFC 5424 message into an IngestInput. It is lenient
// and never panics: anything unparseable falls back to (informational severity, now, raw message in Data). The
// tenant is NEVER derived here — attribution is the mTLS channel (MA-SYS-2); any HOSTNAME/APP-NAME in the
// payload is stored as informational Data only, never used to pick a tenant.
func parse(msg []byte) ingestion.IngestInput {
	in := ingestion.IngestInput{Source: "syslog", Severity: "informational", Data: map[string]any{}}
	s := string(msg)
	in.Data["raw"] = s

	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
	if !strings.HasPrefix(s, "<") {
		return in // not RFC 5424 — keep the raw, informational default
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 5 {
		return in
	}
	pri, err := strconv.Atoi(s[1:end])
	if err == nil && pri >= 0 && pri < 192 {
		in.Severity = severityFromPRI(pri % 8) // low 3 bits = syslog severity
	}
	rest := strings.TrimSpace(s[end+1:])
	fields := strings.SplitN(rest, " ", 7)
	// fields: [VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG...]
	if len(fields) >= 2 && fields[1] != "-" {
		if t, e := time.Parse(time.RFC3339, fields[1]); e == nil {
			in.ObservedAt = t
		}
	}
	if len(fields) >= 3 && fields[2] != "-" {
		in.Data["log_source_host"] = fields[2] // informational ONLY — never used for tenant attribution
	}
	if len(fields) >= 4 && fields[3] != "-" {
		in.Data["app_name"] = fields[3]
		in.ActivityName = fields[3]
	}
	if len(fields) >= 7 {
		in.Data["message"] = fields[6]
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now()
	}
	return in
}

// severityFromPRI maps a syslog severity (0..7) to the platform vocabulary.
func severityFromPRI(sev int) string {
	switch {
	case sev <= 2: // emerg/alert/crit
		return "critical"
	case sev == 3: // err
		return "high"
	case sev == 4: // warning
		return "medium"
	case sev == 5: // notice
		return "low"
	default: // info/debug
		return "informational"
	}
}
