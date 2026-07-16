package soar

import "testing"

// The validation here is the whole defence for a deny-list whose failure mode is SILENT: a value the guard cannot
// match doesn't error, doesn't log, and doesn't withhold — it just quietly protects nothing while the UI shows a
// populated list. So each case below is a way an operator could believe they had designated a crown jewel and be
// wrong.

func TestValidateProtectedValue_RejectsWildcards(t *testing.T) {
	// "*" is THE idiom for "everything" in every other tool an operator has used. Here the host guard does
	// strings.Contains(host, pattern) and the identity guard an equality test, so a globbed value matches only a
	// host or UPN literally containing an asterisk — nothing. Accepting it would produce a deny-list that reads as
	// maximally protective and is exactly as protective as an empty one.
	//
	// "*.corp.*" and "dc*" are the important cases, and the ones a naive "is it ENTIRELY wildcards?" check waves
	// through: they look like considered, specific rules, so nobody re-reads them.
	for _, kind := range []ProtectedKind{ProtectedKindHost, ProtectedKindIdentity} {
		for _, v := range []string{"*", "**", "%", "*.*", "?", "*.corp.*", "dc*", "%admin%", "dc0?", "*@corp.gov.gh"} {
			if _, err := validateProtectedValue(kind, v); err == nil {
				t.Errorf("%s: wildcard %q accepted — it would match nothing and protect nothing", kind, v)
			}
		}
	}
}

func TestValidateProtectedValue_AllowsLegalHostAndUPNPunctuation(t *testing.T) {
	// The mirror of the wildcard test, and the reason the glob set is exactly "*?%": dots, dashes and underscores
	// are ordinary in real crown-jewel names. Rejecting them would push operators toward shorter, broader patterns
	// — the opposite of what we want.
	for _, v := range []string{"dc01.corp.gov.gh", "svc_backup", "payroll-db-01", "sql01.corp.gov.gh"} {
		if got, err := validateProtectedValue(ProtectedKindHost, v); err != nil || got != v {
			t.Errorf("host %q rejected (%v) — legal hostname punctuation must be accepted", v, err)
		}
	}
	if got, err := validateProtectedValue(ProtectedKindIdentity, "svc_backup@corp.gov.gh"); err != nil || got != "svc_backup@corp.gov.gh" {
		t.Errorf("UPN with an underscore rejected (%v)", err)
	}
}

func TestValidateProtectedValue_HostSubstringSemantics(t *testing.T) {
	// Hosts match as a substring, so over-broad is fail-safe (more withholds) but a single character disables the
	// tenant's entire containment capability by accident.
	if _, err := validateProtectedValue(ProtectedKindHost, "a"); err == nil {
		t.Error("1-char host pattern accepted: it substring-matches nearly every host and would withhold every isolate")
	}
	for _, v := range []string{"dc", "dc01", "payroll", "sql01.corp.gov.gh"} {
		if got, err := validateProtectedValue(ProtectedKindHost, v); err != nil || got != v {
			t.Errorf("host %q rejected (%v) — it is a legitimate crown-jewel pattern", v, err)
		}
	}
}

func TestValidateProtectedValue_IdentityExactMatchSemantics(t *testing.T) {
	// The identity guard matches EXACTLY (denySet[lower(ref)]). A fragment is therefore worse than useless: it
	// occupies a row in the deny-list while matching no identity the guard will ever see.
	for _, v := range []string{"admin", "glenn", "break-glass", "svc_"} {
		if _, err := validateProtectedValue(ProtectedKindIdentity, v); err == nil {
			t.Errorf("partial identity %q accepted — the identity deny-list matches exactly, so it protects nothing", v)
		}
	}
	// The two forms the guard CAN match: a UPN, and a resolved object id.
	for _, v := range []string{"breakglass@corp.gov.gh", "6f8d1c2e-0b3a-4c5d-8e9f-1a2b3c4d5e6f"} {
		if got, err := validateProtectedValue(ProtectedKindIdentity, v); err != nil || got != v {
			t.Errorf("identity %q rejected (%v) — the guard matches this form", v, err)
		}
	}
}

func TestValidateProtectedValue_TrimsAndBounds(t *testing.T) {
	got, err := validateProtectedValue(ProtectedKindHost, "  dc01  ")
	if err != nil || got != "dc01" {
		t.Fatalf("trim: got %q, %v; want \"dc01\", nil", got, err)
	}
	// Whitespace inside a value can never match a real host/UPN and usually means a paste accident.
	if _, err := validateProtectedValue(ProtectedKindHost, "dc01 dc02"); err == nil {
		t.Error("embedded whitespace accepted: no host ref contains a space, so this would match nothing")
	}
	long := make([]byte, maxProtectedValue+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := validateProtectedValue(ProtectedKindHost, string(long)); err == nil {
		t.Error("over-long value accepted")
	}
	if _, err := validateProtectedValue(ProtectedKindHost, ""); err == nil {
		t.Error("empty value accepted")
	}
}

func TestParseProtectedKind(t *testing.T) {
	for _, s := range []string{"host", "HOST", " identity "} {
		if _, err := ParseProtectedKind(s); err != nil {
			t.Errorf("ParseProtectedKind(%q) = %v; want ok", s, err)
		}
	}
	for _, s := range []string{"", "hosts", "user", "protected_hosts", "../host"} {
		if _, err := ParseProtectedKind(s); err == nil {
			t.Errorf("ParseProtectedKind(%q) accepted an unknown kind", s)
		}
	}
}

// protectedSpecs is the allow-list that lets the repo hold fully-static SQL per kind instead of interpolating a
// table name. If a kind is ever added without its spec, the repo would fall through to a bad-request at runtime
// rather than build a query — but the enum and the map must not drift apart silently.
func TestProtectedSpecs_CoverEveryKind(t *testing.T) {
	for _, k := range []ProtectedKind{ProtectedKindHost, ProtectedKindIdentity} {
		spec, ok := protectedSpecs[k]
		if !ok {
			t.Fatalf("kind %q has no SQL spec", k)
		}
		if spec.list == "" || spec.insert == "" || spec.del == "" {
			t.Errorf("kind %q has an incomplete SQL spec", k)
		}
	}
	if len(protectedSpecs) != 2 {
		t.Errorf("protectedSpecs has %d entries; a new kind needs validation semantics in validateProtectedValue too", len(protectedSpecs))
	}
}
