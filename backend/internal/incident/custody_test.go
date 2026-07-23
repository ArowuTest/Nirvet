package incident

// safeArticleURL is the authoritative guard against a stored-XSS KB "Reference URL": the value is rendered as a
// clickable <a href> in the console, so a javascript:/data: URL there would execute in a victim's authenticated
// session. Rejecting non-http(s) schemes at write time means a malicious scheme can never be persisted. Empty is
// allowed (no reference). This is a pure unit test — no DB.

import "testing"

func TestSafeArticleURL(t *testing.T) {
	ok := []string{
		"",
		"   ",
		"https://runbook.example.com/phishing",
		"http://intranet.local/kb/42",
		"HTTPS://Example.com/Path?q=1", // scheme is case-insensitive
	}
	for _, in := range ok {
		if _, err := safeArticleURL(in); err != nil {
			t.Fatalf("safeArticleURL(%q) should be allowed, got error: %v", in, err)
		}
	}

	// The XSS vectors + other non-web schemes must all be rejected.
	bad := []string{
		"javascript:alert(document.cookie)",
		"JavaScript:alert(1)",     // case-obfuscated
		"  javascript:alert(1)  ", // whitespace-padded (trimmed then checked)
		"data:text/html,<script>1</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://host/x",
	}
	for _, in := range bad {
		if _, err := safeArticleURL(in); err == nil {
			t.Fatalf("safeArticleURL(%q) must be REJECTED (stored-XSS / non-web scheme)", in)
		}
	}

	// A safe URL is returned trimmed + verbatim (no mutation of an accepted value).
	got, err := safeArticleURL("  https://x.test/y  ")
	if err != nil || got != "https://x.test/y" {
		t.Fatalf("safeArticleURL trim: got %q err %v", got, err)
	}
}
