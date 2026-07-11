package pdfrender

// PDF renderer guarantees (gate must-adds):
//   PDF-2 sanitize strips control/bidi/non-ASCII; PDF-3 page ceiling; PDF-6 no active-content PDF tokens;
//   PDF-8 deterministic bytes. These tests ARE the acceptance artifact the reviewer asked for.

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var fixedDate = time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

func sampleDoc() Doc {
	return Doc{
		Title:     "Service Review",
		Columns:   []string{"metric", "value"},
		Meta:      [][2]string{{"tenant", "t-1"}, {"scope", "tenant"}},
		Rows:      [][]string{{"open_incidents", "3"}, {"mttr_seconds", "5400"}},
		CreatedAt: fixedDate,
	}
}

// PDF-8: identical input → identical bytes (reproducible evidence-pack hashing).
func TestRender_Deterministic(t *testing.T) {
	a, err := Render(sampleDoc())
	if err != nil {
		t.Fatalf("render a: %v", err)
	}
	b, err := Render(sampleDoc())
	if err != nil {
		t.Fatalf("render b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("PDF-8: two renders of the same Doc must be byte-identical (got %d vs %d bytes)", len(a), len(b))
	}
	if !bytes.HasPrefix(a, []byte("%PDF-")) {
		t.Fatalf("output must be a PDF (missing %%PDF- header)")
	}
}

// PDF-6: the produced PDF carries no active-content ACTION dictionary. The renderer never calls an fpdf API that
// adds a link, annotation, or action, so these PDF name tokens — which live in object dictionaries, not in the
// (compressed) text stream — must be absent. Adversarial cell data (injection payloads) is drawn as inert Tj text
// and cannot manufacture a dictionary key; this test guards against a future regression that structurally adds one
// (e.g. someone wiring a clickable link → /URI + /Annots would appear and fail here).
func TestRender_NoActiveContentTokens(t *testing.T) {
	d := sampleDoc()
	d.Title = "Quarterly <script>alert(1)</script> review"
	d.Rows = append(d.Rows,
		[]string{"javascript:alert(1)", "=WEBSERVICE(\"http://evil\")"},
		[]string{"..\\..\\windows\\system32", "‮spoofed‬ order"},
	)
	out, err := Render(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// Active-content / action tokens the renderer must never emit. NOTE: go-pdf/fpdf structurally writes an EMPTY
	// "/Names << /EmbeddedFiles << /Names [ ] >> >>" container in the catalog even with no attachment, so we do NOT
	// grep the inert "/EmbeddedFile" string; a REAL file attachment instead emits "/Type /Filespec" + "/EF", so the
	// absence of "/Filespec" is the precise "no embedded file" guard.
	forbidden := []string{"/JavaScript", "/Launch", "/URI", "/OpenAction", "/Annots", "/AA", "/RichMedia", "/Filespec"}
	for _, tok := range forbidden {
		if bytes.Contains(out, []byte(tok)) {
			t.Fatalf("PDF-6: produced PDF must not contain active-content token %q", tok)
		}
	}
	// The EmbeddedFiles names tree must be present-but-EMPTY (no actual attachment).
	if bytes.Contains(out, []byte("/EmbeddedFiles")) && bytes.Contains(out, []byte("/EF")) {
		t.Fatal("PDF-6: EmbeddedFiles names tree must be empty (no /EF attachment)")
	}
}

// PDF-3: a document that overflows the page ceiling is refused (not silently truncated).
func TestRender_PageCeiling(t *testing.T) {
	d := sampleDoc()
	d.MaxPages = 1
	rows := make([][]string, 0, 4000)
	for i := 0; i < 4000; i++ {
		rows = append(rows, []string{"row", "x"})
	}
	d.Rows = rows
	if _, err := Render(d); err == nil {
		t.Fatal("PDF-3: a document exceeding the page ceiling must be refused")
	}
}

// PDF-2: sanitize strips CR/LF, C0/C1 controls, Unicode bidi overrides, and non-ASCII, and bounds length.
func TestSanitize(t *testing.T) {
	if got := sanitize("a\r\nb\tc"); got != "a??b c" {
		// CR and LF are non-printable, non-space controls → '?'; TAB → space.
		t.Fatalf("control handling: %q", got)
	}
	if got := sanitize("x‮y⁦z"); got != "x?y?z" {
		t.Fatalf("bidi overrides must be stripped: %q", got)
	}
	if got := sanitize("café"); got != "caf?" {
		t.Fatalf("non-ASCII must be replaced: %q", got)
	}
	long := strings.Repeat("a", maxCellRunes+50)
	if got := sanitize(long); len(got) != maxCellRunes {
		t.Fatalf("length must be bounded to %d, got %d", maxCellRunes, len(got))
	}
}
