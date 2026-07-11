// Package pdfrender renders a report to PDF from typed primitives using a pure-Go, ZERO-EGRESS drawer.
//
// Security posture (PDF export gate, HEAVY tier):
//   - It draws directly with go-pdf/fpdf CORE fonts — no HTML intermediate, no headless browser, no network, no
//     filesystem, no font files, and no os/exec. That eliminates the PDF-generation SSRF/RCE class BY CONSTRUCTION
//     (there is no URL to fetch, no markup to parse, no script/action to emit), the same way the XLSX inline-string
//     serializer eliminates formula injection. The CI import fence (scripts/check-pdf-render-fence.sh) is the teeth:
//     this package's dependency closure must never include net/http, os/exec, or any HTML/headless renderer (PDF-1).
//   - Every cell string is sanitized to printable ASCII, stripping C0/C1 controls, CR/LF, and Unicode bidi-override
//     code points, so no value can carry a layout/spoofing payload (PDF-2). Non-ASCII is replaced (slice-A ASCII-only
//     report text).
//   - No fpdf API that adds external-URI links, annotations, or actions is used — so the produced PDF carries no
//     /URI, /JavaScript, /Launch, /OpenAction, /AA, /EmbeddedFile, or /RichMedia (asserted by test, PDF-6).
//   - Output is DETERMINISTIC: the creation/mod date is fixed by the caller (the report's generated_at) and the core
//     font embeds no subsettable data, so identical input → identical bytes → reproducible evidence-pack hashing
//     (PDF-5/PDF-8). Bounded by a hard page ceiling (PDF-3).
package pdfrender

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// Doc is the sanitized, typed input to a render. Every string is drawn verbatim (after internal sanitization);
// no value is ever interpreted as markup, a link, or an action. Meta is an ordered slice (not a map) so the
// output is deterministic.
type Doc struct {
	Title     string
	Columns   []string
	Rows      [][]string
	Meta      [][2]string
	CreatedAt time.Time // fixed by the caller (report ready time) → deterministic, reproducible bytes
	MaxPages  int       // hard page ceiling (0 → default)
}

const (
	maxCellRunes   = 512
	defaultMaxPage = 200
)

// Render draws the document to PDF bytes. Pure computation: no I/O of any kind.
func Render(d Doc) ([]byte, error) {
	if len(d.Columns) == 0 {
		return nil, errors.New("pdfrender: no columns")
	}
	maxPages := d.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPage
	}

	pdf := fpdf.New("P", "mm", "A4", "") // "" font dir → CORE fonts only, never touches the filesystem
	// DETERMINISM (PDF-8): fpdf emits its font objects by ranging over an internal map, and Go randomizes map
	// iteration order — so with >1 font (we use Helvetica + Helvetica-Bold) the object order, and thus the bytes,
	// vary run-to-run unless catalogSort is enabled. SetCatalogSort forces a stable sorted order → byte-identical
	// output for evidence-pack hashing. Compression is left off (its content-stream ordering is a second, avoidable
	// source of drift), which does not affect inertness — the renderer emits no action dictionaries regardless.
	pdf.SetCatalogSort(true)
	// Deterministic document metadata: fixed dates + fixed producer (no wall-clock, no fpdf-version drift).
	pdf.SetCreationDate(d.CreatedAt.UTC())
	pdf.SetModificationDate(d.CreatedAt.UTC())
	pdf.SetProducer("Nirvet", false)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Title.
	pdf.SetFont("Helvetica", "B", 16)
	pdf.MultiCell(0, 8, sanitize(d.Title), "", "L", false)
	pdf.Ln(2)

	// REP-003 metadata header (ordered).
	pdf.SetFont("Helvetica", "", 8)
	for _, kv := range d.Meta {
		pdf.MultiCell(0, 4, sanitize(kv[0])+": "+sanitize(kv[1]), "", "L", false)
	}
	pdf.Ln(3)

	// Table geometry.
	nCols := len(d.Columns)
	pageW, _ := pdf.GetPageSize()
	lm, _, rm, _ := pdf.GetMargins()
	colW := (pageW - lm - rm) / float64(nCols)

	// Header row (drawn as plain cells with borders — no links/annotations/actions).
	pdf.SetFont("Helvetica", "B", 9)
	for _, c := range d.Columns {
		pdf.CellFormat(colW, 6, sanitize(c), "1", 0, "L", false, 0, "")
	}
	pdf.Ln(-1)

	// Data rows.
	pdf.SetFont("Helvetica", "", 9)
	for _, row := range d.Rows {
		for i := 0; i < nCols; i++ {
			v := ""
			if i < len(row) {
				v = sanitize(row[i])
			}
			pdf.CellFormat(colW, 5, v, "1", 0, "L", false, 0, "")
		}
		pdf.Ln(-1)
		if pdf.PageCount() > maxPages {
			return nil, errors.New("pdfrender: exceeds page ceiling")
		}
	}

	if err := pdf.Error(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sanitize restricts a cell to printable ASCII and strips control + Unicode bidi-override characters, so no cell
// value can carry a layout/spoofing payload into the PDF. TAB and any space become a plain space; printable ASCII
// (0x20–0x7E) passes; everything else — all C0/C1 controls, CR/LF, DEL, bidi overrides (U+202A–202E, U+2066–2069,
// U+200E/200F) and every non-ASCII rune — is replaced with an inert '?'. Length-bounded to maxCellRunes.
func sanitize(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxCellRunes {
			break
		}
		switch {
		case r == '\t' || r == ' ':
			b.WriteByte(' ')
		case r >= 0x20 && r <= 0x7E:
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
		n++
	}
	return b.String()
}
