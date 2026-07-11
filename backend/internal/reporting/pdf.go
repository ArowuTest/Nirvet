package reporting

// PDF export (§6.13 launch-line, HEAVY tier). The renderer lives in the fenced sub-package internal/reporting/
// pdfrender (pure-Go, zero-egress — see its doc + scripts/check-pdf-render-fence.sh). This file is the thin,
// deterministic adapter from a typed Dataset to pdfrender.Doc. Determinism (PDF-5/PDF-8) requires a stable input:
// the REP-003 meta map is emitted in SORTED key order, and the creation date is taken from the report's own
// generated_at (never wall-clock), so identical content renders to identical bytes for evidence-pack hashing.

import (
	"sort"
	"strconv"
	"time"

	"github.com/ArowuTest/nirvet/internal/reporting/pdfrender"
)

// cellText renders a typed cell to its display string. Unlike the CSV path it does NOT prefix formula triggers —
// the PDF is not a spreadsheet, and pdfrender sanitizes every string at the draw boundary regardless.
func cellText(c Cell) string {
	switch c.Kind {
	case KindString:
		return c.S
	case KindNumber:
		return strconv.FormatFloat(c.N, 'f', -1, 64)
	case KindTime:
		return c.T.UTC().Format(time.RFC3339)
	case KindBool:
		return strconv.FormatBool(c.B)
	default:
		return ""
	}
}

// renderReportPDF converts a Dataset to deterministic PDF bytes via the fenced renderer.
func renderReportPDF(ds Dataset) ([]byte, error) {
	// Creation date from the report's own generated_at (deterministic); zero time if absent/unparseable.
	var created time.Time
	if v, ok := ds.Meta["generated_at"]; ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			created = t
		}
	}
	// Ordered meta (sorted keys) so map iteration order can't perturb the bytes.
	keys := make([]string, 0, len(ds.Meta))
	for k := range ds.Meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	doc := pdfrender.Doc{
		Title:     ds.Title,
		Columns:   append([]string(nil), ds.Columns...),
		CreatedAt: created,
	}
	for _, k := range keys {
		doc.Meta = append(doc.Meta, [2]string{k, ds.Meta[k]})
	}
	for _, row := range ds.Rows {
		r := make([]string, len(row))
		for i, c := range row {
			r[i] = cellText(c)
		}
		doc.Rows = append(doc.Rows, r)
	}
	return pdfrender.Render(doc)
}
