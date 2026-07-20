package reporting

// §6.13 #125 R-3 — the export-security unit tests (pure, no DB). The headline: a formula NEVER survives into a
// tabular export, and a legitimate number is NEVER corrupted.

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func csvOf(t *testing.T, ds Dataset) string {
	t.Helper()
	b, err := ToCSV(ds)
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	return string(b)
}

// CSV: a string cell starting with a formula trigger is neutralized; a numeric cell is written native (not corrupted).
func TestCSV_TypeAwareNeutralization(t *testing.T) {
	ds := Dataset{
		Columns: []string{"note", "amount"},
		Rows: [][]Cell{
			{Str("=SUM(A1:A9)"), Num(-5)}, // hostile string + legit negative number
			{Str("-cmd|calc"), Num(42)},   // -leading STRING is a trigger → neutralize
			{Str("plain"), Num(3.5)},
		},
	}
	out := csvOf(t, ds)
	if !strings.Contains(out, "'=SUM(A1:A9)") {
		t.Fatalf("formula string must be neutralized with a leading quote:\n%s", out)
	}
	if !strings.Contains(out, "'-cmd|calc") {
		t.Fatalf("a -leading STRING must be neutralized:\n%s", out)
	}
	// The legit negative number must NOT be corrupted to '-5 (reviewer refinement #1).
	if strings.Contains(out, "'-5") {
		t.Fatalf("a numeric -5 must stay native, not become '-5:\n%s", out)
	}
	if !strings.Contains(out, "-5") {
		t.Fatalf("the native number -5 must be present:\n%s", out)
	}
}

// XLSX: a hostile string is an INLINE STRING (formula-proof by type); a number is a native cell; nothing is a formula.
// DOCX is a valid WordprocessingML zip; a string value is xml-escaped into document.xml (never breaks the markup),
// and numbers render as text. A Word document has no formula concept, so there is nothing to formula-neutralize.
func TestDOCX_ValidZipAndXMLEscaped(t *testing.T) {
	ds := Dataset{
		Title:   "Service Review",
		Meta:    map[string]string{"scope": "tenant"},
		Columns: []string{"metric", "value"},
		Rows:    [][]Cell{{Str("note<script>&"), Num(42)}},
	}
	b, err := ToDOCX(ds)
	if err != nil {
		t.Fatalf("docx: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a valid zip/docx: %v", err)
	}
	var doc, hasCT bool
	var docXML string
	for _, f := range zr.File {
		switch f.Name {
		case "word/document.xml":
			doc = true
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			docXML = string(data)
		case "[Content_Types].xml":
			hasCT = true
		}
	}
	if !doc || !hasCT {
		t.Fatalf("docx must contain word/document.xml + [Content_Types].xml (doc=%v ct=%v)", doc, hasCT)
	}
	// The hostile value must be escaped, never raw markup.
	if strings.Contains(docXML, "<script>") {
		t.Fatalf("string value must be xml-escaped, not raw markup:\n%s", docXML)
	}
	if !strings.Contains(docXML, "note&lt;script&gt;&amp;") {
		t.Fatalf("escaped value must be present:\n%s", docXML)
	}
	if !strings.Contains(docXML, "42") || !strings.Contains(docXML, "<w:tbl>") {
		t.Fatalf("docx must render the number + a table:\n%s", docXML)
	}
}

func TestXLSX_StringsAreInlineNeverFormula(t *testing.T) {
	ds := Dataset{
		Columns: []string{"note", "amount"},
		Rows:    [][]Cell{{Str("=WEBSERVICE(\"http://169.254.169.254/\")"), Num(-5)}},
	}
	b, err := ToXLSX(ds)
	if err != nil {
		t.Fatalf("xlsx: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a valid zip/xlsx: %v", err)
	}
	var sheet string
	for _, f := range zr.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(data)
		}
	}
	if sheet == "" {
		t.Fatal("sheet1.xml missing from the xlsx")
	}
	// The hostile value must appear inside an inline string, never as a formula cell.
	if strings.Contains(sheet, "<f>") || strings.Contains(sheet, "<f ") {
		t.Fatalf("xlsx must contain NO formula cell:\n%s", sheet)
	}
	if !strings.Contains(sheet, `t="inlineStr"`) || !strings.Contains(sheet, "WEBSERVICE") {
		t.Fatalf("the hostile value must be carried as an inline string:\n%s", sheet)
	}
	// The number is a native numeric cell (a <v> with no t="inlineStr" wrapper for that cell).
	if !strings.Contains(sheet, "<v>-5</v>") {
		t.Fatalf("the number -5 must be a native numeric cell:\n%s", sheet)
	}
}

func TestSerialize_Dispatch(t *testing.T) {
	ds := Dataset{Columns: []string{"a"}, Rows: [][]Cell{{Str("x")}}}
	for _, f := range []Format{FormatJSON, FormatCSV, FormatXLSX} {
		if b, err := Serialize(ds, f); err != nil || len(b) == 0 {
			t.Fatalf("format %s should serialize: err=%v len=%d", f, err, len(b))
		}
	}
	if _, err := Serialize(ds, Format("pdf")); err == nil {
		t.Fatal("an unsupported format must error (PDF is deferred to its own gate)")
	}
}

func TestColName(t *testing.T) {
	cases := map[int]string{0: "A", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA"}
	for i, want := range cases {
		if got := colName(i); got != want {
			t.Fatalf("colName(%d)=%q want %q", i, got, want)
		}
	}
}
