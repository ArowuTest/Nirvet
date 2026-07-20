package reporting

// §6.13 #125 R-3 — the export serializers. This is the security choke point: the ONLY place a Dataset becomes bytes,
// so formula-injection neutralization cannot be bypassed by any report type.
//
//   - JSON  — inherently safe (no formula concept); typed values pass through as native JSON.
//   - CSV   — has no cell types, so a STRING cell whose first char is a formula trigger (= + - @ TAB CR LF) is
//             prefixed with a single quote (reviewer refinement #1: ONLY string cells — a number is written native,
//             so `-5` stays `-5` and is never corrupted).
//   - XLSX  — a STRING cell is written as an INLINE STRING (`t="inlineStr"`), which by type can never be a formula,
//             DDE, =HYPERLINK or =WEBSERVICE (refinement #2 — impossible by type, no value pollution). Numbers are
//             native numeric cells. This is a minimal, dependency-free writer (no third-party lib, no network).

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// formulaTriggers are the leading characters a spreadsheet may interpret as a formula/command in a string cell.
const formulaTriggers = "=+-@\t\r\n"

// neutralizeCSVString prefixes a STRING value that begins with a formula trigger. Applied only to string cells.
func neutralizeCSVString(s string) string {
	if s != "" && strings.ContainsRune(formulaTriggers, rune(s[0])) {
		return "'" + s
	}
	return s
}

// cellCSV renders a cell for CSV: strings are neutralized, everything else is written in its native form (so numbers
// keep their sign and value).
func cellCSV(c Cell) string {
	switch c.Kind {
	case KindString:
		return neutralizeCSVString(c.S)
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

// ToCSV serializes the dataset to CSV. Column headers are trusted labels but are neutralized too (defense in depth).
func ToCSV(ds Dataset) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	head := make([]string, len(ds.Columns))
	for i, c := range ds.Columns {
		head[i] = neutralizeCSVString(c)
	}
	if err := w.Write(head); err != nil {
		return nil, err
	}
	for _, row := range ds.Rows {
		rec := make([]string, len(row))
		for i, c := range row {
			rec[i] = cellCSV(c)
		}
		if err := w.Write(rec); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// jsonCell renders a cell as a native JSON value (string/number/bool/RFC3339-string). JSON has no formula semantics.
func jsonCell(c Cell) any {
	switch c.Kind {
	case KindString:
		return c.S
	case KindNumber:
		return c.N
	case KindTime:
		return c.T.UTC().Format(time.RFC3339)
	case KindBool:
		return c.B
	default:
		return nil
	}
}

// ToJSON serializes the dataset to JSON (title + REP-003 meta + columns + typed rows).
func ToJSON(ds Dataset) ([]byte, error) {
	rows := make([][]any, len(ds.Rows))
	for i, row := range ds.Rows {
		cells := make([]any, len(row))
		for j, c := range row {
			cells[j] = jsonCell(c)
		}
		rows[i] = cells
	}
	return json.Marshal(map[string]any{
		"title": ds.Title, "meta": ds.Meta, "columns": ds.Columns, "rows": rows,
	})
}

// ---- minimal XLSX (dependency-free) ----

func xmlEscape(s string) string {
	// Drop XML-1.0-illegal control chars (except \t \n \r), then escape the markup metacharacters.
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// colName converts a 0-based column index to a spreadsheet column name (0→A, 26→AA).
func colName(i int) string {
	name := ""
	for i >= 0 {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
	}
	return name
}

// cellXML renders one cell at (col,row). STRING → inline string (formula-proof by type); NUMBER → native numeric
// cell; TIME/BOOL → inline string (safe; native date styling deferred). Nothing is ever emitted as a formula cell.
func cellXML(col, row int, c Cell) string {
	ref := fmt.Sprintf("%s%d", colName(col), row)
	switch c.Kind {
	case KindNumber:
		return fmt.Sprintf(`<c r="%s"><v>%s</v></c>`, ref, strconv.FormatFloat(c.N, 'f', -1, 64))
	case KindString:
		return fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, ref, xmlEscape(c.S))
	case KindTime:
		return fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`, ref, xmlEscape(c.T.UTC().Format(time.RFC3339)))
	case KindBool:
		return fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`, ref, strconv.FormatBool(c.B))
	default:
		return fmt.Sprintf(`<c r="%s"/>`, ref)
	}
}

const xlsxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`

const xlsxRootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`

const xlsxWorkbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets></workbook>`

const xlsxWorkbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`

// ToXLSX serializes the dataset to a minimal .xlsx. Every data string is an inline string, so no cell can be a
// formula; numbers are native. Header row = the (trusted) column labels as inline strings.
func ToXLSX(ds Dataset) ([]byte, error) {
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sheet.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	// header
	sheet.WriteString(`<row r="1">`)
	for i, label := range ds.Columns {
		sheet.WriteString(cellXML(i, 1, Str(label)))
	}
	sheet.WriteString(`</row>`)
	// data rows (1-based, offset by the header)
	for r, row := range ds.Rows {
		sheet.WriteString(fmt.Sprintf(`<row r="%d">`, r+2))
		for c, cell := range row {
			sheet.WriteString(cellXML(c, r+2, cell))
		}
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", xlsxContentTypes},
		{"_rels/.rels", xlsxRootRels},
		{"xl/workbook.xml", xlsxWorkbook},
		{"xl/_rels/workbook.xml.rels", xlsxWorkbookRels},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	for _, p := range parts {
		f, err := zw.Create(p.name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- minimal DOCX (dependency-free) ----
//
// A .docx is a WordprocessingML package: [Content_Types].xml + _rels/.rels + word/document.xml. The dataset renders as
// a Word table. Unlike a spreadsheet, a Word document has NO formula concept — a cell is document TEXT — so the safety
// here is XML-escaping (the same xmlEscape choke point) so a string value can never inject markup into document.xml;
// no formula neutralization is needed or applied. Dependency-free: same archive/zip writer as ToXLSX, no third-party
// lib, no network.

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`

const docxRootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`

// cellDisplay renders a cell as its plain display text (no CSV formula-quote — that is a spreadsheet-only concern; a
// Word cell is inert text). The value is xml-escaped by the caller before it enters document.xml.
func cellDisplay(c Cell) string {
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

// docxParagraph is one text paragraph; docxCell wraps a table cell around a paragraph. Both xml-escape their text.
func docxParagraph(text string) string {
	return `<w:p><w:r><w:t xml:space="preserve">` + xmlEscape(text) + `</w:t></w:r></w:p>`
}
func docxCell(text string) string {
	return `<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>` + docxParagraph(text) + `</w:tc>`
}

// ToDOCX serializes the dataset to a minimal .docx: a title, the REP-003 metadata, and a table (header row = the
// trusted column labels; body = the typed cells as display text). Every text node is xml-escaped so a value can never
// break out of document.xml.
func ToDOCX(ds Dataset) ([]byte, error) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	body.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	if ds.Title != "" {
		body.WriteString(docxParagraph(ds.Title))
	}
	// Metadata lines (REP-003) — deterministic order so the document is stable/diffable.
	metaKeys := make([]string, 0, len(ds.Meta))
	for k := range ds.Meta {
		metaKeys = append(metaKeys, k)
	}
	sort.Strings(metaKeys)
	for _, k := range metaKeys {
		body.WriteString(docxParagraph(k + ": " + ds.Meta[k]))
	}
	// Table.
	body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>`)
	body.WriteString(`<w:tr>`)
	for _, label := range ds.Columns {
		body.WriteString(docxCell(label))
	}
	body.WriteString(`</w:tr>`)
	for _, row := range ds.Rows {
		body.WriteString(`<w:tr>`)
		for _, c := range row {
			body.WriteString(docxCell(cellDisplay(c)))
		}
		body.WriteString(`</w:tr>`)
	}
	body.WriteString(`</w:tbl>`)
	body.WriteString(`<w:sectPr/></w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", docxContentTypes},
		{"_rels/.rels", docxRootRels},
		{"word/document.xml", body.String()},
	}
	for _, p := range parts {
		f, err := zw.Create(p.name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Format is an export format.
type Format string

const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
	FormatXLSX Format = "xlsx"
	FormatDOCX Format = "docx"
	FormatPDF  Format = "pdf" // rendered by the fenced pdfrender sub-package (not via Serialize — see pdf.go)
)

// Serialize renders a dataset in the requested format.
func Serialize(ds Dataset, f Format) ([]byte, error) {
	switch f {
	case FormatJSON:
		return ToJSON(ds)
	case FormatCSV:
		return ToCSV(ds)
	case FormatXLSX:
		return ToXLSX(ds)
	case FormatDOCX:
		return ToDOCX(ds)
	}
	return nil, fmt.Errorf("reporting: unsupported format %q", f)
}

// contentType / extension pin the download response to the real format (refinement #4).
func (f Format) ContentType() string {
	switch f {
	case FormatJSON:
		return "application/json"
	case FormatCSV:
		return "text/csv"
	case FormatXLSX:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case FormatDOCX:
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case FormatPDF:
		return "application/pdf"
	}
	return "application/octet-stream"
}

func (f Format) Ext() string { return "." + string(f) }
