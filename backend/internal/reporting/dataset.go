package reporting

// §6.13 #125 R-3 — the typed-cell dataset. The whole formula-injection defense rests on cells being TYPED: a number
// is written as a native number (never a formula, and never corrupted by a defensive prefix — reviewer refinement
// #1), and a string is written so it can never be interpreted as a formula (an inline string in XLSX; a
// trigger-prefixed value in CSV — refinement #2). The report content assembles a Dataset; the serializers below are
// the ONLY place cells become bytes, so neutralization cannot be bypassed by a new report type.

import "time"

// CellKind is the value type of a cell — it decides how the cell is serialized (and whether it can ever be a formula).
type CellKind uint8

const (
	KindEmpty  CellKind = iota
	KindString          // untrusted text — MUST be rendered formula-proof
	KindNumber          // native number — never a formula, never prefix-corrupted
	KindTime            // native date/time
	KindBool            // native boolean
)

// Cell is one typed value.
type Cell struct {
	Kind CellKind
	S    string
	N    float64
	T    time.Time
	B    bool
}

// Str builds an (untrusted) string cell.
func Str(s string) Cell { return Cell{Kind: KindString, S: s} }

// Num builds a native number cell.
func Num(n float64) Cell { return Cell{Kind: KindNumber, N: n} }

// TimeCell builds a native time cell.
func TimeCell(t time.Time) Cell { return Cell{Kind: KindTime, T: t} }

// BoolCell builds a native boolean cell.
func BoolCell(b bool) Cell { return Cell{Kind: KindBool, B: b} }

// Dataset is a single tabular sheet plus the REP-003 metadata header (data-period, tenant, scope, coverage,
// limitations, evidence references) that every report must carry.
type Dataset struct {
	Title   string            `json:"title"`
	Meta    map[string]string `json:"meta"`    // REP-003 header
	Columns []string          `json:"columns"` // header row labels (trusted, from the report definition)
	Rows    [][]Cell          `json:"-"`       // typed data cells (untrusted content)
}
