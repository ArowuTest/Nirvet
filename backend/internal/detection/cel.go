package detection

// CEL expression rules (SRS §6.6) — a second, more expressive detection DSL
// alongside the native condition model and Sigma import. A rule may carry a CEL
// expression that is evaluated against the normalized event exposed as `event`,
// e.g.  event.severity == "critical" && event.class_name.contains("malware")
//  or   event.data.vendor == "CrowdStrike" && int(event.confidence) >= 80
// The expression must evaluate to a bool. The detection Engine is not wired to one
// rule language — this plugs into the same evaluation loop as Sigma/native rules.

import (
	"fmt"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// celEnv is the shared CEL environment: a single `event` variable, a string-keyed
// map with dynamic values (canonical fields + the data payload). Built once.
var celEnv = mustCELEnv()

// celCostLimit bounds the work a single CEL evaluation may perform on the detection hot
// path (R3 M3). A hostile or accidentally-expensive rule — e.g. a comprehension macro
// (.all/.exists) over a large vendor-supplied list in event.data — is cut off instead of
// burning CPU per event. A *cost* limit (not a wall-clock deadline) is used deliberately:
// it is deterministic and machine-independent, so the same event+rule always evaluates
// the same way, which a detection engine requires. Legitimate detection expressions cost
// only tens of units; 100k is a wide margin below which nothing real is truncated.
const celCostLimit uint64 = 100_000

func mustCELEnv() *cel.Env {
	env, err := cel.NewEnv(cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		panic("detection: cel env: " + err.Error())
	}
	return env
}

// CompileCEL parses + type-checks an expression and returns a runnable program.
// Errors surface at rule-create time so a bad rule never reaches the hot path.
func CompileCEL(expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("empty expression")
	}
	ast, iss := celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	// The expression must produce a boolean (a rule "fires" or not).
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("expression must evaluate to bool, got %s", ast.OutputType())
	}
	// CostLimit bounds runtime work; an over-budget eval returns an error, which EvalCEL
	// treats as "did not fire" (fail-safe) — the hot path can never be pinned by one rule.
	return celEnv.Program(ast, cel.CostLimit(celCostLimit))
}

// EvalCEL runs a compiled program against an event, returning whether it fired.
// It is fail-safe: any evaluation error means "did not fire" (never panics on the
// hot path).
func EvalCEL(prog cel.Program, ev eventstore.NormalizedEvent) bool {
	out, _, err := prog.Eval(map[string]any{"event": eventToMap(ev)})
	if err != nil {
		return false
	}
	return out == types.True
}

// eventToMap exposes the normalized event to CEL: canonical fields plus the nested
// data payload under event.data.
func eventToMap(ev eventstore.NormalizedEvent) map[string]any {
	data := ev.Data
	if data == nil {
		data = map[string]any{}
	}
	return map[string]any{
		"class_name":    ev.ClassName,
		"activity_name": ev.ActivityName,
		"severity":      ev.Severity,
		"source":        ev.Source,
		"actor_ref":     ev.ActorRef,
		"target_ref":    ev.TargetRef,
		"action":        ev.Action,
		"outcome":       ev.Outcome,
		"confidence":    ev.Confidence,
		"data":          data,
	}
}
