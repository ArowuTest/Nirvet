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
	return celEnv.Program(ast)
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
