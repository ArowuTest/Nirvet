package recovery

import (
	"context"
	"strings"
	"testing"
)

func completeComponentProbes() map[StatefulComponent]ComponentProbe {
	probes := make(map[StatefulComponent]ComponentProbe, len(requiredComponents))
	for _, component := range requiredComponents {
		component := component
		probes[component] = ComponentProbe{
			Applicable: true,
			Validator: ValidatorFunc(func(context.Context) (string, error) {
				return "validated " + string(component), nil
			}),
		}
	}
	return probes
}

func TestValidateStatefulComponentsRequiresWholeManifest(t *testing.T) {
	probes := completeComponentProbes()
	delete(probes, ComponentBlob)
	if _, err := ValidateStatefulComponents(context.Background(), probes); err == nil || !strings.Contains(err.Error(), string(ComponentBlob)) {
		t.Fatalf("missing blob recovery story was not refused: %v", err)
	}
}

func TestValidateStatefulComponentsAllowsProvenNonApplicableProfile(t *testing.T) {
	probes := completeComponentProbes()
	probes[ComponentAnalytics] = ComponentProbe{
		Applicable:      false,
		ProfileEvidence: "deployment profile declares PostgreSQL event store and ClickHouse DSN is absent",
	}
	evidence, err := ValidateStatefulComponents(context.Background(), probes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(evidence[ComponentAnalytics], "not applicable") {
		t.Fatal("profile-proven exclusion did not produce evidence")
	}
}

func TestValidateStatefulComponentsRejectsUnexplainedExclusion(t *testing.T) {
	probes := completeComponentProbes()
	probes[ComponentAnalytics] = ComponentProbe{Applicable: false}
	if _, err := ValidateStatefulComponents(context.Background(), probes); err == nil {
		t.Fatal("unexplained stateful-component exclusion was accepted")
	}
}

func TestValidateStatefulComponentsRejectsEmptyEvidence(t *testing.T) {
	probes := completeComponentProbes()
	probes[ComponentQueue] = ComponentProbe{
		Applicable: true,
		Validator:  ValidatorFunc(func(context.Context) (string, error) { return " ", nil }),
	}
	if _, err := ValidateStatefulComponents(context.Background(), probes); err == nil {
		t.Fatal("evidence-free queue recovery check was accepted")
	}
}
