package recovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// StatefulComponent is one recoverable surface named by the reviewer-authored
// recovery manifest. The inventory is closed so a deployment cannot silently
// omit a difficult component from certification.
type StatefulComponent string

const (
	ComponentPostgres  StatefulComponent = "postgres"
	ComponentCrypto    StatefulComponent = "crypto_material"
	ComponentBlob      StatefulComponent = "object_blob_storage"
	ComponentQueue     StatefulComponent = "queue_outbox_idempotency"
	ComponentConfig    StatefulComponent = "secrets_config"
	ComponentContent   StatefulComponent = "content_packages"
	ComponentAudit     StatefulComponent = "audit_records"
	ComponentSessions  StatefulComponent = "session_revocation"
	ComponentRetention StatefulComponent = "retention_erasure"
	ComponentAnalytics StatefulComponent = "analytics_clickhouse"
)

var requiredComponents = []StatefulComponent{
	ComponentPostgres,
	ComponentCrypto,
	ComponentBlob,
	ComponentQueue,
	ComponentConfig,
	ComponentContent,
	ComponentAudit,
	ComponentSessions,
	ComponentRetention,
	ComponentAnalytics,
}

// ComponentProbe validates the restored component. Applicable=false is allowed
// only when ProfileEvidence proves that the deployment profile does not use that
// component; an unconfigured or omitted probe is a certification failure.
type ComponentProbe struct {
	Applicable      bool
	ProfileEvidence string
	Validator       Validator
}

// ValidateStatefulComponents executes the complete manifest inventory and
// returns evidence for each component. Missing entries, unexplained exclusions,
// empty evidence, and validation errors all fail closed.
func ValidateStatefulComponents(ctx context.Context, probes map[StatefulComponent]ComponentProbe) (map[StatefulComponent]string, error) {
	required := make(map[StatefulComponent]struct{}, len(requiredComponents))
	for _, component := range requiredComponents {
		required[component] = struct{}{}
	}
	for component := range probes {
		if _, ok := required[component]; !ok {
			return nil, fmt.Errorf("recovery: unknown stateful component %q", component)
		}
	}

	evidence := make(map[StatefulComponent]string, len(requiredComponents))
	var missing []string
	for _, component := range requiredComponents {
		probe, ok := probes[component]
		if !ok {
			missing = append(missing, string(component))
			continue
		}
		if !probe.Applicable {
			profileEvidence := strings.TrimSpace(probe.ProfileEvidence)
			if profileEvidence == "" {
				return nil, fmt.Errorf("recovery: component %q excluded without deployment-profile evidence", component)
			}
			evidence[component] = "not applicable: " + profileEvidence
			continue
		}
		if probe.Validator == nil {
			return nil, fmt.Errorf("recovery: component %q has no validator", component)
		}
		result, err := probe.Validator.ValidateRecovery(ctx)
		if err != nil {
			return nil, fmt.Errorf("recovery: component %q: %w", component, err)
		}
		result = strings.TrimSpace(result)
		if result == "" {
			return nil, fmt.Errorf("recovery: component %q returned no evidence", component)
		}
		evidence[component] = result
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("recovery: stateful component inventory incomplete: %s", strings.Join(missing, ", "))
	}
	return evidence, nil
}
