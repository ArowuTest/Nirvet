package recovery

import (
	"fmt"
	"sort"
	"strings"
)

// ConfigRequirement names one secret or configuration value that must be present
// before a restored deployment may start. Requirements are supplied by the
// deployment profile so optional components are explicit rather than silently
// skipped.
type ConfigRequirement struct {
	Name      string
	Sensitive bool
}

// ValidateConfigCompleteness proves that every value required by the restored
// deployment profile is present. It returns names only and never emits secret
// values into recovery evidence or errors.
func ValidateConfigCompleteness(requirements []ConfigRequirement, values map[string]string) (string, error) {
	if len(requirements) == 0 {
		return "", fmt.Errorf("recovery: restored deployment config inventory is empty")
	}
	seen := make(map[string]struct{}, len(requirements))
	var missing []string
	for _, requirement := range requirements {
		name := strings.TrimSpace(requirement.Name)
		if name == "" {
			return "", fmt.Errorf("recovery: config inventory contains an empty name")
		}
		if _, duplicate := seen[name]; duplicate {
			return "", fmt.Errorf("recovery: duplicate config requirement %q", name)
		}
		seen[name] = struct{}{}
		if strings.TrimSpace(values[name]) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("recovery: required restored config is missing: %s", strings.Join(missing, ", "))
	}
	return fmt.Sprintf("%d required restored configuration values present", len(requirements)), nil
}
