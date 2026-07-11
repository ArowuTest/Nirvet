package api

// Route↔OpenAPI parity guard (external-review governance fix). The spec was hand-maintained and silently fell
// behind the router (86 of 236 routes by the time it was caught). This test extracts every route registered in
// cmd/api/main.go and fails the build if any is missing from openapi.yaml — so the spec can never drift again.
// Adding a route now forces adding its spec entry.

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var muxRouteRe = regexp.MustCompile(`mux\.Handle\("([A-Z]+) ([^"]+)"`)

// waivedRoutes are intentionally undocumented (the spec/docs endpoints themselves).
var waivedRoutes = map[string]bool{
	"GET /openapi.yaml": true,
	"GET /docs":         true,
}

func TestOpenAPICoversAllRoutes(t *testing.T) {
	src, err := os.ReadFile("../cmd/api/main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapiYAML, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	documented := map[string]bool{}
	for p, methods := range doc.Paths {
		for m := range methods {
			documented[strings.ToUpper(m)+" "+p] = true
		}
	}

	var missing []string
	seen := map[string]bool{}
	for _, m := range muxRouteRe.FindAllStringSubmatch(string(src), -1) {
		key := m[1] + " " + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		if !documented[key] && !waivedRoutes[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d route(s) registered in main.go but missing from api/openapi.yaml — document them (or add a "+
			"waiver): \n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}
