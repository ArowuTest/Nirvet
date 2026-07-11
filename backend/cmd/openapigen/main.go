// Command openapigen is a one-off helper that emits OpenAPI path stubs for every route registered in
// cmd/api/main.go that is not yet in api/openapi.yaml. Output is a YAML fragment (path items grouped by
// path) appended under the spec's `paths:` section. The permanent guard is api/openapi_sync_test.go.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var routeRe = regexp.MustCompile(`mux\.Handle\("([A-Z]+) ([^"]+)"`)
var paramRe = regexp.MustCompile(`\{(\w+)\}`)

func main() {
	src, err := os.ReadFile("cmd/api/main.go")
	must(err)
	spec, err := os.ReadFile("api/openapi.yaml")
	must(err)

	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	must(yaml.Unmarshal(spec, &doc))
	documented := map[string]bool{}
	for p, ms := range doc.Paths {
		for m := range ms {
			documented[strings.ToUpper(m)+" "+p] = true
		}
	}
	waived := map[string]bool{"GET /openapi.yaml": true, "GET /docs": true}
	public := map[string]bool{"POST /auth/password-reset/confirm": true}

	// Group missing routes by path.
	byPath := map[string][]string{}
	seen := map[string]bool{}
	for _, m := range routeRe.FindAllStringSubmatch(string(src), -1) {
		method, path := m[1], m[2]
		key := method + " " + path
		if seen[key] || documented[key] || waived[key] {
			continue
		}
		seen[key] = true
		byPath[path] = append(byPath[path], method)
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return // spec already covers every route — nothing to append
	}

	var b strings.Builder
	b.WriteString("\n  # --- auto-added by cmd/openapigen (external-review OpenAPI parity); enrich schemas incrementally ---\n")
	for _, p := range paths {
		tag := "misc"
		if seg := strings.Split(strings.Trim(p, "/"), "/"); len(seg) > 0 && seg[0] != "" {
			tag = seg[0]
		}
		params := paramRe.FindAllStringSubmatch(p, -1)
		fmt.Fprintf(&b, "  %s:\n", p)
		methods := byPath[p]
		sort.Strings(methods)
		for _, method := range methods {
			lm := strings.ToLower(method)
			fmt.Fprintf(&b, "    %s:\n", lm)
			fmt.Fprintf(&b, "      tags: [%s]\n", tag)
			fmt.Fprintf(&b, "      summary: %s %s\n", method, p)
			if public[method+" "+p] {
				b.WriteString("      security: []\n")
			}
			if len(params) > 0 {
				b.WriteString("      parameters:\n")
				for _, pm := range params {
					fmt.Fprintf(&b, "        - { name: %s, in: path, required: true, schema: { type: string } }\n", pm[1])
				}
			}
			b.WriteString("      responses:\n")
			b.WriteString("        '200': { description: OK }\n")
			b.WriteString("        '400': { description: bad request, content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }\n")
			if !public[method+" "+p] {
				b.WriteString("        '401': { description: unauthenticated }\n")
				b.WriteString("        '403': { description: forbidden }\n")
			}
		}
	}
	fmt.Print(b.String())
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
