// Package api serves the OpenAPI specification and a Swagger UI. The spec is
// embedded at build time so the binary is self-contained (no runtime file
// dependency) and portable across every deployment target (ADR-0005).
package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiYAML []byte

// SpecHandler serves the raw OpenAPI 3.1 document at GET /openapi.yaml.
func SpecHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapiYAML)
	}
}

// docsHTML renders Swagger UI (from a CDN) pointed at the embedded spec. Kept
// dependency-free: a single static page, no bundled assets.
const docsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Nirvet API — Reference</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({ url: '/openapi.yaml', dom_id: '#swagger-ui' });
  </script>
</body>
</html>`

// DocsHandler serves the Swagger UI page at GET /docs.
func DocsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(docsHTML))
	}
}
