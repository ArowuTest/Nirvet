#!/usr/bin/env bash
#
# check-pdf-render-fence.sh — the CI teeth behind the PDF renderer's "zero-egress by construction" invariant.
#
# internal/reporting/pdfrender draws PDFs from typed primitives with a pure-Go core-font drawer. The whole
# SSRF/RCE-elimination argument rests on it having NO way to reach the network, a subprocess, or an HTML/headless
# renderer. The strongest form of that guarantee is STRUCTURAL: pdfrender must not IMPORT — transitively — any of
# those packages. If they are not in its dependency closure, they are unreachable, full stop. (Stronger than
# grepping imports: catches indirect deps.)
#
# Run from backend/. Exits non-zero (printing the offending dependency) on any forbidden dep.
set -euo pipefail

MOD='github.com/ArowuTest/nirvet'

# Forbidden in the render path:
#   - net/http            : any network egress (the SSRF vector).
#   - os/exec             : any subprocess / shell-out (the RCE vector — e.g. wkhtmltopdf/chromium).
#   - html, html/template : an HTML intermediate (headless-render / markup-parse vector).
#   - chromedp/rod/...     : headless-browser drivers.
# stdlib `os` is permitted (fpdf may reference it) but os/exec specifically is not.
FORBIDDEN='^(net/http|net/http/.*|os/exec|html|html/template)$|chromedp|go-rod|/rod|wkhtml|webkit|playwright|puppeteer|headless'

deps="$(go list -deps ./internal/reporting/pdfrender/... 2>/dev/null || true)"
if [ -z "$deps" ]; then
  echo "check-pdf-render-fence: could not list deps for ./internal/reporting/pdfrender/... (build error?)" >&2
  exit 1
fi

offenders="$(echo "$deps" | grep -E "$FORBIDDEN" || true)"
if [ -n "$offenders" ]; then
  echo "PDF-FENCE VIOLATION: internal/reporting/pdfrender must reach no network/subprocess/HTML-render package," >&2
  echo "but its dependency closure includes:" >&2
  echo "$offenders" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "The PDF renderer is zero-egress by construction (pure-Go core-font drawer). If a feature seems to need one" >&2
  echo "of these, it reintroduces the SSRF/RCE class the gate eliminated — redesign, do not add the import." >&2
  exit 1
fi

echo "check-pdf-render-fence: OK — internal/reporting/pdfrender reaches no network/subprocess/HTML-render package (deps checked against ${MOD})."
