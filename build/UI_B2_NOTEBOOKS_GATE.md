# Pre-code gate — B2: Investigation notebooks (§6.9 slice B, UI-depth Bucket B)

**Owner directive:** build backend+UI *gated*; no hardcoding; honest states, no fabrication. Gate precedes code.

## Problem / SRS grounding
§6.9 slice A shipped the hunt-query engine (allow-list → bound params), entity graph, case timeline and data-gap
panels. It has **no persisted analyst working surface** — an investigator cannot keep notes or save a hunt query
for reuse. §6.9 slice B calls for notebooks / saved views / a war-room. This slice builds the **notebook core**:
a private, persisted investigation notebook made of ordered cells (a markdown **note** or a saved **hunt query**),
optionally tied to an incident. "Saved views" are realised as query cells (a named, reusable hunt query lives in
a cell). Real-time multi-analyst **war-room collaboration is deferred** (single sovereign operator; honest note in
the UI rather than a faked presence/typing surface).

## Design — mirrors the proven B1 sessions+turns shape
### Persistence — migs 0125 (tables) + 0126 (owner_bypass loop, same 0121→0122 pattern)
- `investigation_notebooks`: `id` PK gen_random_uuid, `tenant_id` DEFAULT app_current_tenant(), `user_id` uuid
  (owner — notebooks are private to the creating analyst, matching copilot sessions), `title` text,
  `incident_ref` uuid NULL, `created_at`, `updated_at`.
- `investigation_notebook_cells`: `id` PK, `tenant_id` DEFAULT, `notebook_id` FK→notebooks ON DELETE CASCADE,
  `position` int (append order; reorder swaps positions), `kind` text CHECK IN ('note','query'), `content` text
  (markdown for note; the hunt-query text for query), `created_at`, `updated_at`.
- Both: `ENABLE`+`FORCE ROW LEVEL SECURITY`, `tenant_isolation` policy; owner_bypass added by 0126's DO-loop (NOT
  hand-written — a `current_user = CURRENT_USER` literal is a tautology that defeats isolation); `GRANT … TO nirvet_app`.

### Service (`internal/investigation/notebook.go`)
- `CreateNotebook(ctx,p,title,incidentRef)`, `ListNotebooks(ctx,p)` (own only, recent first),
  `GetNotebook(ctx,p,id)` (notebook + cells ordered by position; RLS + user_id ownership → 404 otherwise).
- `AddCell(ctx,p,notebookId,kind,content)` (append at max(position)+1; validates kind; bounds content length),
  `UpdateCell(ctx,p,notebookId,cellId,content)`, `DeleteCell(ctx,p,notebookId,cellId)`,
  `MoveCell(ctx,p,notebookId,cellId,dir)` (swap with the adjacent cell — simple, honest reorder).
- Every mutation bumps notebook.updated_at and is audited (`investigation.notebook_*`).

### Routes (`cmd/api/main.go`) — provider-gated (analyst_t1+, the hunt tier)
- `POST /investigation/notebooks`, `GET /investigation/notebooks`, `GET /investigation/notebooks/{id}`,
  `POST /investigation/notebooks/{id}/cells`, `PUT /investigation/notebooks/{id}/cells/{cid}`,
  `DELETE /investigation/notebooks/{id}/cells/{cid}`, `POST /investigation/notebooks/{id}/cells/{cid}/move`.
- Add all to `api/openapi.yaml` (parity CI).

## Invariants / guardrails
1. **RLS + ownership** — notebooks/cells tenant-scoped AND user-owned; a peer/another tenant cannot read or mutate
   another analyst's notebook. New RLS tables get owner_bypass (mig 0126).
2. **A query cell is just stored text** — saving a hunt query in a cell does NOT execute it. Execution stays the
   existing `POST /investigation/run-hunt-query` path (allow-list compiled to bound params). No new query-exec
   surface, no injection surface added here.
3. **No hardcoding** — content-length + cell-count caps are safety bounds, not policy thresholds.
4. **Honest states** — empty notebook / no notebooks → honest empty states; war-room collaboration surface shows a
   "single-operator — real-time war-room N/A on this deployment" note, never fabricated collaborators.
5. CI: gofmt/vet/build, owner_bypass guard, OpenAPI parity, from-zero migration, existing investigation tests.

## Tests
- DB-gated integration: create notebook → add note + query cells → GetNotebook returns them in position order →
  update a cell → move a cell (order changes) → delete a cell; ownership isolation (a peer 404s on get/mutate).
  Guard with `testsupport.RequireDSN`.

## UI (after backend green)
`console/notebooks` (nav: Operations > Notebooks): notebook rail (+ New, optional incident grounding), notebook
view = ordered cells with inline add (note/query), edit, move up/down, delete; query cells show the query text
with a "Run in hunt" link to the hunt page. Honest empty states + the war-room deferral note.

## Out of scope (deferred, honest)
Real-time war-room presence/co-editing, shared team notebooks, notebook export to evidence pack — not in this
slice; the UI states the war-room deferral rather than faking collaborators.
