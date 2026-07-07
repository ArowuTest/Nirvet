# ADR-0001 — Multi-tenancy & tenant isolation

**Status:** Accepted (assumed sign-off, Jul 2026; pre-go-live security-architect review pending)
**Deciders:** Owner + build agent · **Stack:** Go · PostgreSQL

## Context

Nirvet is multi-tenant and holds each customer's security telemetry, alerts, cases and evidence. A cross-tenant
leak is a catastrophic, trust-ending failure (NFR-001, SRS §13). The platform must simultaneously serve a
low-cost **shared SaaS** model *and* **dedicated / sovereign** deployments for banks, enterprise and government —
from one codebase. We already run RLS in Go/Postgres on a sibling project (GN-WAAS), so the pattern is proven in
our stack, including its footguns.

## Decision

**Default = pooled shared database with PostgreSQL Row-Level Security (RLS); isolation escalates by tier.**

1. **`tenant_id uuid NOT NULL` on every tenant-owned table.** It leads every composite index and is part of every
   foreign key (a child row cannot reference a parent in another tenant).
2. **RLS is the enforcement boundary, not app-code `WHERE` clauses.** For each table:
   `ENABLE ROW LEVEL SECURITY` **and `FORCE ROW LEVEL SECURITY`** (table owners bypass RLS otherwise), with a
   `USING (tenant_id = current_setting('app.current_tenant')::uuid)` policy (plus `WITH CHECK` on writes).
3. **The app connects as a dedicated non-owner role without `BYPASSRLS`.** Migrations run as a separate
   privileged role; the runtime role can never see across tenants even with a bug.
4. **Tenant context is set per request with `SET LOCAL app.current_tenant = $1` inside the request transaction**,
   from middleware that derives tenant from the authenticated principal — never from client-supplied body/query.
   `SET LOCAL` (transaction-scoped) is mandatory because transaction-pooling poolers (PgBouncer, Render-style)
   reuse connections across clients; a session-level `SET` would leak tenant context.
5. **Object storage, search/event store, and vector store are tenant-scoped too** — isolation is not just
   Postgres. Evidence in GCS under a `tenant/{id}/…` prefix with path-scoped IAM; event-store queries carry a
   mandatory tenant predicate (ADR-0002); vector embeddings namespaced per tenant.
6. **`isolation_tier` on the tenant record drives the model:**
   - `pooled` → shared DB + RLS (SME / standard SaaS).
   - `dedicated` → own database (or instance), same code, provisioned per tenant (banks, enterprise private SOC).
   - `sovereign` → dedicated deployment in-region/in-country on GCP, optionally customer-managed keys (Ghana,
     regulators). See ADR-0004 for the key hierarchy.
7. **Isolation is tested, not asserted.** CI includes negative tests that authenticate as tenant A and attempt to
   read/write tenant B's rows, files, events and vectors, asserting every attempt fails. This gate is required for
   any release touching data access (SRS §13, §18).

## Consequences

**Positive:** DB-enforced isolation (defense in depth beyond app code); one codebase spans SaaS→sovereign; cheap
to start; regulated buyers get true silos without a rewrite; CI proves the property auditors ask about.

**Negative / risks:**
- RLS footguns are real. **Known pitfall (from GN-WAAS): a swallowed failed statement inside a read-only RLS
  transaction aborts the whole transaction → "commit unexpectedly resulted in rollback" on GETs.** Rule: never
  issue a write via the read connection in a GET path; keep read handlers strictly read-only; surface statement
  errors instead of swallowing them.
- Every data-access path must run inside the tenant-context transaction — enforce via a single repository/db
  helper (ties to the entity→repo→usecase→handler pattern) so no query can bypass it.
- Pooled model shares a noisy-neighbor blast radius for performance; heavy tenants may need promotion to
  `dedicated`. Capacity/quotas mitigate (ADR-0003).

## MVP vs best-in-class

- **MVP:** `pooled` RLS only, with the full guardrails above + CI isolation tests. `dedicated`/`sovereign` are
  designed-for (the `isolation_tier` switch and provisioning seams exist) but not built until a customer needs them.
- **Best-in-class later:** per-tenant CMEK/BYOK for regulated tenants, automated dedicated-instance provisioning
  pipeline, and periodic third-party isolation pen-test.

## References

SRS §13 (Security, Privacy & Multi-Tenancy), §4 (deployment models), NFR-001/006/009; doc 02 §7 (tenant
isolation). Related: [ADR-0002](0002-event-store.md), [ADR-0004](0004-connector-credential-vault.md).
