# The Nirvet heartbeat (walking skeleton)

**Owner principle (Jul 2026):** every operational module must participate in one continuous thread
pulled through *every* layer of the SOC value loop. If that thread is green end-to-end, the platform
has a real heartbeat and everything else — more connectors, AI, reports, dashboards — is **incremental**
(breadth added to a spine that already holds weight, not a spine we hope appears later).

## The chain (each link is real code, exercised in order)

```
Login → Tenant → Connector → Receive event → Normalize → Store event →
Detection → Alert → Incident → Assign analyst → Timeline → Playbook →
Close incident → Audit trail
```

| # | Link | Where it lives | Proven by |
|---|------|----------------|-----------|
| 1 | Login | `iam.Service.Login` (password + MFA, writes `auth.login` audit) | Heartbeat step 1 |
| 2 | Tenant | `tenant.Service` + Postgres RLS (`app_current_tenant()`, FORCE) | tenant-scoped throughout |
| 3 | Connector | `connector.Service.Create` (webhook; one-time source key) | step 3 |
| 4 | Receive event | `connector.Service.IngestWebhook` (source-key auth) → `ingestion.Service.Ingest` | step 4 |
| 5 | Normalize | `ingestion.Worker` → source-aware normalizer | steps 5–8 (worker) |
| 6 | Store event | `eventstore` (Postgres now, ClickHouse at V1) + blob evidence | " |
| 7 | Detection | `detection.Engine` (cached per-tenant condition rules) | " |
| 8 | Alert | `alert.Service.CreateFromEvent` (idempotent `event:rule`) | " |
| 9 | Incident | `incident.Service.CreateFromAlert` (atomic; links alert→incident; seeds timeline) | step 9 |
| 10 | Assign analyst | `incident.Service.Assign` (same-tenant check; → `investigating`) | step 10 |
| 11 | Timeline | `incident.Service.AddNote` / every stage appends an ordered entry | steps 11, 14 |
| 12 | Playbook | `soar.Service.Run(..., &incidentID)` + authority-to-act approval | step 12 |
| 13 | Close incident | `incident.Service.Close` (records closure entry) | step 13 |
| 14 | Audit trail | audit middleware on every HTTP mutation + service-level auth audit | step 15 |

## The guard

`internal/integrationtest/flow_test.go` → `TestIntegration/Heartbeat_EndToEnd` walks the **entire** chain as
one thread against a migrated Postgres (gated on `NIRVET_TEST_DATABASE_URL`, runs in CI). A break here is a
**P0** — it means a layer of the platform stopped carrying weight.

This test has already earned its keep twice:
- It forced the **Assign-analyst** link to exist (incidents previously only got an owner at promotion).
- It caught an **orphaned timeline entry** (an entry written with a zero-UUID `incident_id`; `NOT NULL`
  doesn't catch the zero UUID). Fixed in code *and* hardened at the DB with a foreign key
  (`migrations/0009_incident_timeline_fk.sql`) so the class of bug now fails loudly.

## What is deliberately *not* in the heartbeat

Breadth that hangs off the spine and is added incrementally: additional connectors (Defender pull exists,
syslog/others pending), AI copilot (assistive-only), threat-intel enrichment, reporting/compliance
aggregates, billing entitlements, dashboards (UI from designer HTML). None of these are load-bearing for
the loop — they enrich it.
