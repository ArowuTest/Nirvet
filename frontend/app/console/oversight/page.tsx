"use client";

// Vendor / regulator posture oversight (MA-4 + oversight resolver family). A metadata-ONLY fleet view: for each
// tenant in the caller's grant scope, scalar incident-posture counts (open by severity, SLA breach/at-risk,
// escalations) — never incident content, titles, or telemetry (the store has nowhere to put them). Read via
// GET /posture/fleet, oversight-gated (platform_admin whole-instance; org_sub_admin / payer grant-scoped). A
// non-oversight role 403s → the page shows an access note rather than empty data.

import { useEffect, useState } from "react";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, StatusTag, EmptyState } from "@/components/ui";

type Posture = {
  tenant_id: string;
  open_total: number; open_critical: number; open_high: number; open_medium: number; open_low: number;
  oldest_open_at?: string; unacked: number; ack_overdue: number; sla_breached: number; sla_at_risk: number;
  escalated: number; last_activity_at?: string; updated_at: string;
};

export default function OversightPage() {
  const [rows, setRows] = useState<Posture[] | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "forbidden" | "error">("loading");

  useEffect(() => {
    apiGet<{ posture: Posture[] | null; count: number }>("/posture/fleet")
      .then((r) => { setRows(r.posture ?? []); setState("ready"); })
      .catch((e) => setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "error"));
  }, []);

  const totals = (rows ?? []).reduce(
    (a, r) => ({ tenants: a.tenants + 1, open: a.open + r.open_total, crit: a.crit + r.open_critical, breached: a.breached + r.sla_breached, atRisk: a.atRisk + r.sla_at_risk }),
    { tenants: 0, open: 0, crit: 0, breached: 0, atRisk: 0 },
  );

  return (
    <div>
      <PageHeader title="Fleet oversight" sub="Metadata-only incident posture across your grant-scoped tenants — counts only, never content" />

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}
      {state === "forbidden" && <EmptyState title="Oversight access required" hint="This surface is limited to platform-admin, org-sub-admin and payer (grant-scoped) roles." />}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>Could not read fleet posture.</div>}

      {state === "ready" && (
        <div className="space-y-5">
          <KpiStrip>
            <Kpi label="Tenants" value={String(totals.tenants)} />
            <Kpi label="Open incidents" value={String(totals.open)} />
            <Kpi label="Open critical" value={String(totals.crit)} tone={totals.crit > 0 ? "danger" : undefined} />
            <Kpi label="SLA breached" value={String(totals.breached)} tone={totals.breached > 0 ? "danger" : undefined} />
            <Kpi label="SLA at risk" value={String(totals.atRisk)} tone={totals.atRisk > 0 ? "warn" : undefined} />
          </KpiStrip>

          <Panel title="Per-tenant posture" sub="Scalar counts projected from incident metadata (MA4-1) — no titles, categories or telemetry" bodyStyle={{ padding: 0 }}>
            {(rows ?? []).length === 0 ? <div className="p-6"><EmptyState title="No tenants in scope" hint="No tenants are within your oversight grant, or none have posture yet." /></div> : (
              <Table head={<><Th>Tenant</Th><Th>Open</Th><Th>Crit</Th><Th>High</Th><Th>SLA breached</Th><Th>At risk</Th><Th>Escalated</Th><Th className="text-right">Last activity</Th></>}>
                {(rows ?? []).map((r) => (
                  <tr key={r.tenant_id}>
                    <Td className="font-mono text-[11px]" title={r.tenant_id}>{r.tenant_id.slice(0, 8)}…</Td>
                    <Td className="font-medium">{r.open_total}</Td>
                    <Td>{r.open_critical > 0 ? <StatusTag tone="danger">{r.open_critical}</StatusTag> : "0"}</Td>
                    <Td>{r.open_high > 0 ? <StatusTag tone="warn">{r.open_high}</StatusTag> : "0"}</Td>
                    <Td>{r.sla_breached > 0 ? <StatusTag tone="danger">{r.sla_breached}</StatusTag> : "0"}</Td>
                    <Td>{r.sla_at_risk > 0 ? <StatusTag tone="warn">{r.sla_at_risk}</StatusTag> : "0"}</Td>
                    <Td>{r.escalated}</Td>
                    <Td className="text-right text-xs">{r.last_activity_at ? new Date(r.last_activity_at).toLocaleString() : "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
