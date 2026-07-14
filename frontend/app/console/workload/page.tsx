"use client";

// Team workload (UI-depth Bucket B / B4). A SOC lead's per-analyst open-incident roll-up, wired to
// GET /incidents/workload (manager). Shows who is carrying what, how much is critical, and where SLAs are
// breaching, plus the Unassigned bucket. Manager-gated server-side → a non-manager sees an access note.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, StatusTag, EmptyState } from "@/components/ui";

type Row = {
  owner_id?: string | null;
  owner_email: string;
  open_total: number;
  open_critical: number;
  open_high: number;
  sla_breached: number;
  sla_at_risk: number;
  oldest_open_at?: string;
};

export default function WorkloadPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "forbidden" | "error">("loading");

  useEffect(() => {
    apiGet<{ workload: Row[] | null }>("/incidents/workload")
      .then((r) => { setRows(r.workload ?? []); setState("ready"); })
      .catch((e) => setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "error"));
  }, []);

  const totals = (rows ?? []).reduce(
    (a, r) => ({ analysts: a.analysts + (r.owner_id ? 1 : 0), open: a.open + r.open_total, breached: a.breached + r.sla_breached, atRisk: a.atRisk + r.sla_at_risk }),
    { analysts: 0, open: 0, breached: 0, atRisk: 0 },
  );

  return (
    <div>
      <PageHeader title="Team workload" sub="Open-incident load per analyst — balance the queue and catch SLA pressure early" />

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}
      {state === "forbidden" && <EmptyState title="Manager access required" hint="The team workload roll-up is available to SOC managers. Analysts see their own queue on the Incidents page." />}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>Could not load workload.</div>}

      {state === "ready" && (
        <div className="space-y-5">
          <KpiStrip>
            <Kpi label="Analysts with load" value={String(totals.analysts)} />
            <Kpi label="Open incidents" value={String(totals.open)} />
            <Kpi label="SLA breached" value={String(totals.breached)} tone={totals.breached > 0 ? "danger" : undefined} />
            <Kpi label="SLA at risk" value={String(totals.atRisk)} tone={totals.atRisk > 0 ? "warn" : undefined} />
          </KpiStrip>

          <Panel title="Per-analyst load" sub="Open incidents grouped by owner; breach and at-risk are derived from SLA due times" bodyStyle={{ padding: 0 }}>
            {(rows ?? []).length === 0 ? <div className="p-6"><EmptyState title="No open incidents" hint="When incidents are open they appear here grouped by their assigned analyst." /></div> : (
              <Table head={<><Th>Analyst</Th><Th>Open</Th><Th>Critical</Th><Th>High</Th><Th>Breached</Th><Th>At risk</Th><Th className="text-right">Oldest open</Th></>}>
                {(rows ?? []).map((r, i) => {
                  const unassigned = !r.owner_id;
                  return (
                    <tr key={r.owner_id ?? `unassigned-${i}`} style={unassigned ? { background: "rgba(245,158,11,0.06)" } : undefined}>
                      <Td className={unassigned ? "font-semibold" : "font-medium"} style={unassigned ? { color: "var(--c-warn)" } : undefined}>
                        {unassigned ? "Unassigned" : (r.owner_email || r.owner_id)}
                      </Td>
                      <Td className="font-medium">{r.open_total}</Td>
                      <Td>{r.open_critical > 0 ? <StatusTag tone="danger">{r.open_critical}</StatusTag> : "0"}</Td>
                      <Td>{r.open_high > 0 ? <StatusTag tone="warn">{r.open_high}</StatusTag> : "0"}</Td>
                      <Td>{r.sla_breached > 0 ? <StatusTag tone="danger">{r.sla_breached}</StatusTag> : "0"}</Td>
                      <Td>{r.sla_at_risk > 0 ? <StatusTag tone="warn">{r.sla_at_risk}</StatusTag> : "0"}</Td>
                      <Td className="text-right text-xs">{r.oldest_open_at ? new Date(r.oldest_open_at).toLocaleDateString() : "—"}</Td>
                    </tr>
                  );
                })}
              </Table>
            )}
          </Panel>

          <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            Need to rebalance? Open the <Link href="/console/incidents" style={{ color: "var(--c-primary)" }}>Incidents</Link> queue to reassign cases and clear the breaching ones first.
          </p>
        </div>
      )}
    </div>
  );
}
