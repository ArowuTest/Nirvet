"use client";

// SOC Dashboard — the console landing screen. Built to the approved SOC-Dashboard-v2 mockup using the shared
// design-system primitives (components/ui), wired to the real backend: GET /reports/summary (KPIs), /incidents/
// at-risk (SLA-at-risk incidents), /alerts (recent queue). Resilient to an offline backend so the design still
// renders (empty states, not a crash).

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { Panel, KpiStrip, Kpi, SevBadge, StatusTag, stageTone, PageHeader, Table, Th, Td, EmptyState } from "@/components/ui";

type Summary = {
  open_alerts: number;
  open_incidents: number;
  events_last_24h: number;
  sla: { open_incidents: number; ack_breaching: number; resolve_breaching: number; resolved_late: number };
  mean_times: { mttr_seconds: number | null; resolved_count: number };
};
type Incident = { id: string; title: string; severity: string; stage: string; created_at: string; resolve_due_at?: string };
type Alert = { id: string; title: string; severity: string; status: string; source: string; created_at: string };

function mttr(sec: number | null): string {
  if (sec == null) return "—";
  const h = sec / 3600;
  return h >= 1 ? `${h.toFixed(1)}h` : `${Math.round(sec / 60)}m`;
}

export default function DashboardPage() {
  const [sum, setSum] = useState<Summary | null>(null);
  const [atRisk, setAtRisk] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [err, setErr] = useState(false);

  useEffect(() => {
    Promise.allSettled([
      apiGet<Summary>("/reports/summary"),
      apiGet<{ incidents: Incident[] | null }>("/incidents/at-risk"),
      apiGet<{ alerts: Alert[] | null }>("/alerts"),
    ]).then(([s, i, a]) => {
      if (s.status === "fulfilled") setSum(s.value);
      else setErr(true);
      if (i.status === "fulfilled") setAtRisk(i.value.incidents ?? []);
      if (a.status === "fulfilled") setAlerts((a.value.alerts ?? []).slice(0, 6));
    });
  }, []);

  return (
    <div>
      <PageHeader title="SOC Dashboard" sub="Live operational posture across your monitored estate" />

      <KpiStrip>
        <Kpi label="Open Incidents" value={sum?.open_incidents ?? "—"} sub="active cases" tone={sum && sum.open_incidents > 0 ? "warn" : "default"} />
        <Kpi label="Open Alerts" value={sum?.open_alerts ?? "—"} sub="awaiting triage" />
        <Kpi
          label="SLA Breaching"
          value={sum ? sum.sla.ack_breaching + sum.sla.resolve_breaching : "—"}
          sub="ack + resolve overdue"
          tone={sum && sum.sla.ack_breaching + sum.sla.resolve_breaching > 0 ? "danger" : "ok"}
        />
        <Kpi label="MTTR" value={mttr(sum?.mean_times.mttr_seconds ?? null)} sub={`${sum?.mean_times.resolved_count ?? 0} resolved`} />
        <Kpi label="Events · 24h" value={sum ? sum.events_last_24h.toLocaleString() : "—"} sub="ingested" />
      </KpiStrip>

      {err && (
        <p className="mt-4 text-[12px]" style={{ color: "var(--c-ink-3)" }}>
          Live metrics unavailable — the API isn’t reachable from this browser session.
        </p>
      )}

      <div className="mt-6 grid gap-6" style={{ gridTemplateColumns: "1.4fr 1fr" }}>
        <Panel
          title="Incidents at risk"
          sub="Open incidents past or nearing an SLA deadline"
          actions={<Link href="/console/incidents" className="text-[12px]" style={{ color: "var(--c-primary)" }}>All incidents →</Link>}
          bodyStyle={{ padding: 0 }}
        >
          {atRisk.length === 0 ? (
            <div className="p-5"><EmptyState title="No incidents at risk" hint="All open incidents are within their SLA windows." /></div>
          ) : (
            <Table head={<><Th>Severity</Th><Th>Incident</Th><Th>Stage</Th><Th className="text-right">Resolve due</Th></>}>
              {atRisk.map((i) => (
                <tr key={i.id}>
                  <Td><SevBadge severity={i.severity} /></Td>
                  <Td className="!text-[color:var(--c-ink)]">
                    <Link href={`/console/incidents/${i.id}`} className="hover:underline">{i.title}</Link>
                  </Td>
                  <Td><StatusTag tone={stageTone(i.stage)}>{i.stage}</StatusTag></Td>
                  <Td className="text-right font-mono text-xs">{i.resolve_due_at ? new Date(i.resolve_due_at).toLocaleString() : "—"}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>

        <Panel
          title="Alert queue"
          sub="Most recent alerts awaiting triage"
          actions={<Link href="/console/alerts" className="text-[12px]" style={{ color: "var(--c-primary)" }}>Queue →</Link>}
        >
          {alerts.length === 0 ? (
            <EmptyState title="Queue is clear" hint="No untriaged alerts right now." />
          ) : (
            <ul className="space-y-2.5">
              {alerts.map((a) => (
                <li key={a.id} className="flex items-center gap-3">
                  <SevBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm" style={{ color: "var(--c-ink)" }}>{a.title}</div>
                    <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{a.source} · {new Date(a.created_at).toLocaleTimeString()}</div>
                  </div>
                  <StatusTag tone={a.status === "new" ? "info" : "neutral"}>{a.status}</StatusTag>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
