"use client";

// Customer overview (SRS §6.3 / UI-002). The customer's own posture: open incidents/alerts, SLA adherence,
// recent activity — all from the customer read-model (/customer/incidents, /customer/alerts), a positive-allowlist
// projection. KPIs are derived from the customer's own rows (honest, not a separate rollup — the exec rollup is
// read-model Slice B). No provider-internal data is reachable here.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, SevBadge, StatusTag, stageTone, EmptyState } from "@/components/ui";

type Incident = { incident_id: string; title: string; severity: string; status: string; created_at: string; ack_breached: boolean; resolve_breached: boolean };
type Alert = { alert_id: string; title: string; severity: string; status: string; affected_asset?: string; created_at: string };

const CLOSED = new Set(["closed", "post_incident_review"]);
const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];
const sevColor: Record<string, string> = { critical: "#fca5a5", high: "#fcd34d", medium: "#fde68a", low: "#7dd3fc", informational: "#cbd5e1" };

export default function PortalOverview() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiGet<{ incidents: Incident[] | null }>("/customer/incidents"),
      apiGet<{ alerts: Alert[] | null }>("/customer/alerts"),
    ]).then(([i, a]) => {
      if (i.status === "fulfilled") setIncidents(i.value.incidents ?? []);
      if (a.status === "fulfilled") setAlerts(a.value.alerts ?? []);
      setLoading(false);
    });
  }, []);

  const openInc = incidents.filter((i) => !CLOSED.has(i.status));
  const breaching = incidents.filter((i) => i.ack_breached || i.resolve_breached).length;
  const openAlerts = alerts.filter((a) => a.status === "new" || a.status === "assigned").length;
  // Severity mix, computed from the customer's own alert rows (no separate rollup — honest to what they can see).
  const sevCounts = alerts.reduce<Record<string, number>>((acc, a) => { acc[a.severity] = (acc[a.severity] ?? 0) + 1; return acc; }, {});
  const totalSev = Object.values(sevCounts).reduce((a, b) => a + b, 0);

  return (
    <div>
      <PageHeader title="Security overview" sub="Your organisation's incidents, alerts and service posture" />

      <KpiStrip>
        <Kpi label="Open Incidents" value={loading ? "—" : openInc.length} sub="active cases" tone={openInc.length > 0 ? "warn" : "default"} />
        <Kpi label="Open Alerts" value={loading ? "—" : openAlerts} sub="awaiting triage" />
        <Kpi label="SLA Breaching" value={loading ? "—" : breaching} sub="overdue" tone={breaching > 0 ? "danger" : "ok"} />
        <Kpi label="Incidents (total)" value={loading ? "—" : incidents.length} sub="all time" />
      </KpiStrip>

      <div className="mt-6 grid gap-6" style={{ gridTemplateColumns: "1.3fr 1fr" }}>
        <Panel title="Recent incidents" sub="Cases affecting your estate" actions={<Link href="/portal/incidents" className="text-[12px]" style={{ color: "var(--c-primary)" }}>All →</Link>} bodyStyle={{ padding: 0 }}>
          {loading ? <div className="p-5 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : openInc.length === 0 ? (
            <div className="p-5"><EmptyState title="No open incidents" hint="Your estate is clear right now." /></div>
          ) : (
            <ul>
              {openInc.slice(0, 6).map((i) => (
                <li key={i.incident_id} className="flex items-center gap-3 px-5 py-3" style={{ borderTop: "1px solid var(--c-border)" }}>
                  <SevBadge severity={i.severity} />
                  <Link href={`/portal/incidents/${i.incident_id}`} className="min-w-0 flex-1 truncate text-sm hover:underline" style={{ color: "var(--c-ink)" }}>{i.title}</Link>
                  {(i.ack_breached || i.resolve_breached) && <StatusTag tone="danger">SLA</StatusTag>}
                  <StatusTag tone={stageTone(i.status)}>{i.status.replace(/_/g, " ")}</StatusTag>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Alert severity mix" sub="Your alerts by severity">
          {loading ? <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</p> : totalSev === 0 ? (
            <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>No alerts to summarise.</p>
          ) : (
            <div className="space-y-2.5">
              {SEV_ORDER.filter((s) => sevCounts[s]).map((s) => {
                const pct = Math.round((sevCounts[s] / totalSev) * 100);
                return (
                  <div key={s}>
                    <div className="mb-1 flex items-center justify-between text-[12px]">
                      <span className="capitalize" style={{ color: "var(--c-ink-2)" }}>{s}</span>
                      <span style={{ color: "var(--c-ink-3)" }}>{sevCounts[s]} · {pct}%</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full" style={{ background: "var(--c-surface-2)" }}>
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: sevColor[s] }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      <div className="mt-6">
        <Panel title="Recent alerts" actions={<Link href="/portal/alerts" className="text-[12px]" style={{ color: "var(--c-primary)" }}>All →</Link>}>
          {loading ? <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</p> : alerts.length === 0 ? (
            <EmptyState title="No alerts" hint="Nothing to show." />
          ) : (
            <ul className="space-y-2.5">
              {alerts.slice(0, 6).map((a) => (
                <li key={a.alert_id} className="flex items-center gap-3">
                  <SevBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm" style={{ color: "var(--c-ink)" }}>{a.title}</div>
                    {a.affected_asset && <div className="truncate text-[11px]" style={{ color: "var(--c-ink-3)" }}>{a.affected_asset}</div>}
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
