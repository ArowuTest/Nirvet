"use client";

// Entity / blast-radius graph (§6.9). Given an entity ref (host / user / IP), compose the tenant's alerts,
// incidents, correlations and the matched inventory asset around it — the analyst's "what does this entity touch"
// view. Read-only, tenant-scoped (GET /entities/graph?ref=), reachable from alert & asset detail via ?ref=.

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Alert = { id: string; title: string; severity: string; status?: string; created_at?: string };
type Incident = { id: string; title: string; severity: string; status?: string; stage?: string };
type Correlation = { id: string; entity: string; status: string; alert_count: number; max_severity: string; risk_score: number; techniques: string[] | null; incident_id?: string };
type Asset = { id: string; ref: string; name: string; kind: string; criticality: string };
type Summary = { alert_count: number; incident_count: number; open_incidents: number; correlation_count: number; max_severity: string };
type Graph = { ref: string; asset?: Asset | null; alerts: Alert[] | null; incidents: Incident[] | null; correlations: Correlation[] | null; summary: Summary };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function EntitiesInner() {
  const qs = useSearchParams();
  const initial = qs.get("ref") ?? "";
  const [ref, setRef] = useState(initial);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">(initial ? "loading" : "idle");
  const [err, setErr] = useState("");

  const build = useCallback(async (r: string) => {
    const q = r.trim();
    if (!q) return;
    setState("loading"); setErr("");
    try {
      const g = await apiGet<Graph>(`/entities/graph?ref=${encodeURIComponent(q)}`);
      setGraph(g); setState("ready");
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not build the entity graph."); setState("error"); }
  }, []);

  useEffect(() => { if (initial) build(initial); }, [initial, build]);

  return (
    <div>
      <PageHeader title="Entity graph" sub="Blast radius for a host, user or IP — its alerts, incidents, correlations and asset" />

      <div className="mb-4 flex gap-2">
        <input value={ref} onChange={(e) => setRef(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") build(ref); }} placeholder="Entity ref — host / user / ip (e.g. host-01, user@corp, 10.0.0.5)" className="flex-1 rounded-lg px-3 py-2 text-sm" style={inputStyle} />
        <Button size="sm" disabled={!ref.trim()} onClick={() => build(ref)}>Build graph</Button>
      </div>

      {state === "idle" && <EmptyState title="Enter an entity ref" hint="Paste a host, user or IP to see everything connected to it." />}
      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Building…</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "ready" && graph && (
        <div className="space-y-5">
          <KpiStrip>
            <Kpi label="Alerts" value={String(graph.summary.alert_count)} />
            <Kpi label="Incidents" value={String(graph.summary.incident_count)} />
            <Kpi label="Open incidents" value={String(graph.summary.open_incidents)} />
            <Kpi label="Correlations" value={String(graph.summary.correlation_count)} />
            <Kpi label="Max severity" value={graph.summary.max_severity || "—"} />
          </KpiStrip>

          <Panel title="Asset" sub="Matched inventory record (if this entity is a managed asset)">
            {graph.asset ? (
              <div className="flex items-center gap-3">
                <Link href={`/console/assets/${graph.asset.id}`} className="font-medium" style={{ color: "var(--c-primary)" }}>{graph.asset.name || graph.asset.ref}</Link>
                <StatusTag tone="neutral">{graph.asset.kind}</StatusTag>
                <StatusTag tone={graph.asset.criticality === "critical" ? "danger" : graph.asset.criticality === "high" ? "warn" : "neutral"}>{graph.asset.criticality}</StatusTag>
              </div>
            ) : <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>This entity is not a managed asset in the inventory.</p>}
          </Panel>

          <Panel title="Alerts" bodyStyle={{ padding: 0 }}>
            {(graph.alerts ?? []).length === 0 ? <div className="p-6"><EmptyState title="No alerts" hint="No alerts reference this entity." /></div> : (
              <Table head={<><Th>Severity</Th><Th>Alert</Th><Th>Status</Th><Th className="text-right">Seen</Th></>}>
                {(graph.alerts ?? []).map((a) => (
                  <tr key={a.id} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td><SevBadge severity={a.severity} /></Td>
                    <Td><Link href={`/console/alerts?focus=${a.id}`} className="font-medium" style={{ color: "var(--c-primary)" }}>{a.title}</Link></Td>
                    <Td className="text-xs">{a.status ?? "—"}</Td>
                    <Td className="text-right text-xs">{a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <Panel title="Incidents" bodyStyle={{ padding: 0 }}>
            {(graph.incidents ?? []).length === 0 ? <div className="p-6"><EmptyState title="No incidents" hint="No incidents reference this entity." /></div> : (
              <Table head={<><Th>Severity</Th><Th>Incident</Th><Th>Stage</Th><Th className="text-right">Status</Th></>}>
                {(graph.incidents ?? []).map((i) => (
                  <tr key={i.id} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td><SevBadge severity={i.severity} /></Td>
                    <Td><Link href={`/console/incidents/${i.id}`} className="font-medium" style={{ color: "var(--c-primary)" }}>{i.title}</Link></Td>
                    <Td className="text-xs">{i.stage ?? "—"}</Td>
                    <Td className="text-right text-xs">{i.status ?? "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <Panel title="Correlations" bodyStyle={{ padding: 0 }}>
            {(graph.correlations ?? []).length === 0 ? <div className="p-6"><EmptyState title="No correlations" hint="No correlation clusters reference this entity." /></div> : (
              <Table head={<><Th>Risk</Th><Th>Entity</Th><Th>Alerts</Th><Th>Max sev</Th><Th>Techniques</Th><Th className="text-right">Status</Th></>}>
                {(graph.correlations ?? []).map((c) => (
                  <tr key={c.id}>
                    <Td className="font-semibold">{c.risk_score}</Td>
                    <Td className="font-mono text-xs">{c.entity}</Td>
                    <Td className="text-xs">{c.alert_count}</Td>
                    <Td>{c.max_severity ? <SevBadge severity={c.max_severity} /> : "—"}</Td>
                    <Td className="text-xs">{(c.techniques ?? []).join(", ") || "—"}</Td>
                    <Td className="text-right"><StatusTag tone={c.status === "open" ? "warn" : "neutral"}>{c.status}</StatusTag></Td>
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

export default function EntitiesPage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}>
      <EntitiesInner />
    </Suspense>
  );
}
