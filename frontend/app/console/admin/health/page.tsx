"use client";

// Platform health (§6.18 slice B / B3). Operator view of THIS instance's health, wired to GET /admin/health
// (padmin). Honest single-sovereign model: live db + event-store status, configured backend names for the soft
// dependencies (queue/blob/cache), and real Go-runtime signal. No fabricated fleet/nodes — an explicit note says
// the multi-node fleet view is N/A on this deployment.

import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, StatusTag, Button } from "@/components/ui";

type Dependency = { name: string; status: string; detail?: string };
type Runtime = { uptime_seconds: number; goroutines: number; heap_alloc_bytes: number; num_gc: number; num_cpu: number; go_version: string };
type Health = { status: string; checked_at: string; instance: string; dependencies: Dependency[] | null; runtime: Runtime };

function depTone(s: string): "ok" | "warn" | "danger" | "neutral" {
  if (s === "ok") return "ok";
  if (s === "unavailable") return "danger";
  return "neutral"; // configured / in-memory / redis
}
function fmtUptime(sec: number) {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}
function fmtBytes(b: number) {
  if (b > 1 << 30) return `${(b / (1 << 30)).toFixed(1)} GB`;
  if (b > 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`;
  return `${(b / 1024).toFixed(0)} KB`;
}

export default function PlatformHealthPage() {
  const [h, setH] = useState<Health | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "forbidden" | "error">("loading");

  const load = useCallback(async () => {
    setState("loading");
    try { setH(await apiGet<Health>("/admin/health")); setState("ready"); }
    catch (e) { setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "error"); }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <PageHeader
        title="Platform health"
        sub="Liveness of this Nirvet instance and its dependencies"
        actions={h && <Button size="sm" variant="ghost" onClick={load}>Refresh</Button>}
      />

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}
      {state === "forbidden" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(245,158,11,0.12)", color: "#f59e0b", border: "1px solid var(--c-border)" }}>Platform health is limited to platform-admin.</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>Could not read platform health.</div>}

      {state === "ready" && h && (
        <div className="space-y-5">
          <div className="flex items-center gap-3">
            <StatusTag tone={h.status === "ok" ? "ok" : "danger"}>{h.status === "ok" ? "Healthy" : "Degraded"}</StatusTag>
            <span className="text-xs" style={{ color: "var(--c-ink-3)" }}>checked {new Date(h.checked_at).toLocaleTimeString()}</span>
          </div>

          <KpiStrip>
            <Kpi label="Uptime" value={fmtUptime(h.runtime.uptime_seconds)} />
            <Kpi label="Goroutines" value={String(h.runtime.goroutines)} />
            <Kpi label="Heap in use" value={fmtBytes(h.runtime.heap_alloc_bytes)} />
            <Kpi label="GC cycles" value={String(h.runtime.num_gc)} />
            <Kpi label="CPUs" value={String(h.runtime.num_cpu)} />
          </KpiStrip>

          <Panel title="Dependencies" sub="Hard dependencies (database, event store) are probed live; soft dependencies show their configured backend" bodyStyle={{ padding: 0 }}>
            <Table head={<><Th>Dependency</Th><Th>Status</Th><Th className="text-right">Backend</Th></>}>
              {(h.dependencies ?? []).map((d) => (
                <tr key={d.name}>
                  <Td className="font-medium capitalize">{d.name.replace(/_/g, " ")}</Td>
                  <Td><StatusTag tone={depTone(d.status)}>{d.status}</StatusTag></Td>
                  <Td className="text-right font-mono text-xs">{d.detail || "—"}</Td>
                </tr>
              ))}
            </Table>
          </Panel>

          <Panel title="Runtime">
            <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm md:grid-cols-3">
              <div><span style={{ color: "var(--c-ink-3)" }}>Go version</span><div style={{ color: "var(--c-ink)" }}>{h.runtime.go_version}</div></div>
              <div><span style={{ color: "var(--c-ink-3)" }}>Instance model</span><div style={{ color: "var(--c-ink)" }}>{h.instance}</div></div>
            </div>
            <p className="mt-4 text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              This is a single sovereign instance. A multi-node fleet / cluster view (per-node CPU, autoscaling, host
              infrastructure) is not applicable on this deployment and is intentionally not shown rather than fabricated.
            </p>
          </Panel>
        </div>
      )}
    </div>
  );
}
