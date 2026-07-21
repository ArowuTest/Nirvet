"use client";

// Forensic entity timeline + typed pivot (§6.9). Given an entity ref (host / user / IP), show its events in
// chronological order over a bounded window (GET /investigation/get-timeline) and the entities one hop away
// (GET /investigation/get-entity-graph — the typed pivot). Read-only, tenant-scoped, provider+. Complements the
// blast-radius "Entity graph" view with the *when* (timeline) and the *who's next to it* (pivot).

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Entity = { kind: string; value: string };
type TimelineEntry = {
  event_time: string; ingest_time: string; source: string; entity: string;
  action: string; severity: string; confidence: number; outcome: string; lane: string;
};
type Timeline = { entity: Entity; entries: TimelineEntry[] | null };
type Neighbor = { entity: Entity; via: string; alert_id: string; severity: string };
type Pivot = { center: Entity; neighbors: Neighbor[] | null };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function refStr(e: Entity) { return `${e.kind}:${e.value}`; }

function TimelineInner() {
  const qs = useSearchParams();
  const initial = qs.get("ref") ?? "";
  const [ref, setRef] = useState(initial);
  const [timeline, setTimeline] = useState<Timeline | null>(null);
  const [pivot, setPivot] = useState<Pivot | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">(initial ? "loading" : "idle");
  const [err, setErr] = useState("");

  const load = useCallback(async (r: string) => {
    const q = r.trim();
    if (!q) return;
    setState("loading"); setErr("");
    try {
      // The pivot is best-effort — a timeline is still useful if the pivot read fails.
      const [tl, pv] = await Promise.all([
        apiGet<Timeline>(`/investigation/get-timeline?ref=${encodeURIComponent(q)}`),
        apiGet<Pivot>(`/investigation/get-entity-graph?ref=${encodeURIComponent(q)}`).catch(() => null),
      ]);
      setTimeline(tl); setPivot(pv); setState("ready");
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not build the timeline."); setState("error"); }
  }, []);

  useEffect(() => { if (initial) load(initial); }, [initial, load]);

  const entries = timeline?.entries ?? [];
  const neighbors = pivot?.neighbors ?? [];

  return (
    <div>
      <PageHeader title="Forensic timeline" sub="Every event touching an entity, in order — plus the entities one hop away" />

      <div className="mb-4 flex gap-2">
        <input value={ref} onChange={(e) => setRef(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") load(ref); }} placeholder="Entity ref — host / user / ip (e.g. host:host-01, user:alice@corp, ip:10.0.0.5)" className="flex-1 rounded-lg px-3 py-2 text-sm" style={inputStyle} />
        <Button size="sm" disabled={!ref.trim()} onClick={() => load(ref)}>Build timeline</Button>
      </div>

      {state === "idle" && <EmptyState title="Enter an entity ref" hint="Paste a host, user or IP to see its events in chronological order." />}
      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Building…</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "ready" && timeline && (
        <div className="space-y-5">
          <Panel title={`Timeline — ${timeline.entity ? refStr(timeline.entity) : ref}`} sub={`${entries.length} event${entries.length === 1 ? "" : "s"} in the window`} bodyStyle={{ padding: 0 }}>
            {entries.length === 0 ? (
              <div className="p-6"><EmptyState title="No events" hint="No events reference this entity in the current window. Widen the window or check the entity ref." /></div>
            ) : (
              <Table head={<><Th>When</Th><Th>Source</Th><Th>Action</Th><Th>Severity</Th><Th>Conf.</Th><Th className="text-right">Outcome</Th></>}>
                {entries.map((e, i) => (
                  <tr key={`${e.event_time}-${i}`} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td className="whitespace-nowrap text-xs">{e.event_time ? new Date(e.event_time).toLocaleString() : "—"}</Td>
                    <Td className="text-xs">{e.source || "—"}</Td>
                    <Td className="text-xs">{e.action || "—"}</Td>
                    <Td>{e.severity ? <SevBadge severity={e.severity} /> : "—"}</Td>
                    <Td className="text-xs">{e.confidence ?? "—"}</Td>
                    <Td className="text-right text-xs">{e.outcome || "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <Panel title="Pivot — one hop away" sub="Entities that share an alert with this one" bodyStyle={{ padding: 0 }}>
            {neighbors.length === 0 ? (
              <div className="p-6"><EmptyState title="No linked entities" hint="No other entity shares an alert with this one." /></div>
            ) : (
              <Table head={<><Th>Entity</Th><Th>Via</Th><Th>Severity</Th><Th className="text-right">Pivot</Th></>}>
                {neighbors.map((n, i) => (
                  <tr key={`${n.alert_id}-${i}`} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td className="font-mono text-xs">{n.entity ? refStr(n.entity) : "—"}</Td>
                    <Td className="text-xs">{n.via || "—"}</Td>
                    <Td>{n.severity ? <SevBadge severity={n.severity} /> : "—"}</Td>
                    <Td className="text-right">
                      {n.entity && (
                        <Link href={`/console/timeline?ref=${encodeURIComponent(refStr(n.entity))}`} className="text-xs font-medium" style={{ color: "var(--c-primary)" }}>Timeline →</Link>
                      )}
                    </Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <div className="flex items-center gap-3 text-xs" style={{ color: "var(--c-ink-3)" }}>
            <StatusTag tone="neutral">read-only</StatusTag>
            <Link href={`/console/entities?ref=${encodeURIComponent(ref)}`} style={{ color: "var(--c-primary)" }}>See full blast-radius graph →</Link>
          </div>
        </div>
      )}
    </div>
  );
}

export default function TimelinePage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}>
      <TimelineInner />
    </Suspense>
  );
}
