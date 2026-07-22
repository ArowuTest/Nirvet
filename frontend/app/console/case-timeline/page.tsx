"use client";

// Multi-lane case timeline (#188, §6.9) — the whole story of a case in one chronological stream: raw events, analyst
// actions, automation runs, customer comms and evidence, each on its own lane. GET /investigation/case-timeline
// ?incident={uuid}[&refs=kind:value,…][&from&to]. Read-only, provider tier, tenant-scoped. Complements the incident
// detail's own journal by folding in the correlated ENTITY event stream (the refs) alongside the case journal, so an
// analyst sees the attacker's actions and the responder's actions on one shared clock. Backend existed with no UI.

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Entry = {
  at: string;
  lane: "event" | "analyst" | "automation" | "comms" | "evidence" | string;
  source?: string;
  entity?: string;
  actor?: string;
  summary: string;
  severity?: string;
  outcome?: string;
};
type CaseTimeline = { incident_id: string; entries: Entry[] | null };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

// Lane → visual identity. Each lane gets a dot colour + label so the eye can separate attacker (event) from
// responder (analyst/automation) from customer (comms) from custody (evidence) at a glance.
const LANES: { key: Entry["lane"]; label: string; color: string; tone: "info" | "ok" | "warn" | "danger" | "neutral" }[] = [
  { key: "event", label: "Event", color: "#f59e0b", tone: "warn" },
  { key: "analyst", label: "Analyst", color: "var(--c-primary)", tone: "info" },
  { key: "automation", label: "Automation", color: "#8b5cf6", tone: "neutral" },
  { key: "comms", label: "Comms", color: "#06b6d4", tone: "info" },
  { key: "evidence", label: "Evidence", color: "#10b981", tone: "ok" },
];
const laneMeta = (l: string) => LANES.find((x) => x.key === l) ?? { key: l, label: l, color: "var(--c-ink-3)", tone: "neutral" as const };

function fmt(dt: string) {
  return dt ? new Date(dt).toLocaleString() : "—";
}

function CaseTimelineInner() {
  const qs = useSearchParams();
  const incident = qs.get("incident") ?? "";
  const [refs, setRefs] = useState("");
  const [tl, setTl] = useState<CaseTimeline | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">(incident ? "loading" : "idle");
  const [err, setErr] = useState("");
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  const load = useCallback(async (inc: string, r: string) => {
    if (!inc) return;
    setState("loading");
    setErr("");
    try {
      const params = new URLSearchParams({ incident: inc });
      const cleanRefs = r.split(",").map((s) => s.trim()).filter(Boolean);
      if (cleanRefs.length) params.set("refs", cleanRefs.join(","));
      const res = await apiGet<CaseTimeline>(`/investigation/case-timeline?${params.toString()}`);
      setTl(res);
      setState("ready");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Could not build the case timeline.");
      setState("error");
    }
  }, []);

  useEffect(() => {
    if (incident) load(incident, "");
  }, [incident, load]);

  function toggleLane(k: string) {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  }

  const entries = (tl?.entries ?? []).filter((e) => !hidden.has(e.lane));

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader title="Case timeline" sub="Every lane of the case — events, analyst actions, automation, comms and evidence — on one clock" />

      {incident ? (
        <div className="mb-4">
          <Link href={`/console/incidents/${incident}`} className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Back to case</Link>
          <div className="mt-2 flex gap-2">
            <input
              value={refs}
              onChange={(e) => setRefs(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") load(incident, refs); }}
              placeholder="Optional: fold in entity events — host:host-01, user:alice@corp (comma-separated, max 10)"
              className="flex-1 rounded-lg px-3 py-2 text-sm"
              style={inputStyle}
            />
            <Button size="sm" onClick={() => load(incident, refs)}>Rebuild</Button>
          </div>
        </div>
      ) : (
        <EmptyState title="No case selected" hint="Open a case timeline from an incident's detail page." />
      )}

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Building…</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "ready" && tl && (
        <>
          {/* Lane legend / filter — click a lane to hide it. */}
          <div className="mb-4 flex flex-wrap gap-2">
            {LANES.map((l) => {
              const off = hidden.has(l.key);
              return (
                <button
                  key={l.key}
                  onClick={() => toggleLane(l.key)}
                  className="flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] transition"
                  style={{ background: off ? "transparent" : "var(--c-surface-2)", border: "1px solid var(--c-border)", color: off ? "var(--c-ink-3)" : "var(--c-ink-2)", opacity: off ? 0.5 : 1 }}
                >
                  <span className="h-2 w-2 rounded-full" style={{ background: l.color }} />
                  {l.label}
                </button>
              );
            })}
          </div>

          <Panel title={`Timeline`} sub={`${entries.length} entr${entries.length === 1 ? "y" : "ies"}`}>
            {entries.length === 0 ? (
              <EmptyState title="No entries" hint="No activity in the window for the selected lanes. Widen the window or enable more lanes." />
            ) : (
              <ol className="space-y-4">
                {entries.map((e, i) => {
                  const m = laneMeta(e.lane);
                  return (
                    <li key={`${e.at}-${i}`} className="relative pl-5">
                      <span className="absolute left-0 top-1.5 h-2.5 w-2.5 rounded-full" style={{ background: m.color }} />
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusTag tone={m.tone}>{m.label}</StatusTag>
                        {e.severity && <SevBadge severity={e.severity} />}
                        <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fmt(e.at)}</span>
                        {(e.actor || e.entity) && <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>· {e.actor || e.entity}</span>}
                        {e.source && <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>· {e.source}</span>}
                      </div>
                      <p className="mt-1 text-sm" style={{ color: "var(--c-ink-2)" }}>{e.summary}</p>
                      {e.outcome && <span className="mt-1 inline-block text-[11px]" style={{ color: "var(--c-ink-3)" }}>outcome: {e.outcome}</span>}
                    </li>
                  );
                })}
              </ol>
            )}
          </Panel>

          <div className="mt-3 flex items-center gap-2 text-xs" style={{ color: "var(--c-ink-3)" }}>
            <StatusTag tone="neutral">read-only</StatusTag>
            <span>Default window: last 7 days.</span>
          </div>
        </>
      )}
    </div>
  );
}

export default function CaseTimelinePage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}>
      <CaseTimelineInner />
    </Suspense>
  );
}
