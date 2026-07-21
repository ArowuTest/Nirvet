"use client";

// Data-gaps — "what you are NOT seeing" (INV-009). Three blind-spot signals for the tenant: live detection rules
// starved of their source, host sources that went quiet, and sources whose parse confidence collapsed. Read-only,
// tenant-scoped (GET /investigation/data-gaps), provider+. An honest SOC surfaces its own coverage holes.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, StatusTag, EmptyState } from "@/components/ui";

type CoverageGap = { rule_id: string; name: string; stage: string; missing_deps: string[] | null };
type SilentSource = { source?: string; last_seen?: string; expected?: string; [k: string]: unknown };
type DriftingSource = { source: string; events: number; avg_confidence: number; parser: string; parser_version: number; drift: boolean };
type DataGaps = { coverage_gaps: CoverageGap[] | null; silent_sources: SilentSource[] | null; drifting_sources: DriftingSource[] | null };

export default function DataGapsPage() {
  const [gaps, setGaps] = useState<DataGaps | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [err, setErr] = useState("");

  useEffect(() => {
    (async () => {
      try { setGaps(await apiGet<DataGaps>("/investigation/data-gaps")); setState("ready"); }
      catch (e) { setErr(e instanceof ApiError ? e.message : "Could not load data gaps."); setState("error"); }
    })();
  }, []);

  const coverage = gaps?.coverage_gaps ?? [];
  const silent = gaps?.silent_sources ?? [];
  const drift = gaps?.drifting_sources ?? [];
  const clean = state === "ready" && coverage.length === 0 && silent.length === 0 && drift.length === 0;

  return (
    <div>
      <PageHeader title="Data gaps" sub="What you are not seeing — starved rules, silent sources, and collapsing parse quality" />

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "ready" && (
        <div className="space-y-5">
          <KpiStrip>
            <Kpi label="Starved rules" value={String(coverage.length)} />
            <Kpi label="Silent sources" value={String(silent.length)} />
            <Kpi label="Drifting sources" value={String(drift.length)} />
          </KpiStrip>

          {clean && <EmptyState title="No blind spots detected" hint="Every live rule has its source, no source has gone quiet, and parse confidence is holding. This is the good state." />}

          <Panel title="Starved detection rules" sub="Live rules whose required source is not arriving — they cannot fire" bodyStyle={{ padding: 0 }}>
            {coverage.length === 0 ? <div className="p-6"><EmptyState title="None" hint="No live rule is missing its source." /></div> : (
              <Table head={<><Th>Rule</Th><Th>Stage</Th><Th className="text-right">Missing source(s)</Th></>}>
                {coverage.map((c) => (
                  <tr key={c.rule_id} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td><Link href={`/console/detections?focus=${c.rule_id}`} className="font-medium" style={{ color: "var(--c-primary)" }}>{c.name}</Link></Td>
                    <Td className="text-xs">{c.stage || "—"}</Td>
                    <Td className="text-right text-xs">{(c.missing_deps ?? []).join(", ") || "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <Panel title="Silent sources" sub="Host sources that were reporting and went quiet" bodyStyle={{ padding: 0 }}>
            {silent.length === 0 ? <div className="p-6"><EmptyState title="None" hint="No source has gone unexpectedly quiet." /></div> : (
              <Table head={<><Th>Source</Th><Th>Expected</Th><Th className="text-right">Last seen</Th></>}>
                {silent.map((s, i) => (
                  <tr key={`${String(s.source ?? "")}-${i}`} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td className="text-xs">{String(s.source ?? "—")}</Td>
                    <Td className="text-xs">{s.expected ? String(s.expected) : "—"}</Td>
                    <Td className="text-right text-xs">{s.last_seen ? new Date(String(s.last_seen)).toLocaleString() : "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <Panel title="Drifting sources" sub="Sources whose average parse confidence dropped below the tenant floor" bodyStyle={{ padding: 0 }}>
            {drift.length === 0 ? <div className="p-6"><EmptyState title="None" hint="Parse confidence is holding across sources." /></div> : (
              <Table head={<><Th>Source</Th><Th>Parser</Th><Th>Events</Th><Th>Avg confidence</Th><Th className="text-right">State</Th></>}>
                {drift.map((d, i) => (
                  <tr key={`${d.source}-${i}`} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td className="text-xs">{d.source || "—"}</Td>
                    <Td className="text-xs">{d.parser ? `${d.parser} v${d.parser_version}` : "—"}</Td>
                    <Td className="text-xs">{d.events}</Td>
                    <Td className="text-xs">{d.avg_confidence}</Td>
                    <Td className="text-right"><StatusTag tone={d.drift ? "warn" : "neutral"}>{d.drift ? "drifting" : "ok"}</StatusTag></Td>
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
