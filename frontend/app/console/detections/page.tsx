"use client";

// Detection rule catalogue (SRS §6.6 / DET-001/003/006/008). Lists the detection-as-code rules
// (GET /detections → {rules}), global (tenant nil) + tenant-owned, with lifecycle stage, enabled state,
// severity, MITRE, and kind (simple/threshold/distinct). Coverage gaps (GET /detections/coverage) surface
// data-source dependencies a tenant can't satisfy. Authoring/lifecycle actions are detEng-gated server-side.

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Rule = {
  id: string;
  tenant_id?: string | null;
  name: string;
  description: string;
  severity: string;
  confidence: number;
  mitre: string[] | null;
  enabled: boolean;
  stage: string;
  version: number;
  kind: string;
  created_at: string;
};
type Gap = { rule_id?: string; rule_name?: string; source?: string; missing?: string } & Record<string, unknown>;

const ACTIVE = new Set(["pilot", "production", "tuned"]);
function stageToneOf(s: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  if (s === "production" || s === "tuned") return "ok";
  if (s === "pilot") return "info";
  if (s === "retired") return "neutral";
  return "warn"; // draft / peer_review / qa
}

const STAGES = ["", "draft", "peer_review", "qa", "pilot", "production", "tuned", "retired"];

export default function DetectionsPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [gaps, setGaps] = useState<Gap[]>([]);
  const [loading, setLoading] = useState(true);
  const [stage, setStage] = useState("");
  const [q, setQ] = useState("");

  const load = useCallback(async () => {
    const [r, g] = await Promise.allSettled([
      apiGet<{ rules: Rule[] | null }>("/detections"),
      apiGet<{ gaps: Gap[] | null }>("/detections/coverage"),
    ]);
    if (r.status === "fulfilled") setRules(r.value.rules ?? []);
    if (g.status === "fulfilled") setGaps(g.value.gaps ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const shown = useMemo(
    () =>
      rules.filter(
        (r) => (!stage || r.stage === stage) && (!q || r.name.toLowerCase().includes(q.toLowerCase()) || (r.mitre ?? []).some((m) => m.toLowerCase().includes(q.toLowerCase())))
      ),
    [rules, stage, q]
  );

  const activeCount = rules.filter((r) => r.enabled && ACTIVE.has(r.stage)).length;

  return (
    <div>
      <PageHeader
        title="Detections"
        sub="Detection-as-code rule catalogue — lifecycle, coverage and tuning"
        actions={<Link href="/console/detections/new"><Button size="sm">New rule</Button></Link>}
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>
          <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{activeCount}</span> active · <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{rules.length}</span> total
        </div>
        <select value={stage} onChange={(e) => setStage(e.target.value)} className="rounded-lg px-2.5 py-1.5 text-xs capitalize" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}>
          {STAGES.map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, " ") : "All stages"}</option>)}
        </select>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name or MITRE…" className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-none" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)", minWidth: 180 }} />
      </div>

      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading rules…</div>
        ) : shown.length === 0 ? (
          <div className="p-6"><EmptyState title="No rules" hint="No detection rules match this filter." /></div>
        ) : (
          <Table head={<><Th>Severity</Th><Th>Rule</Th><Th>Stage</Th><Th>Kind</Th><Th>MITRE</Th><Th className="text-right">Enabled</Th></>}>
            {shown.map((r) => (
              <tr key={r.id}>
                <Td><SevBadge severity={r.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]">
                  <Link href={`/console/detections/${r.id}`} className="font-medium hover:underline">{r.name}</Link>
                  {!r.tenant_id && <span className="ml-2 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "rgba(99,102,241,0.15)", color: "#a5b4fc" }}>GLOBAL</span>}
                  <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>v{r.version} · conf {r.confidence}%</div>
                </Td>
                <Td><StatusTag tone={stageToneOf(r.stage)}>{r.stage.replace(/_/g, " ")}</StatusTag></Td>
                <Td className="text-xs capitalize">{r.kind}</Td>
                <Td className="font-mono text-[11px]">{(r.mitre ?? []).slice(0, 3).join(", ") || "—"}</Td>
                <Td className="text-right">
                  <StatusTag tone={r.enabled ? "ok" : "neutral"}>{r.enabled ? "on" : "off"}</StatusTag>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {gaps.length > 0 && (
        <div className="mt-6">
          <Panel title="Coverage gaps" sub="Rules that depend on a data source not active for this tenant (DET-009)">
            <ul className="space-y-2">
              {gaps.map((g, i) => (
                <li key={i} className="flex items-center gap-2 text-[13px]" style={{ color: "var(--c-ink-2)" }}>
                  <StatusTag tone="warn">gap</StatusTag>
                  <span>{g.rule_name ?? g.rule_id ?? "rule"}</span>
                  {g.missing && <span style={{ color: "var(--c-ink-3)" }}>— needs {String(g.missing)}</span>}
                  {!g.missing && g.source && <span style={{ color: "var(--c-ink-3)" }}>— {String(g.source)}</span>}
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      )}
    </div>
  );
}
