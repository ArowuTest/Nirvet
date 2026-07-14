"use client";

// Detection rule detail (DET-001/003/006/007). Resolves the rule from GET /detections (no single-get route),
// plus version history (/versions), FP-feedback tuning stats (/feedback), and test cases (/tests). Lifecycle
// transitions (POST /transition) advance draft→…→production→tuned→retired; enable toggle (POST /enabled); run
// tests (POST /tests/run). All authoring/lifecycle actions are detEng-gated server-side → 403 surfaced.

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Predicate = { field: string; op: string; value: string };
type Rule = {
  id: string;
  tenant_id?: string | null;
  name: string;
  description: string;
  severity: string;
  confidence: number;
  mitre: string[] | null;
  condition: { all?: Predicate[]; any?: Predicate[] };
  expression?: string;
  enabled: boolean;
  stage: string;
  version: number;
  kind: string;
  window_seconds?: number;
  threshold?: number;
  entity_field?: string;
  created_at: string;
};
type Version = { version: number; stage?: string; note?: string; at?: string; created_at?: string } & Record<string, unknown>;
type Feedback = { total: number; by_disposition: Record<string, number> | null; false_positives: number; fp_rate: number; tuning_recommended: boolean };
type TestCase = { id: string; name?: string; expect_match?: boolean } & Record<string, unknown>;

// Forward lifecycle (SRS §9.4). Any active stage may also retire.
const NEXT: Record<string, string[]> = {
  draft: ["peer_review"],
  peer_review: ["qa", "draft"],
  qa: ["pilot"],
  pilot: ["production"],
  production: ["tuned", "retired"],
  tuned: ["retired"],
  retired: [],
};
function stageToneOf(s: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  if (s === "production" || s === "tuned") return "ok";
  if (s === "pilot") return "info";
  if (s === "retired") return "neutral";
  return "warn";
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div>
      <div className="mt-1 text-sm" style={{ color: "var(--c-ink)" }}>{children}</div>
    </div>
  );
}

export default function DetectionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [rule, setRule] = useState<Rule | null>(null);
  const [versions, setVersions] = useState<Version[]>([]);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [tests, setTests] = useState<TestCase[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "notfound">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const list = await apiGet<{ rules: Rule[] | null }>("/detections");
      const r = (list.rules ?? []).find((x) => x.id === id);
      if (!r) return setState("notfound");
      setRule(r);
      setState("ready");
      const [v, f, t] = await Promise.allSettled([
        apiGet<{ versions: Version[] | null }>(`/detections/${id}/versions`),
        apiGet<Feedback>(`/detections/${id}/feedback`),
        apiGet<{ test_cases?: TestCase[] | null; tests?: TestCase[] | null }>(`/detections/${id}/tests`),
      ]);
      if (v.status === "fulfilled") setVersions(v.value.versions ?? []);
      if (f.status === "fulfilled") setFeedback(f.value);
      if (t.status === "fulfilled") setTests(t.value.test_cases ?? t.value.tests ?? []);
    } catch {
      setState("notfound");
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    setBusy(true);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "This requires a detection-engineer role." : e instanceof Error ? e.message : "Action failed." });
    } finally {
      setBusy(false);
    }
  }

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "notfound" || !rule)
    return (
      <div>
        <PageHeader title="Detection rule" />
        <EmptyState title="Rule not found" hint="It may have been retired, or you don't have access." />
      </div>
    );

  const preds = [...(rule.condition?.all ?? []).map((p) => ({ ...p, join: "AND" })), ...(rule.condition?.any ?? []).map((p) => ({ ...p, join: "OR" }))];
  const nexts = NEXT[rule.stage] ?? [];

  return (
    <div className="mx-auto max-w-5xl">
      <Link href="/console/detections" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Detections</Link>
      <div className="mt-2">
        <PageHeader
          title={rule.name}
          sub={rule.description || `Detection rule · v${rule.version}`}
          actions={<div className="flex items-center gap-2"><SevBadge severity={rule.severity} /><StatusTag tone={stageToneOf(rule.stage)}>{rule.stage.replace(/_/g, " ")}</StatusTag></div>}
        />
      </div>
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <div className="grid gap-6" style={{ gridTemplateColumns: "1.5fr 1fr" }}>
        <div className="space-y-6">
          <Panel title="Logic">
            <div className="mb-4 grid grid-cols-2 gap-4">
              <Field label="Kind"><span className="capitalize">{rule.kind}</span>{rule.kind !== "simple" && <span className="ml-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>≥{rule.threshold} in {rule.window_seconds}s per {rule.entity_field}</span>}</Field>
              <Field label="Confidence">{rule.confidence}%</Field>
              <Field label="MITRE ATT&CK">
                {(rule.mitre ?? []).length ? <div className="flex flex-wrap gap-1">{(rule.mitre ?? []).map((m) => <span key={m} className="rounded px-1.5 py-0.5 font-mono text-[11px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{m}</span>)}</div> : "—"}
              </Field>
              <Field label="Scope">{rule.tenant_id ? "Tenant" : "Global"}</Field>
            </div>
            {rule.expression ? (
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>CEL expression</div>
                <pre className="overflow-x-auto rounded-lg p-3 font-mono text-[12px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{rule.expression}</pre>
              </div>
            ) : (
              <div>
                <div className="mb-1.5 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Condition</div>
                {preds.length === 0 ? <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No predicates.</p> : (
                  <ul className="space-y-1.5">
                    {preds.map((p, i) => (
                      <li key={i} className="flex items-center gap-2 font-mono text-[12px]" style={{ color: "var(--c-ink-2)" }}>
                        <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}>{p.join}</span>
                        {p.field} <span style={{ color: "var(--c-primary)" }}>{p.op}</span> {p.value || "∅"}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Test cases" sub="DET-005 — sample events with expected match" actions={tests.length > 0 ? <Button size="sm" variant="ghost" disabled={busy} onClick={() => act(() => apiPost(`/detections/${id}/tests/run`), "Tests run.")}>Run tests</Button> : undefined}>
            {tests.length === 0 ? <EmptyState title="No test cases" hint="Add sample events to prove the rule fires as intended." /> : (
              <ul className="space-y-2">
                {tests.map((t) => (
                  <li key={t.id} className="flex items-center gap-2 text-sm" style={{ color: "var(--c-ink-2)" }}>
                    <StatusTag tone={t.expect_match ? "danger" : "neutral"}>{t.expect_match ? "should fire" : "should not fire"}</StatusTag>
                    {t.name ?? t.id}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <div className="space-y-6">
          <Panel title="Lifecycle">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span style={{ color: "var(--c-ink-3)" }}>Firing</span>
                <button
                  disabled={busy}
                  onClick={() => act(() => apiPost(`/detections/${id}/enabled`, { enabled: !rule.enabled }), rule.enabled ? "Rule disabled." : "Rule enabled.")}
                  className="rounded-lg px-2.5 py-1 text-xs font-medium"
                  style={rule.enabled ? { background: "rgba(16,185,129,0.12)", color: "#6ee7b7" } : { background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}
                >
                  {rule.enabled ? "Enabled" : "Disabled"}
                </button>
              </div>
              {nexts.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Advance stage</div>
                  <div className="flex flex-wrap gap-2">
                    {nexts.map((s) => (
                      <Button key={s} size="sm" variant={s === "retired" ? "danger" : "ghost"} disabled={busy} onClick={() => act(() => apiPost(`/detections/${id}/transition`, { stage: s }), `Moved to ${s.replace(/_/g, " ")}.`)}>
                        {s.replace(/_/g, " ")}
                      </Button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Panel>

          {feedback && (
            <Panel title="Tuning" sub="DET-007 — analyst disposition feedback">
              <div className="space-y-2.5 text-sm">
                <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Dispositions</span><span>{feedback.total}</span></div>
                <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>False positives</span><span>{feedback.false_positives}</span></div>
                <div className="flex items-center justify-between">
                  <span style={{ color: "var(--c-ink-3)" }}>FP rate</span>
                  <StatusTag tone={feedback.tuning_recommended ? "warn" : "ok"}>{(feedback.fp_rate * 100).toFixed(0)}%</StatusTag>
                </div>
                {feedback.tuning_recommended && <p className="text-[12px]" style={{ color: "var(--c-warn)" }}>Tuning recommended — FP rate above threshold.</p>}
              </div>
            </Panel>
          )}

          <Panel title="Version history">
            {versions.length === 0 ? <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No prior versions.</p> : (
              <ul className="space-y-2">
                {versions.map((v, i) => (
                  <li key={i} className="flex items-center gap-2 text-[12px]" style={{ color: "var(--c-ink-2)" }}>
                    <span className="font-mono" style={{ color: "var(--c-ink-3)" }}>v{v.version}</span>
                    {v.stage && <StatusTag tone={stageToneOf(String(v.stage))}>{String(v.stage).replace(/_/g, " ")}</StatusTag>}
                    {v.note && <span className="truncate">{String(v.note)}</span>}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
