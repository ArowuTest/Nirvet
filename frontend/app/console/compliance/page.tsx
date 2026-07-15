"use client";

// Compliance & control coverage (SRS §6.14 / COMP-001/002/008). Framework selector (GET /compliance/frameworks),
// live tenant-scoped assessment (GET /compliance/coverage?framework=) — an overall score, status summary, and the
// function→control rollup where each control shows auto-measured or manually-attested status. Managers can attest
// a manual status (PUT /compliance/status → manager-gated; 403 surfaced). Read for everyone else.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPut, ApiError } from "@/lib/api";
import { PageHeader, Panel, StatusTag, Kpi, KpiStrip, Button } from "@/components/ui";

type Framework = { key: string; name: string; version: string; enabled: boolean };
type ControlAssessment = { control_ref: string; title: string; status: string; score: number; source: string; note: string; evidence_ref?: string };
type FunctionAssessment = { control_ref: string; title: string; status: string; score: number; controls: ControlAssessment[] | null };
type Coverage = { framework: string; score: number; summary: Record<string, number> | null; functions: FunctionAssessment[] | null };

function statusTone(s: string): "ok" | "warn" | "danger" | "neutral" {
  const v = s.toLowerCase();
  if (["met", "pass", "passed", "compliant", "implemented"].includes(v)) return "ok";
  if (["partial", "partially_met", "in_progress"].includes(v)) return "warn";
  if (["not_met", "fail", "failed", "non_compliant", "gap"].includes(v)) return "danger";
  return "neutral";
}
function scoreTone(n: number): "default" | "ok" | "warn" | "danger" {
  return n >= 80 ? "ok" : n >= 50 ? "warn" : "danger";
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [fw, setFw] = useState("");
  const [cov, setCov] = useState<Coverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  useEffect(() => {
    apiGet<{ frameworks: Framework[] | null }>("/compliance/frameworks")
      .then((r) => {
        const list = r.frameworks ?? [];
        setFrameworks(list);
        setFw(list[0]?.key ?? "nist_csf_2_0");
      })
      .catch(() => setFw("nist_csf_2_0"));
  }, []);

  const load = useCallback(async (key: string) => {
    if (!key) return;
    setLoading(true);
    try {
      setCov(await apiGet<Coverage>(`/compliance/coverage?framework=${encodeURIComponent(key)}`));
    } catch {
      setCov(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (fw) load(fw);
  }, [fw, load]);

  async function attest(control_ref: string, status: string) {
    setMsg(null);
    try {
      await apiPut("/compliance/status", { framework_key: fw, control_ref, status });
      setMsg({ tone: "ok", text: `${control_ref} attested ${status.replace(/_/g, " ")}.` });
      await load(fw);
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Attesting a control requires a manager role." : e instanceof Error ? e.message : "Failed." });
    }
  }

  return (
    <div>
      <PageHeader
        title="Compliance"
        sub="Control-framework coverage and regulatory evidence"
        actions={
          <select value={fw} onChange={(e) => setFw(e.target.value)} className="rounded-lg px-3 py-2 text-sm" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}>
            {frameworks.map((f) => <option key={f.key} value={f.key}>{f.name} {f.version}</option>)}
            {frameworks.length === 0 && <option value="nist_csf_2_0">NIST CSF 2.0</option>}
          </select>
        }
      />
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {loading ? (
        <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Assessing…</div>
      ) : !cov ? (
        <Panel><p className="text-sm" style={{ color: "var(--c-ink-3)" }}>No assessment available for this framework.</p></Panel>
      ) : (
        <>
          <KpiStrip>
            <Kpi label="Coverage score" value={`${cov.score}%`} sub="assessed" tone={scoreTone(cov.score)} />
            {Object.entries(cov.summary ?? {}).map(([k, v]) => (
              <Kpi key={k} label={k.replace(/_/g, " ")} value={v} sub="controls" tone={statusTone(k) === "ok" ? "ok" : statusTone(k) === "danger" ? "danger" : statusTone(k) === "warn" ? "warn" : "default"} />
            ))}
          </KpiStrip>

          <div className="mt-6 space-y-3">
            {(cov.functions ?? []).map((fn) => {
              const isOpen = open[fn.control_ref] ?? false;
              return (
                <Panel key={fn.control_ref} bodyStyle={{ padding: 0 }}>
                  <button onClick={() => setOpen((o) => ({ ...o, [fn.control_ref]: !isOpen }))} className="flex w-full items-center gap-3 px-5 py-3.5 text-left">
                    <span className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fn.control_ref}</span>
                    <span className="flex-1 text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{fn.title}</span>
                    <StatusTag tone={statusTone(fn.status)}>{fn.status.replace(/_/g, " ")}</StatusTag>
                    <span className="text-xs tabular-nums" style={{ color: "var(--c-ink-2)" }}>{fn.score}%</span>
                    <span style={{ color: "var(--c-ink-3)" }}>{isOpen ? "▲" : "▼"}</span>
                  </button>
                  {isOpen && (fn.controls ?? []).length === 0 && (
                    // BUG-6: some functions have no broken-out sub-controls; expanding must still reveal detail
                    // (the aggregate assessment) rather than collapsing to a blank panel.
                    <div className="px-5 py-4" style={{ borderTop: "1px solid var(--c-border)" }}>
                      <p className="text-sm" style={{ color: "var(--c-ink-2)" }}>
                        Assessed as <b>{fn.status.replace(/_/g, " ")}</b> at {fn.score}% coverage.
                      </p>
                      <p className="mt-1 text-[12px]" style={{ color: "var(--c-ink-3)" }}>
                        No individual sub-controls are broken out for this function — the score aggregates its measured signals across the framework.
                      </p>
                    </div>
                  )}
                  {isOpen && (fn.controls ?? []).length > 0 && (
                    <ul style={{ borderTop: "1px solid var(--c-border)" }}>
                      {(fn.controls ?? []).map((c) => (
                        <li key={c.control_ref} className="flex items-center gap-3 px-5 py-3" style={{ borderTop: "1px solid var(--c-border)" }}>
                          <span className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{c.control_ref}</span>
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm" style={{ color: "var(--c-ink-2)" }}>{c.title}</div>
                            {c.note && <div className="truncate text-[11px]" style={{ color: "var(--c-ink-3)" }}>{c.note}</div>}
                          </div>
                          <span className="text-[10px] uppercase" style={{ color: "var(--c-ink-3)" }}>{c.source}</span>
                          <StatusTag tone={statusTone(c.status)}>{c.status.replace(/_/g, " ")}</StatusTag>
                          <select
                            defaultValue=""
                            onChange={(e) => { if (e.target.value) attest(c.control_ref, e.target.value); e.currentTarget.value = ""; }}
                            className="rounded px-1.5 py-1 text-[11px]"
                            style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink-3)" }}
                            title="Attest a manual status (manager)"
                          >
                            <option value="">attest…</option>
                            {["met", "partial", "gap", "not_applicable"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
                          </select>
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
