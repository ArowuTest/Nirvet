"use client";

// Admin risk-score configuration (riskscore) — GET/PUT /admin/risk-config. Tunes the composite score's component
// weights, risk bands, and model parameters. All are admin-config (no hardcoding); the backend validates and
// rejects a degenerate config (all-zero weights, non-ascending bands, top band < 100, non-positive scales).

import { useEffect, useState } from "react";
import { apiGet, apiPut, ApiError } from "@/lib/api";
import { PageHeader, Panel, Button } from "@/components/ui";

type Band = { max: number; label: string; tone: string };
type Model = {
  sev_weights: Record<string, number>;
  exploited_penalty: number;
  overdue_penalty: number;
  exposure_scale: number;
  open_incident_weight: number;
  breach_weight: number;
  late_weight: number;
  operational_scale: number;
};
type Config = {
  exposure_weight: number;
  compliance_weight: number;
  operational_weight: number;
  bands: Band[];
  model_params: Model;
};

const TONES = ["ok", "warn", "danger", "neutral"];
const inputCls = "rounded-lg border px-2.5 py-1.5 text-sm text-[var(--c-ink)] outline-none focus:border-[var(--c-primary)]";
const inputStyle = { background: "var(--c-surface)", borderColor: "var(--c-border)" } as const;

function numField(label: string, value: number, onChange: (v: number) => void, step = 0.05) {
  return (
    <label className="flex items-center justify-between gap-3 text-sm" style={{ color: "var(--c-ink-2)" }}>
      <span>{label}</span>
      <input type="number" step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className={`${inputCls} w-24 text-right`} style={inputStyle} />
    </label>
  );
}

export default function AdminRiskConfig() {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    apiGet<Config>("/admin/risk-config").then((c) => { setCfg(c); setState("ready"); }).catch(() => setState("error"));
  }, []);

  function patch(p: Partial<Config>) { setCfg((c) => (c ? { ...c, ...p } : c)); }
  function patchModel(p: Partial<Model>) { setCfg((c) => (c ? { ...c, model_params: { ...c.model_params, ...p } } : c)); }
  function patchBand(i: number, p: Partial<Band>) {
    setCfg((c) => (c ? { ...c, bands: c.bands.map((b, j) => (j === i ? { ...b, ...p } : b)) } : c));
  }

  async function save() {
    if (!cfg) return;
    setBusy(true); setMsg(null);
    try {
      await apiPut("/admin/risk-config", cfg);
      setMsg({ tone: "ok", text: "Risk-score configuration saved." });
    } catch (e) {
      const text = e instanceof ApiError ? e.message : "Could not save configuration.";
      setMsg({ tone: "err", text });
    } finally {
      setBusy(false);
    }
  }

  if (state === "loading") return <Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div></Panel>;
  if (state === "error" || !cfg) return <div><PageHeader title="Risk-score configuration" /><Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Configuration unavailable.</div></Panel></div>;

  const m = cfg.model_params;
  const weightSum = cfg.exposure_weight + cfg.compliance_weight + cfg.operational_weight;

  return (
    <div>
      <PageHeader
        title="Risk-score configuration"
        sub="Tune how the composite posture score weights exposure, compliance and operations"
        actions={<Button onClick={save} disabled={busy}>{busy ? "Saving…" : "Save configuration"}</Button>}
      />

      {msg && (
        <div className="mb-5 rounded-lg px-4 py-3 text-sm" style={{ background: msg.tone === "ok" ? "rgba(16,185,129,0.08)" : "rgba(239,68,68,0.08)", border: `1px solid ${msg.tone === "ok" ? "rgba(16,185,129,0.3)" : "rgba(239,68,68,0.3)"}`, color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>
          {msg.text}
        </div>
      )}

      <div className="grid gap-5" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
        <Panel title="Component weights" sub={`Relative importance (normalized). Current sum: ${weightSum.toFixed(2)}`}>
          <div className="flex flex-col gap-3">
            {numField("Exposure", cfg.exposure_weight, (v) => patch({ exposure_weight: v }))}
            {numField("Compliance", cfg.compliance_weight, (v) => patch({ compliance_weight: v }))}
            {numField("Operational", cfg.operational_weight, (v) => patch({ operational_weight: v }))}
          </div>
        </Panel>

        <Panel title="Risk bands" sub="Ascending by max; the top band must reach 100">
          <div className="flex flex-col gap-2">
            {cfg.bands.map((b, i) => (
              <div key={i} className="flex items-center gap-2">
                <input type="number" value={b.max} onChange={(e) => patchBand(i, { max: Number(e.target.value) })} className={`${inputCls} w-16`} style={inputStyle} />
                <input value={b.label} onChange={(e) => patchBand(i, { label: e.target.value })} className={`${inputCls} flex-1`} style={inputStyle} />
                <select value={b.tone} onChange={(e) => patchBand(i, { tone: e.target.value })} className={inputCls} style={inputStyle}>
                  {TONES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Model parameters" sub="Advanced — how counts convert to component risk">
          <div className="flex flex-col gap-3">
            {numField("Critical vuln weight", m.sev_weights.critical ?? 0, (v) => patchModel({ sev_weights: { ...m.sev_weights, critical: v } }), 1)}
            {numField("High vuln weight", m.sev_weights.high ?? 0, (v) => patchModel({ sev_weights: { ...m.sev_weights, high: v } }), 1)}
            {numField("Medium vuln weight", m.sev_weights.medium ?? 0, (v) => patchModel({ sev_weights: { ...m.sev_weights, medium: v } }), 1)}
            {numField("Low vuln weight", m.sev_weights.low ?? 0, (v) => patchModel({ sev_weights: { ...m.sev_weights, low: v } }), 1)}
            {numField("Exploited penalty", m.exploited_penalty, (v) => patchModel({ exploited_penalty: v }), 1)}
            {numField("Overdue penalty", m.overdue_penalty, (v) => patchModel({ overdue_penalty: v }), 1)}
            {numField("Exposure scale", m.exposure_scale, (v) => patchModel({ exposure_scale: v }), 5)}
            {numField("Open-incident weight", m.open_incident_weight, (v) => patchModel({ open_incident_weight: v }), 1)}
            {numField("SLA-breach weight", m.breach_weight, (v) => patchModel({ breach_weight: v }), 1)}
            {numField("Resolved-late weight", m.late_weight, (v) => patchModel({ late_weight: v }), 1)}
            {numField("Operational scale", m.operational_scale, (v) => patchModel({ operational_scale: v }), 5)}
          </div>
        </Panel>
      </div>
    </div>
  );
}
