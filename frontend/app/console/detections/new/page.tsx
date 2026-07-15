"use client";

// New detection rule (DET-001/003). Linear authoring form → POST /detections with the CreateInput shape:
// {name, description, severity, confidence, mitre[], condition{all[],any[]}, stage}. Condition is a flat
// predicate builder (field/op/value) matching the backend engine (all AND-ed; any OR-ed). detEng-gated → 403.
// Sigma/CEL import are separate backend routes; this form authors the portable condition form.

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { apiPost, errorText } from "@/lib/api";
import { PageHeader, Panel, Button } from "@/components/ui";

const FIELDS = ["class_name", "activity_name", "severity", "source", "actor_ref", "target_ref", "action", "outcome", "confidence"];
const OPS = ["eq", "neq", "contains", "gte", "lte", "exists", "regex"];
const SEVERITIES = ["informational", "low", "medium", "high", "critical"];

type Pred = { field: string; op: string; value: string; join: "all" | "any" };

export default function NewDetectionPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [confidence, setConfidence] = useState(70);
  const [mitre, setMitre] = useState("");
  const [stage, setStage] = useState("draft");
  const [preds, setPreds] = useState<Pred[]>([{ field: "class_name", op: "eq", value: "", join: "all" }]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const input = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

  function setP(i: number, patch: Partial<Pred>) {
    setPreds((ps) => ps.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  }

  async function submit() {
    setErr(null);
    if (!name.trim()) return setErr("Name is required.");
    const all = preds.filter((p) => p.join === "all" && (p.value.trim() !== "" || p.op === "exists")).map(({ field, op, value }) => ({ field, op, value }));
    const any = preds.filter((p) => p.join === "any" && (p.value.trim() !== "" || p.op === "exists")).map(({ field, op, value }) => ({ field, op, value }));
    if (all.length === 0 && any.length === 0) return setErr("Add at least one condition predicate.");
    setBusy(true);
    try {
      const rule = await apiPost<{ id: string }>("/detections", {
        name,
        description,
        severity,
        confidence,
        mitre: mitre.split(",").map((s) => s.trim()).filter(Boolean),
        condition: { all, any },
        stage,
      });
      router.push(`/console/detections/${rule.id}`);
    } catch (e) {
      setErr(errorText(e, "Creating a rule requires a detection-engineer role.", "Create failed."));
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <Link href="/console/detections" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Detections</Link>
      <div className="mt-2"><PageHeader title="New detection rule" sub="Author a condition-based detection (detection-as-code)" /></div>

      <Panel>
        <div className="space-y-4">
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            Name<span style={{ color: "var(--c-danger)" }}> *</span>
            <input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={input} />
          </label>
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            Description
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={input} />
          </label>
          <div className="grid grid-cols-3 gap-3">
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Severity
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm capitalize" style={input}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Confidence %
              <input type="number" min={0} max={100} value={confidence} onChange={(e) => setConfidence(Number(e.target.value))} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={input} />
            </label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Initial stage
              <select value={stage} onChange={(e) => setStage(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm capitalize" style={input}>
                {["draft", "production"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
          </div>
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            MITRE techniques (comma-separated, e.g. T1078, T1110)
            <input value={mitre} onChange={(e) => setMitre(e.target.value)} placeholder="T1078, T1110" className="mt-1 w-full rounded-lg px-3 py-2 font-mono text-sm outline-none" style={input} />
          </label>

          <div className="border-t pt-4" style={{ borderColor: "var(--c-border)" }}>
            <div className="mb-2 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Condition — ALL must match; ANY (optional) needs one</div>
            <div className="space-y-2">
              {preds.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <select value={p.join} onChange={(e) => setP(i, { join: e.target.value as "all" | "any" })} className="rounded-lg px-2 py-2 text-xs" style={input}>
                    <option value="all">ALL</option>
                    <option value="any">ANY</option>
                  </select>
                  <select value={p.field} onChange={(e) => setP(i, { field: e.target.value })} className="rounded-lg px-2 py-2 text-sm" style={input}>
                    {FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
                  </select>
                  <select value={p.op} onChange={(e) => setP(i, { op: e.target.value })} className="rounded-lg px-2 py-2 text-sm" style={input}>
                    {OPS.map((o) => <option key={o} value={o}>{o}</option>)}
                  </select>
                  <input value={p.value} onChange={(e) => setP(i, { value: e.target.value })} placeholder={p.op === "exists" ? "(no value)" : "value…"} disabled={p.op === "exists"} className="flex-1 rounded-lg px-3 py-2 text-sm outline-none disabled:opacity-40" style={input} />
                  {preds.length > 1 && <button onClick={() => setPreds((ps) => ps.filter((_, idx) => idx !== i))} className="px-2 text-sm" style={{ color: "var(--c-ink-3)" }}>✕</button>}
                </div>
              ))}
            </div>
            <Button className="mt-2" size="sm" variant="ghost" onClick={() => setPreds((ps) => [...ps, { field: "actor_ref", op: "eq", value: "", join: "all" }])}>+ Predicate</Button>
          </div>

          {err && <p className="text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</p>}
          <div className="flex gap-2">
            <Button disabled={busy} onClick={submit}>{busy ? "Creating…" : "Create rule"}</Button>
            <Link href="/console/detections"><Button variant="ghost">Cancel</Button></Link>
          </div>
        </div>
      </Panel>
    </div>
  );
}
