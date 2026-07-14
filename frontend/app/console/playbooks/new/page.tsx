"use client";

// Playbook authoring — linear step form (SRS §6.11 / SOAR-001/008; #187 slice B inline path). POST /soar/playbooks
// {name, description, trigger_category, steps[{name, connector_key, action, risk, requires_approval, target}]}.
// Steps are chosen from the tenant action-catalog (GET /soar/action-catalog) so connector_key/action/risk come from
// the real, entitlement-checked catalogue. Branch/loop/wait/schedule are shown as a disabled "v2" palette (the
// backend authoring API is inline-only today; the visual DAG is #181). soarAuthor-gated → 403 surfaced.

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, StatusTag, Button } from "@/components/ui";

type CatalogAction = { connector_key: string; action: string; risk_class?: string; risk?: string; label?: string; description?: string };
type Step = { name: string; connector_key: string; action: string; risk: string; requires_approval: boolean; target: string };

const RISK_TONE: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  informational: "neutral",
  low: "info",
  medium: "warn",
  high: "danger",
  business_critical: "danger",
};
const V2_STEPS = ["Branch", "Loop", "Wait", "Schedule"];

export default function NewPlaybookPage() {
  const router = useRouter();
  const [catalog, setCatalog] = useState<CatalogAction[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [trigger, setTrigger] = useState("");
  const [steps, setSteps] = useState<Step[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<{ actions: CatalogAction[] | null }>("/soar/action-catalog").then((r) => setCatalog(r.actions ?? [])).catch(() => {});
  }, []);

  const input = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

  function addStep(a: CatalogAction) {
    const risk = a.risk_class ?? a.risk ?? "informational";
    setSteps((s) => [...s, { name: a.label ?? a.action, connector_key: a.connector_key, action: a.action, risk, requires_approval: ["medium", "high", "business_critical"].includes(risk), target: "" }]);
  }
  function setStep(i: number, patch: Partial<Step>) {
    setSteps((s) => s.map((x, idx) => (idx === i ? { ...x, ...patch } : x)));
  }

  async function submit() {
    setErr(null);
    if (!name.trim()) return setErr("Name is required.");
    if (steps.length === 0) return setErr("Add at least one step.");
    setBusy(true);
    try {
      const pb = await apiPost<{ id: string }>("/soar/playbooks", {
        name,
        description,
        trigger_category: trigger,
        steps: steps.map((s) => ({ name: s.name, connector_key: s.connector_key, action: s.action, risk: s.risk, requires_approval: s.requires_approval, target: s.target || undefined })),
      });
      router.push(`/console/playbooks${pb?.id ? `` : ``}`);
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setErr(forbidden ? "Authoring a playbook requires a SOAR-author role." : e instanceof Error ? e.message : "Create failed.");
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <Link href="/console/playbooks" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Playbooks</Link>
      <div className="mt-2"><PageHeader title="New playbook" sub="Author a linear response workflow from the action catalogue" /></div>
      {err && <p className="mb-3 text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</p>}

      <div className="grid gap-6" style={{ gridTemplateColumns: "1.5fr 1fr" }}>
        <div className="space-y-5">
          <Panel title="Playbook">
            <div className="space-y-3">
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Name<span style={{ color: "var(--c-danger)" }}> *</span>
                <input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={input} />
              </label>
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Description
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={input} />
              </label>
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Trigger category (incident category)
                <input value={trigger} onChange={(e) => setTrigger(e.target.value)} placeholder="e.g. phishing, ransomware" className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={input} />
              </label>
            </div>
          </Panel>

          <Panel title="Steps" sub="Run in order; a step may require approval by its risk class">
            {steps.length === 0 ? (
              <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No steps yet — add from the action catalogue →</p>
            ) : (
              <ol className="space-y-3">
                {steps.map((s, i) => (
                  <li key={i} className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                    <div className="flex items-center gap-2">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold" style={{ background: "rgba(14,165,233,0.15)", color: "var(--c-primary)" }}>{i + 1}</span>
                      <input value={s.name} onChange={(e) => setStep(i, { name: e.target.value })} className="flex-1 rounded px-2 py-1 text-sm outline-none" style={input} />
                      <StatusTag tone={RISK_TONE[s.risk] ?? "neutral"}>{s.risk.replace(/_/g, " ")}</StatusTag>
                      <button onClick={() => setSteps((st) => st.filter((_, idx) => idx !== i))} className="px-1 text-sm" style={{ color: "var(--c-ink-3)" }}>✕</button>
                    </div>
                    <div className="mt-1.5 font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{s.connector_key} · {s.action}</div>
                    <div className="mt-2 flex items-center gap-3">
                      <label className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--c-ink-2)" }}>
                        <input type="checkbox" checked={s.requires_approval} onChange={(e) => setStep(i, { requires_approval: e.target.checked })} /> requires approval
                      </label>
                      {(s.risk === "high" || s.risk === "business_critical") && (
                        <input value={s.target} onChange={(e) => setStep(i, { target: e.target.value })} placeholder="target (host:… / user:…)" className="flex-1 rounded px-2 py-1 font-mono text-[11px] outline-none" style={input} />
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          <div className="flex gap-2">
            <Button disabled={busy} onClick={submit}>{busy ? "Creating…" : "Create playbook"}</Button>
            <Link href="/console/playbooks"><Button variant="ghost">Cancel</Button></Link>
          </div>
        </div>

        <div className="space-y-5">
          <Panel title="Action catalogue" sub="Entitlement-checked actions for your tenant">
            {catalog.length === 0 ? (
              <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No actions available.</p>
            ) : (
              <ul className="space-y-1.5">
                {catalog.map((a, i) => {
                  const risk = a.risk_class ?? a.risk ?? "informational";
                  return (
                    <li key={i}>
                      <button onClick={() => addStep(a)} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left transition hover:bg-white/5">
                        <span className="flex-1">
                          <span className="block text-sm" style={{ color: "var(--c-ink)" }}>{a.label ?? a.action}</span>
                          <span className="block font-mono text-[10px]" style={{ color: "var(--c-ink-3)" }}>{a.connector_key}</span>
                        </span>
                        <StatusTag tone={RISK_TONE[risk] ?? "neutral"}>{risk.replace(/_/g, " ")}</StatusTag>
                        <span style={{ color: "var(--c-primary)" }}>+</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
          <Panel title="Control flow" sub="Visual branch/loop/wait — coming in v2 (#181)">
            <div className="flex flex-wrap gap-2">
              {V2_STEPS.map((s) => (
                <span key={s} className="cursor-not-allowed rounded-lg px-2.5 py-1.5 text-xs opacity-40" style={{ border: "1px dashed var(--c-border-strong)", color: "var(--c-ink-3)" }}>{s}</span>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
