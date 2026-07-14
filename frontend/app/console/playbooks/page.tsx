"use client";

// Playbooks — the SOAR response-workflow library + run history (§6.11). GET /playbooks (library),
// GET /soar/runs (execution history). Pending-approval runs can be approved/rejected inline
// (POST /soar/runs/{id}/approve|reject, soarApprover-gated → 403 surfaced). Running a playbook is done from an
// incident (it needs case context) and is senior-gated, so this screen is library + oversight, not a launch pad.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, StatusTag, EmptyState, Button } from "@/components/ui";

type Step = { name?: string; connector_key?: string; action?: string };
type Playbook = { id: string; name: string; description: string; trigger_category: string; steps: Step[] | null; enabled: boolean };
type StepResult = { name: string; connector_key: string; action: string; risk: string; status: string; note: string };
type Run = { id: string; playbook_id: string; incident_id?: string; status: string; steps: StepResult[] | null; created_at: string; completed_at?: string };

const runTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  completed: "ok",
  running: "info",
  pending_approval: "warn",
  failed: "danger",
  rejected: "neutral",
};

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [pb, rn] = await Promise.allSettled([
      apiGet<{ playbooks: Playbook[] | null }>("/playbooks"),
      apiGet<{ runs: Run[] | null }>("/soar/runs"),
    ]);
    if (pb.status === "fulfilled") setPlaybooks(pb.value.playbooks ?? []);
    if (rn.status === "fulfilled") setRuns(rn.value.runs ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function decide(id: string, action: "approve" | "reject") {
    setMsg(null);
    setBusy(id);
    try {
      await apiPost(`/soar/runs/${id}/${action}`);
      setMsg({ tone: "ok", text: `Run ${action === "approve" ? "approved" : "rejected"}.` });
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Approving a run requires an approver role." : e instanceof Error ? e.message : "Action failed." });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Playbooks"
        sub="Response-workflow library and execution history"
        actions={<Link href="/console/playbooks/new"><Button size="sm">New playbook</Button></Link>}
      />
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <div className="grid gap-6" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <Panel title="Library" sub="Workflows available to your tenant">
          {loading ? (
            <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</p>
          ) : playbooks.length === 0 ? (
            <EmptyState title="No playbooks" hint="None are configured for your tenant yet." />
          ) : (
            <ul className="space-y-3">
              {playbooks.map((p) => (
                <li key={p.id} className="rounded-xl p-4" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{p.name}</span>
                    <StatusTag tone={p.enabled ? "ok" : "neutral"}>{p.enabled ? "enabled" : "disabled"}</StatusTag>
                  </div>
                  {p.description && <p className="mt-1 text-[13px]" style={{ color: "var(--c-ink-2)" }}>{p.description}</p>}
                  <div className="mt-2 flex items-center gap-3 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                    <span>Trigger: {p.trigger_category || "—"}</span>
                    <span>· {(p.steps ?? []).length} step{(p.steps ?? []).length === 1 ? "" : "s"}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Recent runs" sub="Execution history and pending approvals">
          {loading ? (
            <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</p>
          ) : runs.length === 0 ? (
            <EmptyState title="No runs yet" hint="Playbook runs will appear here." />
          ) : (
            <ul className="space-y-3">
              {runs.map((r) => {
                const steps = r.steps ?? [];
                const executed = steps.filter((s) => s.status === "executed").length;
                return (
                  <li key={r.id} className="rounded-xl p-4" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                    <div className="flex items-center justify-between">
                      <StatusTag tone={runTone[r.status] ?? "neutral"}>{r.status.replace(/_/g, " ")}</StatusTag>
                      <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{new Date(r.created_at).toLocaleString()}</span>
                    </div>
                    <div className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                      {executed}/{steps.length} steps executed
                    </div>
                    {steps.length > 0 && (
                      <ul className="mt-2 space-y-1">
                        {steps.map((s, i) => (
                          <li key={i} className="flex items-center gap-2 text-[11px]" style={{ color: "var(--c-ink-2)" }}>
                            <span className="font-mono">{s.connector_key || "internal"}·{s.action}</span>
                            <StatusTag tone={s.status === "executed" ? "ok" : s.status === "awaiting_approval" ? "warn" : "neutral"}>{s.status.replace(/_/g, " ")}</StatusTag>
                          </li>
                        ))}
                      </ul>
                    )}
                    {r.status === "pending_approval" && (
                      <div className="mt-3 flex gap-2">
                        <Button size="sm" disabled={busy === r.id} onClick={() => decide(r.id, "approve")}>Approve</Button>
                        <Button size="sm" variant="danger" disabled={busy === r.id} onClick={() => decide(r.id, "reject")}>Reject</Button>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
