"use client";

// Incident detail — the case workspace (SRS §6.8, CASE-002/004/005/009). Wired to GET /incidents/{id}
// ({incident, timeline}), the stage state-machine (POST /transition), notes with internal/customer
// visibility (POST /notes), the task checklist (GET/POST tasks, PUT /incident-tasks/{id}) and the
// CASE-009 closure form (POST /close, senior-gated). The stage buttons mirror the backend transition map
// (transitions.go) exactly, so we only offer legal next stages; closing is its own criteria-gated flow.

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, apiPut, ApiError } from "@/lib/api";
import { PageHeader, Panel, SevBadge, StatusTag, stageTone, EmptyState, Button } from "@/components/ui";

type Incident = {
  id: string;
  title: string;
  severity: string;
  category: string;
  stage: string;
  is_major: boolean;
  created_at: string;
  closed_at?: string;
  disposition?: string;
  root_cause?: string;
  impact?: string;
  actions_taken?: string;
  acknowledged_at?: string;
  ack_due_at?: string;
  resolve_due_at?: string;
  ack_breached: boolean;
  resolve_breached: boolean;
};
type TimelineEntry = { id: string; at: string; author: string; kind: string; visibility: string; note: string };
type Task = { id: string; title: string; status: string; created_at: string };
type Attachment = { id: string; filename: string; content_type: string; size_bytes: number; sha256: string; uploaded_at: string };

// Mirrors backend stageTransitions (transitions.go). We omit "closed" — closing is the criteria-gated /close flow.
const TRANSITIONS: Record<string, string[]> = {
  new: ["triage"],
  triage: ["assigned", "investigating"],
  assigned: ["investigating"],
  investigating: ["waiting_customer", "containment_pending", "contained"],
  waiting_customer: ["investigating", "containment_pending"],
  containment_pending: ["contained"],
  contained: ["eradication"],
  eradication: ["recovery"],
  recovery: ["monitoring"],
  monitoring: [],
  closed: ["post_incident_review", "investigating"],
  post_incident_review: [],
};

const DISPOSITIONS = ["true_positive", "false_positive", "benign_true_positive", "duplicate", "not_applicable"];

const kindTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  status: "info",
  action: "warn",
  evidence: "ok",
  note: "neutral",
};

function fmt(dt?: string) {
  return dt ? new Date(dt).toLocaleString() : "—";
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [inc, setInc] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [linked, setLinked] = useState<{ id: string; title: string; severity: string; status: string }[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "notfound">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // form state
  const [note, setNote] = useState("");
  const [noteVis, setNoteVis] = useState<"internal" | "customer">("internal");
  const [newTask, setNewTask] = useState("");
  const [showClose, setShowClose] = useState(false);
  const [closure, setClosure] = useState({ disposition: "true_positive", root_cause: "", impact: "", actions_taken: "", lessons_learned: "", customer_ack: false });

  const load = useCallback(async () => {
    try {
      const res = await apiGet<{ incident: Incident; timeline: TimelineEntry[] | null }>(`/incidents/${id}`);
      setInc(res.incident);
      setTimeline(res.timeline ?? []);
      const t = await apiGet<{ tasks: Task[] | null }>(`/incidents/${id}/tasks`).catch(() => ({ tasks: [] }));
      setTasks(t.tasks ?? []);
      const at = await apiGet<{ attachments: Attachment[] | null }>(`/incidents/${id}/attachments`).catch(() => ({ attachments: [] }));
      setAttachments(at.attachments ?? []);
      const la = await apiGet<{ alerts: { id: string; title: string; severity: string; status: string }[] | null }>(`/incidents/${id}/alerts`).catch(() => ({ alerts: [] }));
      setLinked(la.alerts ?? []);
      setState("ready");
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
      const m = e instanceof Error ? e.message : "Action failed";
      setMsg({ tone: "danger", text: forbidden ? "That action requires a senior analyst role." : m });
    } finally {
      setBusy(false);
    }
  }

  async function downloadPack() {
    setMsg(null);
    setBusy(true);
    try {
      const pack = await apiGet<unknown>(`/incidents/${id}/evidence-pack`);
      const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence-${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setMsg({ tone: "ok", text: "Signed evidence pack downloaded." });
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Exporting an evidence pack requires a senior analyst role." : e instanceof Error ? e.message : "Export failed." });
    } finally {
      setBusy(false);
    }
  }

  function fmtBytes(n: number) {
    return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  }

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "notfound" || !inc)
    return (
      <div>
        <PageHeader title="Incident" />
        <EmptyState title="Incident not found" hint="It may have been closed, or you don't have access." />
      </div>
    );

  const nextStages = TRANSITIONS[inc.stage] ?? [];
  const closed = inc.stage === "closed" || inc.stage === "post_incident_review";

  return (
    <div className="mx-auto max-w-6xl">
      <Link href="/console/incidents" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Incidents</Link>
      <div className="mt-2">
        <PageHeader
          title={inc.title}
          sub={`Case opened ${fmt(inc.created_at)}${inc.category ? ` · ${inc.category}` : ""}`}
          actions={
            <div className="flex items-center gap-2">
              {inc.is_major && <StatusTag tone="danger">Major</StatusTag>}
              <SevBadge severity={inc.severity} />
              <StatusTag tone={stageTone(inc.stage)}>{inc.stage.replace(/_/g, " ")}</StatusTag>
            </div>
          }
        />
      </div>

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <div className="grid gap-6" style={{ gridTemplateColumns: "1.6fr 1fr" }}>
        {/* Left: timeline + notes */}
        <div className="space-y-6">
          <Panel title="Investigation timeline" sub="Notes, status changes and actions on this case">
            {timeline.length === 0 ? (
              <EmptyState title="No activity yet" hint="Notes and stage changes will appear here." />
            ) : (
              <ol className="space-y-4">
                {timeline.map((e) => (
                  <li key={e.id} className="relative pl-5">
                    <span className="absolute left-0 top-1.5 h-2 w-2 rounded-full" style={{ background: "var(--c-primary)" }} />
                    <div className="flex items-center gap-2">
                      <StatusTag tone={kindTone[e.kind] ?? "neutral"}>{e.kind}</StatusTag>
                      {e.visibility === "customer" && <StatusTag tone="info">customer-visible</StatusTag>}
                      <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fmt(e.at)} · {e.author}</span>
                    </div>
                    {e.note && <p className="mt-1 text-sm" style={{ color: "var(--c-ink-2)" }}>{e.note}</p>}
                  </li>
                ))}
              </ol>
            )}

            {!closed && (
              <div className="mt-5 border-t pt-4" style={{ borderColor: "var(--c-border)" }}>
                <textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Add an investigation note…"
                  rows={2}
                  className="w-full rounded-lg px-3 py-2 text-sm outline-none"
                  style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
                />
                <div className="mt-2 flex items-center justify-between">
                  <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--c-ink-2)" }}>
                    <input type="checkbox" checked={noteVis === "customer"} onChange={(e) => setNoteVis(e.target.checked ? "customer" : "internal")} />
                    Customer-visible
                  </label>
                  <Button
                    size="sm"
                    disabled={busy || !note.trim()}
                    onClick={() => act(() => apiPost(`/incidents/${id}/notes`, { note, visibility: noteVis }).then(() => setNote("")), "Note added.")}
                  >
                    Add note
                  </Button>
                </div>
              </div>
            )}
          </Panel>

          <Panel title="Linked alerts" sub="Alerts promoted into this incident">
            {linked.length === 0 ? (
              <EmptyState title="No linked alerts" hint="This incident has no source alerts attached." />
            ) : (
              <ul className="space-y-2">
                {linked.map((a) => (
                  <li key={a.id} className="flex items-center gap-3">
                    <SevBadge severity={a.severity} />
                    <Link href={`/console/alerts/${a.id}`} className="min-w-0 flex-1 truncate text-sm hover:underline" style={{ color: "var(--c-ink)" }}>{a.title}</Link>
                    <StatusTag tone={a.status === "new" ? "info" : "neutral"}>{a.status}</StatusTag>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        {/* Right: SLA + lifecycle + tasks */}
        <div className="space-y-6">
          <Panel title="SLA">
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span style={{ color: "var(--c-ink-3)" }}>Acknowledged</span>
                <span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.acknowledged_at)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: "var(--c-ink-3)" }}>Ack due</span>
                <span>{inc.ack_breached ? <StatusTag tone="danger">Breached</StatusTag> : <span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.ack_due_at)}</span>}</span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: "var(--c-ink-3)" }}>Resolve due</span>
                <span>{inc.resolve_breached ? <StatusTag tone="danger">Breached</StatusTag> : <span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.resolve_due_at)}</span>}</span>
              </div>
            </div>
          </Panel>

          <Panel title="Lifecycle">
            {closed ? (
              <div className="space-y-2 text-sm">
                <p style={{ color: "var(--c-ink-2)" }}>Closed {fmt(inc.closed_at)}.</p>
                {inc.disposition && <p><span style={{ color: "var(--c-ink-3)" }}>Disposition:</span> {inc.disposition.replace(/_/g, " ")}</p>}
                {inc.root_cause && <p><span style={{ color: "var(--c-ink-3)" }}>Root cause:</span> {inc.root_cause}</p>}
                {inc.stage === "closed" && (
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => act(() => apiPost(`/incidents/${id}/transition`, { stage: "post_incident_review" }), "Moved to post-incident review.")}>
                    Start post-incident review
                  </Button>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="mb-2 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Advance stage</div>
                  {nextStages.length === 0 ? (
                    <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No further stage before closing.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {nextStages.map((s) => (
                        <Button key={s} size="sm" variant="ghost" disabled={busy} onClick={() => act(() => apiPost(`/incidents/${id}/transition`, { stage: s }), `Moved to ${s.replace(/_/g, " ")}.`)}>
                          {s.replace(/_/g, " ")}
                        </Button>
                      ))}
                    </div>
                  )}
                </div>
                <div className="border-t pt-3" style={{ borderColor: "var(--c-border)" }}>
                  <Button size="sm" variant="danger" onClick={() => setShowClose((v) => !v)}>
                    {showClose ? "Cancel close" : "Close case…"}
                  </Button>
                </div>
              </div>
            )}
          </Panel>

          {showClose && !closed && (
            <Panel title="Close incident" sub="CASE-009 closure criteria — senior analyst only">
              <div className="space-y-3">
                <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
                  Disposition
                  <select
                    value={closure.disposition}
                    onChange={(e) => setClosure({ ...closure, disposition: e.target.value })}
                    className="mt-1 w-full rounded-lg px-3 py-2 text-sm capitalize"
                    style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
                  >
                    {DISPOSITIONS.map((d) => <option key={d} value={d}>{d.replace(/_/g, " ")}</option>)}
                  </select>
                </label>
                {(["root_cause", "impact", "actions_taken", "lessons_learned"] as const).map((f) => (
                  <label key={f} className="block text-[12px] capitalize" style={{ color: "var(--c-ink-3)" }}>
                    {f.replace(/_/g, " ")}{f !== "lessons_learned" && <span style={{ color: "var(--c-danger)" }}> *</span>}
                    <textarea
                      value={closure[f]}
                      onChange={(e) => setClosure({ ...closure, [f]: e.target.value })}
                      rows={2}
                      className="mt-1 w-full rounded-lg px-3 py-2 text-sm"
                      style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
                    />
                  </label>
                ))}
                <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--c-ink-2)" }}>
                  <input type="checkbox" checked={closure.customer_ack} onChange={(e) => setClosure({ ...closure, customer_ack: e.target.checked })} />
                  Customer acknowledged
                </label>
                <Button
                  disabled={busy || !closure.root_cause.trim() || !closure.impact.trim() || !closure.actions_taken.trim()}
                  variant="danger"
                  onClick={() => act(() => apiPost(`/incidents/${id}/close`, closure).then(() => setShowClose(false)), "Incident closed.")}
                >
                  Close incident
                </Button>
              </div>
            </Panel>
          )}

          <Panel title="Tasks" sub="Investigation checklist (CASE-005)">
            {tasks.length === 0 ? (
              <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No tasks yet.</p>
            ) : (
              <ul className="space-y-2">
                {tasks.map((t) => {
                  const done = t.status === "done" || t.status === "cancelled";
                  return (
                    <li key={t.id} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={done}
                        disabled={busy || closed}
                        onChange={() => act(() => apiPut(`/incident-tasks/${t.id}`, { status: done ? "open" : "done" }), "Task updated.")}
                      />
                      <span className="flex-1 text-sm" style={{ color: done ? "var(--c-ink-3)" : "var(--c-ink-2)", textDecoration: done ? "line-through" : "none" }}>
                        {t.title}
                      </span>
                      <StatusTag tone={done ? "ok" : "neutral"}>{t.status.replace(/_/g, " ")}</StatusTag>
                    </li>
                  );
                })}
              </ul>
            )}
            {!closed && (
              <div className="mt-3 flex gap-2">
                <input
                  value={newTask}
                  onChange={(e) => setNewTask(e.target.value)}
                  placeholder="Add a task…"
                  className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-none"
                  style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && newTask.trim()) act(() => apiPost(`/incidents/${id}/tasks`, { title: newTask }).then(() => setNewTask("")), "Task added.");
                  }}
                />
                <Button size="sm" variant="ghost" disabled={busy || !newTask.trim()} onClick={() => act(() => apiPost(`/incidents/${id}/tasks`, { title: newTask }).then(() => setNewTask("")), "Task added.")}>
                  Add
                </Button>
              </div>
            )}
          </Panel>

          <Panel
            title="Evidence"
            sub="Chain-of-custody artifacts (CASE-008)"
            actions={<Button size="sm" variant="ghost" disabled={busy} onClick={downloadPack}>Export pack</Button>}
          >
            {attachments.length === 0 ? (
              <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No evidence files attached. The signed evidence pack bundles the case record, timeline and custody chain.</p>
            ) : (
              <ul className="space-y-2">
                {attachments.map((a) => (
                  <li key={a.id} className="rounded-lg p-2.5" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm" style={{ color: "var(--c-ink)" }} title={a.filename}>{a.filename}</span>
                      <span className="shrink-0 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fmtBytes(a.size_bytes)}</span>
                    </div>
                    <div className="mt-1 truncate font-mono text-[10px]" style={{ color: "var(--c-ink-3)" }} title={a.sha256}>sha256:{a.sha256.slice(0, 24)}…</div>
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
