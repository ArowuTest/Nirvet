"use client";

// Investigation notebooks (§6.9 slice B / B2). A private, persisted analyst working surface: a titled notebook of
// ordered cells (a markdown note, or a saved hunt-query text). Wired to /investigation/notebooks*. A query cell
// only stores text — a "Run in hunt" link takes it to the hunt page for execution (never executed from here).
// War-room real-time collaboration is deferred on a single sovereign operator; the UI states this honestly.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, apiPut, apiDelete, ApiError } from "@/lib/api";
import { PageHeader, Panel, Button, EmptyState } from "@/components/ui";

type Notebook = { id: string; title: string; incident_ref?: string; updated_at: string };
type Cell = { id: string; position: number; kind: string; content: string };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function NotebooksPage() {
  const [notebooks, setNotebooks] = useState<Notebook[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [active, setActive] = useState<Notebook | null>(null);
  const [cells, setCells] = useState<Cell[]>([]);
  const [err, setErr] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newRef, setNewRef] = useState("");
  const [addKind, setAddKind] = useState<"note" | "query">("note");
  const [addContent, setAddContent] = useState("");
  const [editing, setEditing] = useState<Record<string, string>>({});

  const loadList = useCallback(async () => {
    try { const r = await apiGet<{ notebooks: Notebook[] | null }>("/investigation/notebooks"); setNotebooks(r.notebooks ?? []); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not load notebooks."); }
  }, []);

  const open = useCallback(async (id: string) => {
    setActiveId(id); setErr("");
    try {
      const r = await apiGet<{ notebook: Notebook; cells: Cell[] | null }>(`/investigation/notebooks/${id}`);
      setActive(r.notebook); setCells(r.cells ?? []);
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not open notebook."); }
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  async function op(fn: () => Promise<unknown>) {
    setErr("");
    try { await fn(); if (activeId) await open(activeId); await loadList(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Action failed."); }
  }

  async function create() {
    setErr("");
    try {
      const body: Record<string, unknown> = { title: newTitle };
      if (newRef.trim()) body.incident_ref = newRef.trim();
      const nb = await apiPost<Notebook>("/investigation/notebooks", body);
      setShowNew(false); setNewTitle(""); setNewRef("");
      await loadList(); open(nb.id);
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not create notebook."); }
  }

  return (
    <div>
      <PageHeader title="Investigation notebooks" sub="Your private working notebooks — notes and saved hunt queries, kept per investigation" />
      {err && <div className="mb-3 rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      <div className="grid gap-4" style={{ gridTemplateColumns: "260px 1fr" }}>
        {/* Rail */}
        <Panel bodyStyle={{ padding: 0 }}>
          <div className="flex items-center justify-between p-3" style={{ borderBottom: "1px solid var(--c-border)" }}>
            <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Notebooks</span>
            <Button size="sm" variant="ghost" onClick={() => setShowNew((v) => !v)}>+ New</Button>
          </div>
          {showNew && (
            <div className="grid gap-2 p-3" style={{ borderBottom: "1px solid var(--c-border)" }}>
              <input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Title" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
              <input value={newRef} onChange={(e) => setNewRef(e.target.value)} placeholder="Incident id (optional)" className="rounded px-2 py-1.5 font-mono text-xs" style={inputStyle} />
              <Button size="sm" onClick={create}>Create</Button>
            </div>
          )}
          <div className="max-h-[60vh] overflow-y-auto">
            {notebooks.length === 0 ? <div className="p-4"><EmptyState title="No notebooks" hint="Create a notebook to start recording an investigation." /></div> : notebooks.map((n) => (
              <button key={n.id} onClick={() => open(n.id)} className="block w-full px-3 py-2.5 text-left transition hover:bg-[color:var(--c-surface-2)]" style={{ borderBottom: "1px solid var(--c-border)", background: activeId === n.id ? "var(--c-surface-2)" : "transparent" }}>
                <div className="truncate text-sm font-medium" style={{ color: "var(--c-ink)" }}>{n.title}</div>
                <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{n.incident_ref ? "grounded · " : ""}{new Date(n.updated_at).toLocaleDateString()}</div>
              </button>
            ))}
          </div>
        </Panel>

        {/* Notebook */}
        <Panel bodyStyle={{ padding: 0 }}>
          {!active ? (
            <div className="p-10"><EmptyState title="Select or create a notebook" hint="Notebooks are private to you and persist across visits." /></div>
          ) : (
            <div className="p-4">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <div className="text-lg font-bold" style={{ color: "var(--c-ink)" }}>{active.title}</div>
                  {active.incident_ref && <Link href={`/console/incidents/${active.incident_ref}`} className="font-mono text-[11px]" style={{ color: "var(--c-primary)" }}>incident {active.incident_ref.slice(0, 8)}…</Link>}
                </div>
              </div>

              {cells.length === 0 ? <EmptyState title="Empty notebook" hint="Add a note or a saved hunt query below." /> : (
                <div className="space-y-3">
                  {cells.map((c, i) => (
                    <div key={c.id} className="rounded-xl p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                      <div className="mb-2 flex items-center justify-between">
                        <span className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide" style={{ background: c.kind === "query" ? "rgba(37,99,235,0.15)" : "var(--c-surface)", color: c.kind === "query" ? "var(--c-primary)" : "var(--c-ink-3)" }}>{c.kind}</span>
                        <div className="flex items-center gap-1">
                          <button title="Move up" disabled={i === 0} onClick={() => op(() => apiPost(`/investigation/notebooks/${active.id}/cells/${c.id}/move`, { dir: "up" }))} className="px-1.5 text-xs disabled:opacity-30" style={{ color: "var(--c-ink-2)" }}>↑</button>
                          <button title="Move down" disabled={i === cells.length - 1} onClick={() => op(() => apiPost(`/investigation/notebooks/${active.id}/cells/${c.id}/move`, { dir: "down" }))} className="px-1.5 text-xs disabled:opacity-30" style={{ color: "var(--c-ink-2)" }}>↓</button>
                          {c.kind === "query" && <button title="Copy query" onClick={() => navigator.clipboard?.writeText(c.content)} className="px-1.5 text-[11px]" style={{ color: "var(--c-primary)" }}>Copy</button>}
                          <button title="Delete" onClick={() => op(() => apiDelete(`/investigation/notebooks/${active.id}/cells/${c.id}`))} className="px-1.5 text-xs" style={{ color: "var(--c-danger)" }}>✕</button>
                        </div>
                      </div>
                      {editing[c.id] !== undefined ? (
                        <div className="grid gap-2">
                          <textarea value={editing[c.id]} onChange={(e) => setEditing((s) => ({ ...s, [c.id]: e.target.value }))} rows={c.kind === "query" ? 2 : 4} className="w-full rounded-lg px-3 py-2 text-sm" style={{ ...inputStyle, fontFamily: c.kind === "query" ? "monospace" : undefined }} />
                          <div className="flex gap-2">
                            <Button size="sm" onClick={() => op(() => apiPut(`/investigation/notebooks/${active.id}/cells/${c.id}`, { content: editing[c.id] }).then(() => setEditing((s) => { const n = { ...s }; delete n[c.id]; return n; })))}>Save</Button>
                            <Button size="sm" variant="ghost" onClick={() => setEditing((s) => { const n = { ...s }; delete n[c.id]; return n; })}>Cancel</Button>
                          </div>
                        </div>
                      ) : (
                        <div onClick={() => setEditing((s) => ({ ...s, [c.id]: c.content }))} className="cursor-text whitespace-pre-wrap text-sm" style={{ color: "var(--c-ink)", fontFamily: c.kind === "query" ? "monospace" : undefined }}>
                          {c.content || <span style={{ color: "var(--c-ink-3)" }}>(empty — click to edit)</span>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Add cell */}
              <div className="mt-4 rounded-xl p-3" style={{ border: "1px dashed var(--c-border)" }}>
                <div className="mb-2 flex gap-2">
                  {(["note", "query"] as const).map((k) => (
                    <button key={k} onClick={() => setAddKind(k)} className="rounded px-2.5 py-1 text-xs capitalize" style={{ background: addKind === k ? "var(--c-primary)" : "var(--c-surface-2)", color: addKind === k ? "#fff" : "var(--c-ink-2)", border: "1px solid var(--c-border)" }}>{k}</button>
                  ))}
                </div>
                <textarea value={addContent} onChange={(e) => setAddContent(e.target.value)} rows={addKind === "query" ? 2 : 3} placeholder={addKind === "query" ? "Hunt query text to save…" : "Notes (markdown)…"} className="w-full rounded-lg px-3 py-2 text-sm" style={{ ...inputStyle, fontFamily: addKind === "query" ? "monospace" : undefined }} />
                <Button className="mt-2" size="sm" disabled={!addContent.trim()} onClick={() => op(() => apiPost(`/investigation/notebooks/${active.id}/cells`, { kind: addKind, content: addContent }).then(() => setAddContent("")))}>Add {addKind}</Button>
              </div>

              <p className="mt-4 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                Notebooks are private to you. Real-time shared war-rooms are not enabled on this single-operator deployment.
              </p>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
