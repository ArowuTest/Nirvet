"use client";

// AI Copilot investigation workspace (§6.12 AI-001 / B1). A private, multi-turn analyst chat wired to
// /ai/copilot/sessions*. Left rail = the analyst's own sessions (+ New); right = the transcript + composer.
// Assistive-only; customer telemetry is redacted before any egress (the backend routes every turn through the
// redaction chokepoint). Honest states when a session is empty or the AI provider is not configured.

import { useCallback, useEffect, useRef, useState } from "react";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Button, EmptyState } from "@/components/ui";

type Session = { id: string; title: string; incident_ref?: string; updated_at: string };
type Turn = { id: string; role: string; content: string; model?: string; created_at: string };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function CopilotPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [err, setErr] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [newRef, setNewRef] = useState("");
  const [showNew, setShowNew] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const loadSessions = useCallback(async () => {
    try { const r = await apiGet<{ sessions: Session[] | null }>("/ai/copilot/sessions"); setSessions(r.sessions ?? []); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not load sessions."); }
  }, []);

  const openSession = useCallback(async (id: string) => {
    setActiveId(id); setErr("");
    try { const r = await apiGet<{ session: Session; turns: Turn[] | null }>(`/ai/copilot/sessions/${id}`); setTurns(r.turns ?? []); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not open session."); }
  }, []);

  useEffect(() => { loadSessions(); }, [loadSessions]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight }); }, [turns]);

  async function createSession() {
    setErr("");
    try {
      const body: Record<string, unknown> = { title: newTitle };
      if (newRef.trim()) body.incident_ref = newRef.trim();
      const s = await apiPost<Session>("/ai/copilot/sessions", body);
      setShowNew(false); setNewTitle(""); setNewRef("");
      await loadSessions();
      openSession(s.id);
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not start session."); }
  }

  async function send() {
    if (!activeId || !draft.trim() || sending) return;
    const message = draft.trim();
    setSending(true); setErr("");
    // optimistic: show the user's message immediately
    setTurns((t) => [...t, { id: `pending-${Date.now()}`, role: "user", content: message, created_at: new Date().toISOString() }]);
    setDraft("");
    try {
      const turn = await apiPost<Turn>(`/ai/copilot/sessions/${activeId}/messages`, { message });
      setTurns((t) => [...t, turn]);
      loadSessions(); // bump ordering
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Message failed.");
      setTurns((t) => t.filter((x) => !x.id.startsWith("pending-"))); // roll back optimistic
      setDraft(message);
    } finally { setSending(false); }
  }

  return (
    <div>
      <PageHeader title="AI Copilot" sub="A private, assistive investigation chat — customer data is redacted before it ever leaves the platform" />

      {err && <div className="mb-3 rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      <div className="grid gap-4" style={{ gridTemplateColumns: "260px 1fr" }}>
        {/* Sessions rail */}
        <Panel bodyStyle={{ padding: 0 }}>
          <div className="flex items-center justify-between p-3" style={{ borderBottom: "1px solid var(--c-border)" }}>
            <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Sessions</span>
            <Button size="sm" variant="ghost" onClick={() => setShowNew((v) => !v)}>+ New</Button>
          </div>
          {showNew && (
            <div className="grid gap-2 p-3" style={{ borderBottom: "1px solid var(--c-border)" }}>
              <input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Title (e.g. host-01 triage)" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
              <input value={newRef} onChange={(e) => setNewRef(e.target.value)} placeholder="Ground in incident id (optional)" className="rounded px-2 py-1.5 font-mono text-xs" style={inputStyle} />
              <Button size="sm" onClick={createSession}>Start session</Button>
            </div>
          )}
          <div className="max-h-[60vh] overflow-y-auto">
            {sessions.length === 0 ? <div className="p-4"><EmptyState title="No sessions" hint="Start a session to investigate with the copilot." /></div> : sessions.map((s) => (
              <button key={s.id} onClick={() => openSession(s.id)} className="block w-full px-3 py-2.5 text-left transition hover:bg-[color:var(--c-surface-2)]" style={{ borderBottom: "1px solid var(--c-border)", background: activeId === s.id ? "var(--c-surface-2)" : "transparent" }}>
                <div className="truncate text-sm font-medium" style={{ color: "var(--c-ink)" }}>{s.title}</div>
                <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{s.incident_ref ? "grounded · " : ""}{new Date(s.updated_at).toLocaleDateString()}</div>
              </button>
            ))}
          </div>
        </Panel>

        {/* Transcript + composer */}
        <Panel bodyStyle={{ padding: 0 }}>
          {!activeId ? (
            <div className="p-10"><EmptyState title="Select or start a session" hint="Your conversations are private to you and persist across visits." /></div>
          ) : (
            <div className="flex h-[70vh] flex-col">
              <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
                {turns.length === 0 ? <EmptyState title="Ask the copilot" hint="Describe what you're investigating. Responses are assistive — the copilot never takes actions." /> : turns.map((t) => (
                  <div key={t.id} className={`flex ${t.role === "user" ? "justify-end" : "justify-start"}`}>
                    <div className="max-w-[80%] rounded-2xl px-4 py-2.5 text-sm" style={t.role === "user"
                      ? { background: "var(--c-primary)", color: "#fff" }
                      : { background: "var(--c-surface-2)", color: "var(--c-ink)", border: "1px solid var(--c-border)" }}>
                      <div className="whitespace-pre-wrap">{t.content}</div>
                      {t.role === "assistant" && t.model && <div className="mt-1 text-[10px]" style={{ color: "var(--c-ink-3)" }}>{t.model}</div>}
                    </div>
                  </div>
                ))}
                {sending && <div className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>Copilot is thinking…</div>}
              </div>
              <div className="flex gap-2 p-3" style={{ borderTop: "1px solid var(--c-border)" }}>
                <textarea
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
                  rows={2}
                  placeholder="Ask about this case… (Enter to send, Shift+Enter for newline)"
                  className="flex-1 resize-none rounded-lg px-3 py-2 text-sm"
                  style={inputStyle}
                />
                <Button size="sm" disabled={!draft.trim() || sending} onClick={send}>Send</Button>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
