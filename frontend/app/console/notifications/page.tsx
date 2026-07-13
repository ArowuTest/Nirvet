"use client";

// Notifications — the caller's own in-app feed (§6.16). Wired to the per-user inbox: GET /notify/inbox
// ({notifications, unread_count}), POST /notify/inbox/{id}/read, POST /notify/inbox/read-all, and the
// GET/PUT /notify/inbox/prefs feed toggle. All authed (every user), scoped server-side to the caller — no
// role gate. A user may switch their own feed off.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiPut } from "@/lib/api";
import { PageHeader, Panel, StatusTag, EmptyState, Button } from "@/components/ui";

type Note = { id: string; kind: string; subject: string; body: string; created_at: string; read_at?: string };

const kindTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  alert: "danger",
  incident: "warn",
  approval: "info",
  info: "neutral",
};

export default function NotificationsPage() {
  const [notes, setNotes] = useState<Note[]>([]);
  const [unread, setUnread] = useState(0);
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [onlyUnread, setOnlyUnread] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const [feed, prefs] = await Promise.allSettled([
      apiGet<{ notifications: Note[] | null; unread_count: number }>(`/notify/inbox${onlyUnread ? "?unread=1" : ""}`),
      apiGet<{ in_app_enabled: boolean }>("/notify/inbox/prefs"),
    ]);
    if (feed.status === "fulfilled") {
      setNotes(feed.value.notifications ?? []);
      setUnread(feed.value.unread_count);
    }
    if (prefs.status === "fulfilled") setEnabled(prefs.value.in_app_enabled);
    setLoading(false);
  }, [onlyUnread]);

  useEffect(() => {
    load();
  }, [load]);

  async function markRead(id: string) {
    await apiPost(`/notify/inbox/${id}/read`).catch(() => {});
    await load();
  }
  async function markAll() {
    await apiPost("/notify/inbox/read-all").catch(() => {});
    await load();
  }
  async function toggle() {
    const next = !enabled;
    setEnabled(next);
    await apiPut("/notify/inbox/prefs", { in_app_enabled: next }).catch(() => setEnabled(!next));
  }

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="Notifications"
        sub="Your in-app feed — assignments, approvals and case updates addressed to you"
        actions={unread > 0 ? <Button size="sm" variant="ghost" onClick={markAll}>Mark all read ({unread})</Button> : undefined}
      />

      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          {([["All", false], ["Unread", true]] as const).map(([label, v]) => (
            <button
              key={label}
              onClick={() => setOnlyUnread(v)}
              className="rounded-lg px-3 py-1.5 text-xs font-medium transition"
              style={onlyUnread === v ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" } : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--c-ink-2)" }}>
          <input type="checkbox" checked={enabled} onChange={toggle} />
          In-app feed enabled
        </label>
      </div>

      <Panel bodyStyle={{ padding: notes.length ? 0 : undefined }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
        ) : notes.length === 0 ? (
          <EmptyState title={onlyUnread ? "No unread notifications" : "You're all caught up"} hint="New notifications addressed to you will appear here." />
        ) : (
          <ul>
            {notes.map((n) => {
              const unreadRow = !n.read_at;
              return (
                <li
                  key={n.id}
                  className="flex items-start gap-3 px-5 py-4"
                  style={{ borderTop: "1px solid var(--c-border)", background: unreadRow ? "rgba(14,165,233,0.04)" : "transparent" }}
                >
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: unreadRow ? "var(--c-primary)" : "transparent" }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <StatusTag tone={kindTone[n.kind] ?? "neutral"}>{n.kind}</StatusTag>
                      <span className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{n.subject}</span>
                    </div>
                    {n.body && <p className="mt-1 text-[13px]" style={{ color: "var(--c-ink-2)" }}>{n.body}</p>}
                    <div className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{new Date(n.created_at).toLocaleString()}</div>
                  </div>
                  {unreadRow && <Button size="sm" variant="ghost" onClick={() => markRead(n.id)}>Mark read</Button>}
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </div>
  );
}
