"use client";

// Incident board — the case list (SRS §6.8). GET /incidents returns cases with derived SLA-breach flags
// (ack_breached / resolve_breached computed on read). We surface those as an at-a-glance SLA column so the
// analyst sees which cases are overdue without opening each one. Cases are usually promoted from an alert, but an
// analyst can also DECLARE one directly (CASE-001, POST /incidents) — e.g. from a hunt, a customer report or intel;
// that action is senior-gated server-side, so non-seniors see the 403 surfaced as a message.

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, stageTone, EmptyState, Button } from "@/components/ui";

type Incident = {
  id: string;
  title: string;
  severity: string;
  stage: string;
  created_at: string;
  resolve_due_at?: string;
  ack_breached: boolean;
  resolve_breached: boolean;
  is_major: boolean;
};

const OPEN_STAGES = new Set(["closed", "post_incident_review"]);
const SEVERITIES = ["informational", "low", "medium", "high", "critical"];
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function IncidentsPage() {
  const router = useRouter();
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"open" | "all">("open");
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ title: "", severity: "medium", category: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await apiGet<{ incidents: Incident[] | null }>("/incidents");
      setItems(res.incidents ?? []);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function declare() {
    if (!form.title.trim()) {
      setMsg({ tone: "danger", text: "A title is required." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      const inc = await apiPost<Incident>("/incidents", { title: form.title.trim(), severity: form.severity, category: form.category.trim() });
      router.push(`/console/incidents/${inc.id}`);
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Declaring an incident requires a senior analyst role." : e instanceof Error ? e.message : "Could not declare incident." });
      setBusy(false);
    }
  }

  const shown = useMemo(
    () => (tab === "open" ? items.filter((i) => !OPEN_STAGES.has(i.stage)) : items),
    [items, tab]
  );

  return (
    <div>
      <PageHeader
        title="Incidents"
        sub="Security cases and their lifecycle stage"
        actions={<Button size="sm" onClick={() => setShow((s) => !s)}>{show ? "Cancel" : "Declare incident"}</Button>}
      />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {show && (
        <Panel title="Declare an incident" sub="Open a case directly — from a hunt, a customer report, or intel" style={{ marginBottom: 24 }}>
          <div className="grid gap-3" style={{ gridTemplateColumns: "2fr 1fr 1fr auto" }}>
            <input
              className="rounded-lg px-3 py-2 text-sm"
              style={inputStyle}
              placeholder="Incident title"
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
            />
            <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <input
              className="rounded-lg px-3 py-2 text-sm"
              style={inputStyle}
              placeholder="Category (optional)"
              value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}
            />
            <Button size="sm" disabled={busy} onClick={declare}>{busy ? "Declaring…" : "Declare"}</Button>
          </div>
          <p className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
            You are assigned as the owner; the case opens in triage with ack/resolve SLA timers set from its severity.
          </p>
        </Panel>
      )}

      <div className="mb-4 flex items-center gap-2">
        {(["open", "all"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition"
            style={
              tab === t
                ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" }
                : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }
            }
          >
            {t}
          </button>
        ))}
      </div>

      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading incidents…</div>
        ) : shown.length === 0 ? (
          <div className="p-6">
            <EmptyState title="No incidents" hint={tab === "open" ? "No open cases right now." : "Nothing to show."} />
          </div>
        ) : (
          <Table
            head={
              <>
                <Th>Severity</Th>
                <Th>Incident</Th>
                <Th>Stage</Th>
                <Th>SLA</Th>
                <Th className="text-right">Opened</Th>
              </>
            }
          >
            {shown.map((i) => (
              <tr key={i.id}>
                <Td><SevBadge severity={i.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]">
                  <Link href={`/console/incidents/${i.id}`} className="font-medium hover:underline">{i.title}</Link>
                  {i.is_major && <span className="ml-2 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "rgba(239,68,68,0.15)", color: "#fca5a5" }}>MAJOR</span>}
                </Td>
                <Td><StatusTag tone={stageTone(i.stage)}>{i.stage.replace(/_/g, " ")}</StatusTag></Td>
                <Td>
                  {i.ack_breached || i.resolve_breached ? (
                    <StatusTag tone="danger">{i.resolve_breached ? "Resolve overdue" : "Ack overdue"}</StatusTag>
                  ) : (
                    <StatusTag tone="ok">On track</StatusTag>
                  )}
                </Td>
                <Td className="text-right text-xs">{new Date(i.created_at).toLocaleString()}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
