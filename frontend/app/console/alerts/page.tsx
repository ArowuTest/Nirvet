"use client";

// Alert queue — the analyst's primary triage surface (SRS §6.8). Lists alerts from GET /alerts?status=,
// filterable by workflow status, wired to the real disposition + promote actions. Promote is senior-gated
// on the backend (POST /alerts/{id}/promote → 403 for T1) — we surface that verdict rather than hide the
// control, so the RBAC boundary is visible, not guessed.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Alert = {
  id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  confidence: number;
  actor_ref: string;
  target_ref: string;
  mitre?: string[];
  created_at: string;
};

const FILTERS = [
  { key: "", label: "All" },
  { key: "new", label: "New" },
  { key: "assigned", label: "Assigned" },
  { key: "promoted", label: "Promoted" },
  { key: "closed", label: "Closed" },
];

const statusTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  new: "danger",
  assigned: "warn",
  promoted: "info",
  closed: "neutral",
};

export default function AlertsPage() {
  const [filter, setFilter] = useState("");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async (status: string) => {
    setLoading(true);
    try {
      const res = await apiGet<{ alerts: Alert[] | null }>(`/alerts${status ? `?status=${status}` : ""}`);
      setAlerts(res.alerts ?? []);
    } catch {
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(filter);
  }, [filter, load]);

  async function promote(id: string) {
    setMsg(null);
    setBusy(id);
    try {
      await apiPost(`/alerts/${id}/promote`);
      setMsg({ tone: "ok", text: "Alert promoted to an incident." });
      await load(filter);
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      const m = e instanceof Error ? e.message : "Promote failed";
      setMsg({ tone: "danger", text: forbidden ? "Promoting to an incident requires a senior analyst role." : m });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader title="Alert queue" sub="Detections awaiting triage across your monitored estate" />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className="rounded-lg px-3 py-1.5 text-xs font-medium transition"
            style={
              filter === f.key
                ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" }
                : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }
            }
          >
            {f.label}
          </button>
        ))}
      </div>

      {msg && (
        <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>
          {msg.text}
        </p>
      )}

      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div className="p-6">
            <EmptyState title="No alerts here" hint="Nothing matches this filter right now." />
          </div>
        ) : (
          <Table
            head={
              <>
                <Th>Severity</Th>
                <Th>Alert</Th>
                <Th>Source</Th>
                <Th>Entities</Th>
                <Th>Status</Th>
                <Th className="text-right">Actions</Th>
              </>
            }
          >
            {alerts.map((a) => (
              <tr key={a.id}>
                <Td><SevBadge severity={a.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]">
                  <Link href={`/console/alerts/${a.id}`} className="font-medium hover:underline">{a.title}</Link>
                  <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                    {new Date(a.created_at).toLocaleString()}
                    {a.mitre && a.mitre.length > 0 && <> · {a.mitre.slice(0, 3).join(", ")}</>}
                  </div>
                </Td>
                <Td className="text-xs">{a.source}</Td>
                <Td className="max-w-[220px] truncate font-mono text-[11px]" title={`${a.actor_ref} → ${a.target_ref}`}>
                  {a.actor_ref || "—"}{a.target_ref ? ` → ${a.target_ref}` : ""}
                </Td>
                <Td><StatusTag tone={statusTone[a.status] ?? "neutral"}>{a.status}</StatusTag></Td>
                <Td className="text-right">
                  {(a.status === "new" || a.status === "assigned") && (
                    <Button size="sm" variant="ghost" onClick={() => promote(a.id)} disabled={busy === a.id}>
                      {busy === a.id ? "…" : "Promote"}
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
