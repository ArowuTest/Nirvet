"use client";

// Threat Hunt — the bounded, allow-listed event search (§6.9 I-1..I-6). Wired to POST /investigation/run-hunt-query
// with the exact HuntQuery model: a mandatory time window (from/to, on the indexed observed_at) + a flat list of
// AND-ed predicates ({field, op, value}). Fields/ops are the backend's code-owned registry — values are only ever
// bound as SQL parameters server-side, never concatenated. A malformed predicate is refused (400) and surfaced.

import { useState } from "react";
import { apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, EmptyState, Button } from "@/components/ui";

// The allow-listed queryable fields (investigation/fields.go). Enum fields support eq/neq/in; text fields also
// support contains. We expose the common eq/neq/contains ops and let the backend validate op×field.
const FIELDS = [
  { key: "actor_ref", label: "Actor", enum: false },
  { key: "target_ref", label: "Target", enum: false },
  { key: "source", label: "Source", enum: false },
  { key: "severity", label: "Severity", enum: true },
  { key: "outcome", label: "Outcome", enum: true },
  { key: "class", label: "Class", enum: false },
  { key: "activity", label: "Activity", enum: false },
  { key: "action", label: "Action", enum: false },
  { key: "vendor", label: "Vendor", enum: false },
  { key: "product", label: "Product", enum: false },
];
const OPS = [
  { key: "eq", label: "equals" },
  { key: "neq", label: "not equals" },
  { key: "contains", label: "contains" },
];

type Predicate = { field: string; op: string; value: string };
type EventRow = {
  id: string;
  event_time: string;
  source: string;
  class: string;
  activity: string;
  severity: string;
  actor_ref: string;
  target_ref: string;
  action: string;
  outcome: string;
};

function isoLocal(d: Date) {
  // datetime-local wants YYYY-MM-DDTHH:mm in local time
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export default function HuntPage() {
  const now = new Date();
  const dayAgo = new Date(now.getTime() - 24 * 3600 * 1000);
  const [from, setFrom] = useState(isoLocal(dayAgo));
  const [to, setTo] = useState(isoLocal(now));
  const [preds, setPreds] = useState<Predicate[]>([{ field: "actor_ref", op: "contains", value: "" }]);
  const [rows, setRows] = useState<EventRow[] | null>(null);
  const [count, setCount] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function setPred(i: number, patch: Partial<Predicate>) {
    setPreds((ps) => ps.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  }

  async function run() {
    setErr(null);
    setBusy(true);
    try {
      const all = preds
        .filter((p) => p.value.trim() !== "")
        .map((p) => ({ field: p.field, op: p.op, value: p.value }));
      const body = { from: new Date(from).toISOString(), to: new Date(to).toISOString(), all, limit: 200 };
      const res = await apiPost<{ rows: EventRow[] | null; count: number }>("/investigation/run-hunt-query", body);
      setRows(res.rows ?? []);
      setCount(res.count);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Query failed.");
      setRows(null);
    } finally {
      setBusy(false);
    }
  }

  const field = {
    background: "var(--c-surface-2)",
    border: "1px solid var(--c-border)",
    color: "var(--c-ink)",
  } as const;

  return (
    <div>
      <PageHeader title="Threat Hunt" sub="Search normalized events across a bounded time window" />

      <Panel title="Query" sub="All conditions must match; the time window binds the indexed event time">
        <div className="mb-4 grid grid-cols-2 gap-4">
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            From
            <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={field} />
          </label>
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            To
            <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={field} />
          </label>
        </div>

        <div className="space-y-2">
          {preds.map((p, i) => (
            <div key={i} className="flex items-center gap-2">
              <select value={p.field} onChange={(e) => setPred(i, { field: e.target.value })} className="rounded-lg px-2.5 py-2 text-sm" style={field}>
                {FIELDS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
              </select>
              <select value={p.op} onChange={(e) => setPred(i, { op: e.target.value })} className="rounded-lg px-2.5 py-2 text-sm" style={field}>
                {OPS.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
              </select>
              <input value={p.value} onChange={(e) => setPred(i, { value: e.target.value })} placeholder="value…" className="flex-1 rounded-lg px-3 py-2 text-sm outline-none" style={field} />
              {preds.length > 1 && (
                <button onClick={() => setPreds((ps) => ps.filter((_, idx) => idx !== i))} className="px-2 text-sm" style={{ color: "var(--c-ink-3)" }} aria-label="Remove condition">✕</button>
              )}
            </div>
          ))}
        </div>

        <div className="mt-3 flex items-center gap-3">
          <Button size="sm" variant="ghost" onClick={() => setPreds((ps) => [...ps, { field: "target_ref", op: "contains", value: "" }])} disabled={preds.length >= 20}>
            + Condition
          </Button>
          <Button size="sm" onClick={run} disabled={busy}>{busy ? "Searching…" : "Run hunt"}</Button>
          {err && <span className="text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</span>}
        </div>
      </Panel>

      {rows !== null && (
        <div className="mt-6">
          <Panel title="Results" sub={`${count} event${count === 1 ? "" : "s"} matched`} bodyStyle={{ padding: rows.length ? 0 : undefined }}>
            {rows.length === 0 ? (
              <EmptyState title="No matching events" hint="Try widening the time window or relaxing a condition." />
            ) : (
              <Table head={<><Th>Time</Th><Th>Severity</Th><Th>Source</Th><Th>Activity</Th><Th>Actor → Target</Th><Th>Outcome</Th></>}>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <Td className="whitespace-nowrap font-mono text-[11px]">{new Date(r.event_time).toLocaleString()}</Td>
                    <Td><SevBadge severity={r.severity} /></Td>
                    <Td className="text-xs">{r.source}</Td>
                    <Td className="text-xs">{r.activity || r.class || "—"}</Td>
                    <Td className="max-w-[240px] truncate font-mono text-[11px]" title={`${r.actor_ref} → ${r.target_ref}`}>{r.actor_ref || "—"}{r.target_ref ? ` → ${r.target_ref}` : ""}</Td>
                    <Td className="text-xs">{r.outcome || "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
