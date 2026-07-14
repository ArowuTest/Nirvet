"use client";

// Normalized events (SRS §6.5 / ADR-0006) — the tenant's canonical event stream. GET /events returns the
// normalized records; a row opens a full-event detail modal (every field the record carries + raw JSON), the
// depth an analyst needs to inspect what a detection fired on.

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, EmptyState } from "@/components/ui";

type Event = {
  id: string;
  source: string;
  class_name: string;
  severity: string;
  actor_ref: string;
  target_ref: string;
  observed_at: string;
  [k: string]: unknown; // any additional normalized fields the backend carries
};

// FIELD_ORDER surfaces the meaningful fields first in the detail; the rest follow in object order.
const PRIMARY = ["id", "source", "class_name", "severity", "actor_ref", "target_ref", "observed_at"];

export default function EventsPage() {
  const [items, setItems] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<Event | null>(null);

  useEffect(() => {
    apiGet<{ events: Event[] | null }>("/events").then((r) => setItems(r.events ?? [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader title="Normalized events" sub="The tenant's canonical event stream — click a row for the full record" />
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No events" hint="Events appear once telemetry is flowing from your connectors." /></div>
        ) : (
          <Table head={<><Th>Source</Th><Th>Class</Th><Th>Severity</Th><Th>Actor</Th><Th>Target</Th><Th className="text-right">Observed</Th></>}>
            {items.map((e) => (
              <tr key={e.id} onClick={() => setSel(e)} className="cursor-pointer transition hover:bg-[color:var(--c-surface-2)]">
                <Td className="text-xs">{e.source}</Td>
                <Td className="font-medium">{e.class_name}</Td>
                <Td>{e.severity ? <SevBadge severity={e.severity} /> : "—"}</Td>
                <Td className="font-mono text-[11px]">{e.actor_ref || "—"}</Td>
                <Td className="font-mono text-[11px]">{e.target_ref || "—"}</Td>
                <Td className="text-right text-xs">{e.observed_at ? new Date(e.observed_at).toLocaleString() : "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {sel && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => setSel(null)}>
          <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)" }} onClick={(ev) => ev.stopPropagation()}>
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <div className="text-lg font-bold" style={{ color: "var(--c-ink)" }}>{String(sel.class_name)}</div>
                <div className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{String(sel.id)}</div>
              </div>
              <button onClick={() => setSel(null)} className="rounded-lg px-3 py-1.5 text-xs" style={{ border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>Close</button>
            </div>
            <div className="mb-4 grid grid-cols-2 gap-x-6 gap-y-3">
              {[...PRIMARY, ...Object.keys(sel).filter((k) => !PRIMARY.includes(k))].map((k) => {
                const v = sel[k];
                if (v == null || typeof v === "object") return null;
                return (
                  <div key={k}>
                    <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{k.replace(/_/g, " ")}</div>
                    <div className="break-words text-sm" style={{ color: "var(--c-ink)" }}>{String(v) || "—"}</div>
                  </div>
                );
              })}
            </div>
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Raw record</div>
              <pre className="max-h-64 overflow-auto rounded-lg p-3 text-[11px] leading-relaxed" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{JSON.stringify(sel, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
