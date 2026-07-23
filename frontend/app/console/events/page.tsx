"use client";

// Normalized events (SRS §6.5 / ADR-0006) — the tenant's canonical event stream. GET /events returns the
// normalized records; a row opens a full-event detail modal (every field the record carries + raw JSON), the
// depth an analyst needs to inspect what a detection fired on.

import { useEffect, useState } from "react";
import { apiGet, errorText } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type RawEvent = { id: string; checksum: string; payload_base64: string };
type RawState = { loading?: boolean; err?: string; data?: RawEvent } | null;

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
  const [raw, setRaw] = useState<RawState>(null);

  useEffect(() => {
    apiGet<{ events: Event[] | null }>("/events").then((r) => setItems(r.events ?? [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  function open(e: Event) {
    setSel(e);
    setRaw(null); // reset any prior raw-payload verification when switching events
  }

  // Chain-of-custody verification (senior only). The normalized record carries raw_pointer = "raw_events:<uuid>" and
  // the checksum it was normalized from. GET /investigation/raw-event/{id} returns the IMMUTABLE stored payload +
  // its checksum; matching that against the normalized record's checksum proves the raw evidence is intact and
  // untampered. A non-senior gets a friendly 403 (the server enforces; we surface its reason).
  async function verifyRaw(ev: Event) {
    const ptr = String(ev.raw_pointer ?? "");
    const rawId = ptr.startsWith("raw_events:") ? ptr.slice("raw_events:".length) : "";
    if (!rawId) {
      setRaw({ err: "This event carries no stored raw-payload reference." });
      return;
    }
    setRaw({ loading: true });
    try {
      const data = await apiGet<RawEvent>(`/investigation/raw-event/${encodeURIComponent(rawId)}`);
      setRaw({ data });
    } catch (e) {
      setRaw({ err: errorText(e, "Verifying the raw payload requires a senior analyst role.", "Could not fetch the stored raw event.") });
    }
  }

  function decodePayload(b64: string): string {
    try {
      return atob(b64);
    } catch {
      return "(binary payload — not printable)";
    }
  }

  return (
    <div>
      <PageHeader title="Normalized events" sub="The tenant's canonical event stream — click a row for the full record" />
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No events" hint="Events appear once telemetry is flowing from your connectors." /></div>
        ) : (
          <Table head={<><Th>Source</Th><Th>Class</Th><Th>Severity</Th><Th>Actor</Th><Th>Target</Th><Th className="text-right">Observed</Th></>}>
            {items.map((e) => (
              <tr key={e.id} onClick={() => open(e)} className="cursor-pointer transition hover:bg-[color:var(--c-surface-2)]">
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

            {/* Chain-of-custody: fetch the immutable stored raw payload and verify its checksum matches this record. */}
            <div className="mt-4 border-t pt-3" style={{ borderColor: "var(--c-border)" }}>
              <div className="flex items-center justify-between gap-2">
                <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Stored raw payload · chain-of-custody</div>
                <Button size="sm" variant="ghost" disabled={raw?.loading} onClick={() => verifyRaw(sel)}>
                  {raw?.loading ? "Verifying…" : "Verify stored payload"}
                </Button>
              </div>
              {raw?.err && <p className="mt-2 text-[12px]" style={{ color: "var(--c-danger)" }}>{raw.err}</p>}
              {raw?.data && (() => {
                const match = String(sel.checksum ?? "") !== "" && String(sel.checksum) === raw.data.checksum;
                return (
                  <div className="mt-2 space-y-2">
                    <div className="flex items-center gap-2">
                      {match ? <StatusTag tone="ok">checksum verified</StatusTag> : <StatusTag tone="danger">checksum mismatch</StatusTag>}
                      <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{match ? "The stored raw evidence is intact and untampered." : "The stored payload does not match this record's checksum."}</span>
                    </div>
                    <div className="truncate font-mono text-[10px]" style={{ color: "var(--c-ink-3)" }} title={raw.data.checksum}>sha256:{raw.data.checksum}</div>
                    <pre className="max-h-48 overflow-auto rounded-lg p-3 text-[11px] leading-relaxed" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{decodePayload(raw.data.payload_base64)}</pre>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
