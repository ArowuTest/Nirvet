"use client";

// Evidence (SRS §6.13) — tamper-evident case evidence packs. A pack bundles an incident's case record, timeline,
// alerts, events, assets, audit trail and a SHA-256 manifest, Ed25519-signed so it verifies out-of-band. Packs are
// built per incident (GET /incidents/{id}/evidence-pack, senior-gated) — there is no separate store — so this screen
// lists incidents and exports a pack on demand. The signing public key is published here for offline verification.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, ApiError, API_BASE } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, stageTone, EmptyState, Button } from "@/components/ui";

type Incident = { id: string; title: string; severity: string; stage: string; created_at: string };

export default function EvidencePage() {
  const [items, setItems] = useState<Incident[]>([]);
  const [pubkey, setPubkey] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiGet<{ incidents: Incident[] | null }>("/incidents");
      setItems(res.incidents ?? []);
    } catch {
      setItems([]);
    }
    try {
      const k = await apiGet<{ algorithm: string; public_key: string }>("/evidence/public-key");
      setPubkey(k.public_key);
    } catch {
      /* non-fatal */
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Download the signed pack. It's a credentialed GET returning downloadable JSON; we fetch as a blob so the
  // httpOnly session cookie is sent, then trigger a client-side save (a bare <a href> wouldn't carry auth reliably).
  async function download(inc: Incident) {
    setMsg(null);
    setBusy(inc.id);
    try {
      const res = await fetch(`${API_BASE}/incidents/${inc.id}/evidence-pack`, { credentials: "include" });
      if (res.status === 403) throw new ApiError(403, "forbidden", "forbidden");
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence-${inc.id}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMsg({ tone: "ok", text: `Evidence pack for "${inc.title}" exported.` });
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Exporting an evidence pack requires a senior analyst role." : e instanceof Error ? e.message : "Export failed." });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader title="Evidence" sub="Tamper-evident, signed case evidence packs" />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {pubkey && (
        <Panel title="Signing key" sub="Ed25519 public key — verify an exported pack's signature out-of-band" style={{ marginBottom: 24 }}>
          <div className="flex items-center gap-3">
            <code className="min-w-0 flex-1 truncate rounded-lg px-3 py-2 font-mono text-[12px]" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }} title={pubkey}>{pubkey}</code>
            <Button size="sm" variant="ghost" onClick={() => navigator.clipboard?.writeText(pubkey).then(() => setMsg({ tone: "ok", text: "Public key copied." })).catch(() => {})}>Copy</Button>
          </div>
        </Panel>
      )}

      <Panel title="Cases" sub="Export a signed evidence pack for any case" bodyStyle={{ padding: items.length ? 0 : undefined }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
        ) : items.length === 0 ? (
          <EmptyState title="No cases yet" hint="Evidence packs are exported per incident; open a case first." />
        ) : (
          <Table head={<><Th>Severity</Th><Th>Case</Th><Th>Stage</Th><Th>Opened</Th><Th className="text-right">Evidence</Th></>}>
            {items.map((i) => (
              <tr key={i.id}>
                <Td><SevBadge severity={i.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]"><Link href={`/console/incidents/${i.id}`} className="font-medium hover:underline">{i.title}</Link></Td>
                <Td><StatusTag tone={stageTone(i.stage)}>{i.stage.replace(/_/g, " ")}</StatusTag></Td>
                <Td className="text-xs">{new Date(i.created_at).toLocaleDateString()}</Td>
                <Td className="text-right">
                  <Button size="sm" variant="ghost" disabled={busy === i.id} onClick={() => download(i)}>
                    {busy === i.id ? "Exporting…" : "Download pack"}
                  </Button>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
