"use client";

// Integrations — the tenant's connected sources & response tools plus the available catalogue (SRS §6.4/§6.5).
// GET /connectors lists configured connectors with derived health (healthy|degraded|silent|unknown); GET
// /connectors/catalogue lists installable descriptors with their explicit capability set. Test-connection is a
// live probe (senior-gated → surface 403). Capabilities are the honest, backend-advertised set — not aspirational.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, StatusTag, healthTone, EmptyState, Button } from "@/components/ui";

type Connector = {
  id: string;
  kind: string;
  name: string;
  direction: string;
  enabled: boolean;
  health: string;
  last_success?: string;
  created_at: string;
};
type Descriptor = { key: string; name: string; category: string; direction: string; capabilities: string[]; phase: string };

const CAP_LABEL: Record<string, string> = {
  pull_alerts: "Pull alerts",
  receive_webhook: "Webhook in",
  receive_syslog: "Syslog in",
  run_query: "Query",
  run_hunt: "Threat hunt",
  retrieve_asset: "Asset detail",
  isolate_endpoint: "Isolate host",
  release_endpoint: "Release host",
  disable_user: "Disable user",
  enable_user: "Enable user",
  push_ioc: "Push IOC",
  create_ticket: "Create ticket",
  action: "Response action",
};

export default function IntegrationsPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [catalogue, setCatalogue] = useState<Descriptor[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [c, cat] = await Promise.allSettled([
      apiGet<{ connectors: Connector[] | null }>("/connectors"),
      apiGet<{ catalogue: Descriptor[] | null }>("/connectors/catalogue"),
    ]);
    if (c.status === "fulfilled") setConnectors(c.value.connectors ?? []);
    if (cat.status === "fulfilled") setCatalogue(cat.value.catalogue ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function test(id: string) {
    setMsg(null);
    setBusy(id);
    try {
      const res = await apiPost<{ status: string; detail?: string }>(`/connectors/${id}/test`);
      const ok = res.status === "ok";
      setMsg({ tone: ok ? "ok" : "danger", text: ok ? "Connection healthy." : `Probe ${res.status}${res.detail ? `: ${res.detail}` : ""}.` });
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Testing a connector requires a senior analyst role." : e instanceof Error ? e.message : "Probe failed." });
    } finally {
      setBusy(null);
    }
  }

  const installedKinds = new Set(connectors.map((c) => c.kind));

  return (
    <div>
      <PageHeader title="Integrations" sub="Connected telemetry sources and response tools" actions={<Link href="/console/integrations/new"><Button size="sm">Add connector</Button></Link>} />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <Panel title="Your connectors" sub="Configured integrations and their live health" bodyStyle={{ padding: connectors.length ? 0 : undefined }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
        ) : connectors.length === 0 ? (
          <EmptyState title="No connectors configured" hint="Add one from the catalogue below to start ingesting telemetry." />
        ) : (
          <ul>
            {connectors.map((c) => (
              <li key={c.id} className="flex items-center gap-4 px-5 py-4" style={{ borderTop: "1px solid var(--c-border)" }}>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{c.name}</span>
                    <StatusTag tone={healthTone(c.health)}>{c.health}</StatusTag>
                    {!c.enabled && <StatusTag tone="neutral">disabled</StatusTag>}
                  </div>
                  <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                    {c.kind} · {c.direction} · last success {c.last_success ? new Date(c.last_success).toLocaleString() : "never"}
                  </div>
                </div>
                <Button size="sm" variant="ghost" disabled={busy === c.id} onClick={() => test(c.id)}>
                  {busy === c.id ? "Testing…" : "Test"}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="mt-6">
        <Panel title="Catalogue" sub="Available connector types and what each can do">
          <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}>
            {catalogue.map((d) => (
              <div key={d.key} className="rounded-xl p-4" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{d.name}</span>
                  {installedKinds.has(d.key) ? (
                    <StatusTag tone="ok">Connected</StatusTag>
                  ) : (
                    <span className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{d.phase}</span>
                  )}
                </div>
                <div className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{d.category}</div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {d.capabilities.map((cap) => (
                    <span key={cap} className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ background: "rgba(14,165,233,0.1)", color: "var(--c-primary)" }}>
                      {CAP_LABEL[cap] ?? cap}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
