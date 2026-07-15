"use client";

// Connector wizard (SRS §6.4 / ING-002). Two-step create: pick a kind from the catalogue
// (GET /connectors/catalogue), then configure name + credential secret + per-connector config, and create
// (POST /connectors). A webhook connector returns its source key exactly once — shown here, never again. senior-
// gated → 403 surfaced. Secrets are vault-sealed server-side and never returned.

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiGet, apiPost, errorText } from "@/lib/api";
import { PageHeader, Panel, StatusTag, Button } from "@/components/ui";

type Descriptor = { key: string; name: string; category: string; direction: string; phase: string };
type KV = { k: string; v: string };
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function NewConnectorPage() {
  const router = useRouter();
  const [catalogue, setCatalogue] = useState<Descriptor[]>([]);
  const [kind, setKind] = useState<Descriptor | null>(null);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [cfg, setCfg] = useState<KV[]>([{ k: "", v: "" }]);
  const [result, setResult] = useState<{ source_key?: string; id?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<{ catalogue: Descriptor[] | null }>("/connectors/catalogue").then((r) => setCatalogue(r.catalogue ?? [])).catch(() => {});
  }, []);

  async function create() {
    if (!kind) return;
    setErr(null);
    setBusy(true);
    const config: Record<string, string> = {};
    cfg.forEach(({ k, v }) => { if (k.trim()) config[k.trim()] = v; });
    try {
      const r = await apiPost<{ connector?: { id: string }; source_key?: string; ingest_url?: string }>("/connectors", {
        kind: kind.key,
        name: name || kind.name,
        direction: kind.direction,
        secret: secret || undefined,
        config,
      });
      setResult({ source_key: r.source_key, id: r.connector?.id });
    } catch (e) {
      setErr(errorText(e, "Adding a connector requires a senior analyst role.", "Create failed."));
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div className="mx-auto max-w-xl">
        <PageHeader title="Connector created" sub={kind?.name} />
        {result.source_key ? (
          <Panel title="Source key" sub="Send this in the X-Source-Key header when posting to the webhook. Shown once — copy it now.">
            <div className="rounded-lg p-3 font-mono text-sm" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)", wordBreak: "break-all" }}>{result.source_key}</div>
          </Panel>
        ) : (
          <Panel><p className="text-sm" style={{ color: "var(--c-ink-2)" }}>The connector is configured. Test it from the Integrations screen.</p></Panel>
        )}
        <div className="mt-4"><Link href="/console/integrations"><Button>Back to Integrations</Button></Link></div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl">
      <Link href="/console/integrations" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Integrations</Link>
      <div className="mt-2"><PageHeader title="Add connector" sub="Connect a telemetry source or response tool" /></div>
      {err && <p className="mb-3 text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</p>}

      {!kind ? (
        <Panel title="Choose a connector">
          <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))" }}>
            {catalogue.map((d) => (
              <button key={d.key} onClick={() => { setKind(d); setName(d.name); }} className="rounded-xl p-4 text-left transition hover:border-[color:var(--c-border-strong)]" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                <div className="flex items-center justify-between"><span className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{d.name}</span><span className="text-[10px] uppercase" style={{ color: "var(--c-ink-3)" }}>{d.phase}</span></div>
                <div className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{d.category} · {d.direction}</div>
              </button>
            ))}
          </div>
        </Panel>
      ) : (
        <Panel title={`Configure ${kind.name}`} actions={<button onClick={() => setKind(null)} className="text-[12px]" style={{ color: "var(--c-primary)" }}>← change</button>}>
          <div className="space-y-4">
            <div className="flex items-center gap-2"><StatusTag tone="info">{kind.category}</StatusTag><StatusTag tone="neutral">{kind.direction}</StatusTag></div>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Name
              <input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={inputStyle} /></label>
            {kind.key !== "webhook" && kind.key !== "syslog" && (
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Credential secret (API key / client secret — vault-sealed)
                <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={inputStyle} /></label>
            )}
            <div>
              <div className="mb-1.5 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Configuration (e.g. tenant_id, api_base, poll_interval)</div>
              <div className="space-y-2">
                {cfg.map((row, i) => (
                  <div key={i} className="flex gap-2">
                    <input value={row.k} onChange={(e) => setCfg((c) => c.map((x, idx) => (idx === i ? { ...x, k: e.target.value } : x)))} placeholder="key" className="w-1/3 rounded px-2 py-1.5 font-mono text-sm" style={inputStyle} />
                    <input value={row.v} onChange={(e) => setCfg((c) => c.map((x, idx) => (idx === i ? { ...x, v: e.target.value } : x)))} placeholder="value" className="flex-1 rounded px-2 py-1.5 text-sm" style={inputStyle} />
                    {cfg.length > 1 && <button onClick={() => setCfg((c) => c.filter((_, idx) => idx !== i))} className="px-1" style={{ color: "var(--c-ink-3)" }}>✕</button>}
                  </div>
                ))}
              </div>
              <Button className="mt-2" size="sm" variant="ghost" onClick={() => setCfg((c) => [...c, { k: "", v: "" }])}>+ Field</Button>
            </div>
            <Button disabled={busy || !name} onClick={create}>{busy ? "Creating…" : "Create connector"}</Button>
          </div>
        </Panel>
      )}
    </div>
  );
}
