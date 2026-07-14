"use client";

// AI provider & governance config (ADMIN-001 / §6.12). Platform-admin surface, three panels:
//   1. Global provider — the effective default LLM (anthropic | openai_compatible | disabled). api_key is
//      write-only (server returns has_key, never the value). base_url only for openai_compatible and MUST already
//      be on the egress allowlist. SaveResult warnings (e.g. cleartext-http key exposure) are surfaced.
//   2. Egress allowlist — the SSRF allowlist an openai_compatible base_url is validated against. Add/remove.
//   3. Per-tenant AI policy — restrict which provider kinds a given tenant may use (allowlist, not block).
// Wired to /admin/ai/provider, /admin/ai/allowed-endpoints[/{id}], /admin/tenants/{id}/ai-policy, /admin/tenants.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPut, apiPost, apiDelete, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

type ProviderView = { kind: string; base_url?: string; model: string; has_key: boolean; global: boolean };
type SaveResult = { provider: ProviderView; warnings?: string[] };
type Endpoint = { id: string; scheme: string; host: string; port: number; note: string };
type Tenant = { id: string; name: string };

const KINDS = ["anthropic", "openai_compatible", "disabled"];
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function AiConfigPage() {
  const [prov, setProv] = useState<ProviderView | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  // provider form
  const [kind, setKind] = useState("anthropic");
  const [baseURL, setBaseURL] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);

  const [eps, setEps] = useState<Endpoint[]>([]);
  const [newEp, setNewEp] = useState({ scheme: "https", host: "", port: 443, note: "" });

  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [polTid, setPolTid] = useState("");
  const [polKinds, setPolKinds] = useState<string[]>([]);

  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const p = await apiGet<ProviderView>("/admin/ai/provider");
      setProv(p); setNotConfigured(false);
      setKind(p.kind); setBaseURL(p.base_url ?? ""); setModel(p.model);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) { setNotConfigured(true); setProv(null); }
    }
    await apiGet<{ endpoints: Endpoint[] | null }>("/admin/ai/allowed-endpoints").then((r) => setEps(r.endpoints ?? [])).catch(() => {});
    await apiGet<{ tenants: Tenant[] | null }>("/admin/tenants").then((r) => setTenants(r.tenants ?? [])).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  async function saveProvider() {
    setMsg(null); setWarnings([]);
    try {
      const body: Record<string, unknown> = { kind, base_url: kind === "openai_compatible" ? baseURL : "", model, api_key: apiKey };
      const r = await apiPut<SaveResult>("/admin/ai/provider", body);
      setProv(r.provider); setNotConfigured(false); setApiKey("");
      setWarnings(r.warnings ?? []);
      setMsg({ tone: "ok", text: "Global AI provider saved." });
    } catch (e) { setMsg({ tone: "danger", text: `Save provider: ${e instanceof ApiError ? e.message : "failed"}` }); }
  }

  async function run(fn: () => Promise<unknown>, ok: string, what: string) {
    setMsg(null);
    try { await fn(); setMsg({ tone: "ok", text: ok }); await load(); }
    catch (e) { setMsg({ tone: "danger", text: `${what}: ${e instanceof ApiError ? e.message : "failed"}` }); }
  }

  async function loadPolicy(tid: string) {
    setPolTid(tid); setPolKinds([]);
    if (!tid) return;
    // No direct GET for a specific tenant's policy from padmin; default to all kinds, admin narrows. (Effective
    // policy is enforced server-side; this panel writes the allowlist.)
    setPolKinds([...KINDS]);
  }

  return (
    <div>
      <PageHeader title="AI configuration" sub="Global LLM provider, egress allowlist, and per-tenant provider policy" />

      {msg && <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: msg.tone === "ok" ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)", color: msg.tone === "ok" ? "#10b981" : "#ef4444", border: "1px solid var(--c-border)" }}>{msg.text}</div>}

      {/* 1. Global provider */}
      <Panel title="Global AI provider" sub={notConfigured ? "No provider configured — AI features are effectively disabled until set" : `Effective: ${prov?.kind ?? ""}${prov?.has_key ? " · key set" : " · no key"}`}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Provider kind
            <select value={kind} onChange={(e) => setKind(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle}>
              {KINDS.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}
            </select>
          </label>
          <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Model
            <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="claude-… / gpt-…" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
          </label>
          {kind === "openai_compatible" && (
            <label className="text-xs md:col-span-2" style={{ color: "var(--c-ink-2)" }}>Base URL (must be on the egress allowlist)
              <input value={baseURL} onChange={(e) => setBaseURL(e.target.value)} placeholder="https://llm.internal:8443" className="mt-1 w-full rounded-lg px-3 py-2 font-mono text-sm" style={inputStyle} />
            </label>
          )}
          <label className="text-xs md:col-span-2" style={{ color: "var(--c-ink-2)" }}>API key {prov?.has_key && <span style={{ color: "var(--c-ink-3)" }}>(set — leave blank to keep)</span>}
            <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={prov?.has_key ? "•••••••• (unchanged)" : "sk-…"} autoComplete="new-password" className="mt-1 w-full rounded-lg px-3 py-2 font-mono text-sm" style={inputStyle} />
          </label>
        </div>
        {warnings.length > 0 && (
          <div className="mt-3 rounded-lg px-3 py-2 text-[12px]" style={{ background: "rgba(245,158,11,0.12)", color: "#f59e0b", border: "1px solid var(--c-border)" }}>
            {warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
          </div>
        )}
        <div className="mt-3"><Button size="sm" onClick={saveProvider}>Save provider</Button></div>
      </Panel>

      {/* 2. Egress allowlist */}
      <Panel title="Egress allowlist" sub="Approved endpoints an openai_compatible base URL is validated against (SSRF guard)" bodyStyle={{ padding: 0 }}>
        <div className="p-4">
          {eps.length === 0 ? <EmptyState title="No approved endpoints" hint="Add an endpoint before configuring a self-hosted openai_compatible provider." /> : (
            <Table head={<><Th>Scheme</Th><Th>Host</Th><Th>Port</Th><Th>Note</Th><Th className="text-right"></Th></>}>
              {eps.map((e) => (
                <tr key={e.id}>
                  <Td><StatusTag tone={e.scheme === "https" ? "ok" : "warn"}>{e.scheme}</StatusTag></Td>
                  <Td className="font-mono text-xs">{e.host}</Td>
                  <Td className="text-xs">{e.port}</Td>
                  <Td className="text-xs">{e.note || "—"}</Td>
                  <Td className="text-right"><Button size="sm" variant="danger" onClick={() => run(() => apiDelete(`/admin/ai/allowed-endpoints/${e.id}`), "Endpoint removed.", "Remove")}>✕</Button></Td>
                </tr>
              ))}
            </Table>
          )}
          <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-5">
            <select value={newEp.scheme} onChange={(e) => setNewEp({ ...newEp, scheme: e.target.value, port: e.target.value === "https" ? 443 : 80 })} className="rounded px-2 py-1.5 text-sm" style={inputStyle}>
              <option value="https">https</option><option value="http">http</option>
            </select>
            <input value={newEp.host} onChange={(e) => setNewEp({ ...newEp, host: e.target.value })} placeholder="host" className="md:col-span-2 rounded px-2 py-1.5 font-mono text-sm" style={inputStyle} />
            <input type="number" value={newEp.port} onChange={(e) => setNewEp({ ...newEp, port: Number(e.target.value) })} placeholder="port" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
            <Button size="sm" disabled={!newEp.host} onClick={() => run(() => apiPost("/admin/ai/allowed-endpoints", newEp).then(() => setNewEp({ scheme: "https", host: "", port: 443, note: "" })), "Endpoint added.", "Add")}>Add</Button>
            <input value={newEp.note} onChange={(e) => setNewEp({ ...newEp, note: e.target.value })} placeholder="note (optional)" className="md:col-span-5 rounded px-2 py-1.5 text-sm" style={inputStyle} />
          </div>
        </div>
      </Panel>

      {/* 3. Per-tenant policy */}
      <Panel title="Per-tenant AI policy" sub="Restrict which provider kinds a tenant may use (allowlist). Empty = not permitted to save.">
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Tenant
            <select value={polTid} onChange={(e) => loadPolicy(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle}>
              <option value="">Select a tenant…</option>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
          {polTid && (
            <div className="text-xs" style={{ color: "var(--c-ink-2)" }}>Allowed provider kinds
              <div className="mt-2 flex flex-wrap gap-3">
                {KINDS.map((k) => (
                  <label key={k} className="flex items-center gap-1.5 capitalize">
                    <input type="checkbox" checked={polKinds.includes(k)} onChange={(e) => setPolKinds((cur) => e.target.checked ? [...cur, k] : cur.filter((x) => x !== k))} />
                    {k.replace(/_/g, " ")}
                  </label>
                ))}
              </div>
              <div className="mt-3"><Button size="sm" disabled={polKinds.length === 0} onClick={() => run(() => apiPut(`/admin/tenants/${polTid}/ai-policy`, { allowed_kinds: polKinds }), "Tenant AI policy saved.", "Save policy")}>Save policy</Button></div>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
