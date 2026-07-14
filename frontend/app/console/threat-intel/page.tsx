"use client";

// Threat intelligence (SRS §6.10) — the tenant's watchlist indicators and STIX 2.1 object store, plus the decay
// settings that govern how a STIX match ages out. GET /threat-intel (watchlist), GET /threat-intel/stix (objects,
// optional ?type=), GET /threat-intel/settings. Adding a watchlist indicator is senior-gated (POST /threat-intel) →
// 403 surfaced. These feed alert enrichment (the alert-detail "Threat intelligence" panel matches against this).

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, EmptyState, Button } from "@/components/ui";

type Indicator = { id: string; type: string; value: string; tlp: string; score: number; tags: string[] | null; created_at: string };
type StixObject = { id: string; type: string; labels: string[] | null; confidence: number; tlp: string; source: string; value?: string; pattern?: string; revoked: boolean; created: string };
type Settings = { decay_half_life_days: number; min_effective_confidence: number; sighting_boost_cap: number };

const IND_TYPES = ["ip", "domain", "url", "hash", "email", "user", "host"];
const TLPS = ["clear", "green", "amber", "red"];
const tlpTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = { clear: "neutral", green: "ok", amber: "warn", red: "danger" };
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function ThreatIntelPage() {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [stix, setStix] = useState<StixObject[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"watchlist" | "stix">("watchlist");
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ type: "ip", value: "", tlp: "amber", score: 75 });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [i, s, cfg] = await Promise.allSettled([
      apiGet<{ indicators: Indicator[] | null }>("/threat-intel"),
      apiGet<{ objects: StixObject[] | null }>("/threat-intel/stix?limit=200"),
      apiGet<Settings>("/threat-intel/settings"),
    ]);
    if (i.status === "fulfilled") setIndicators(i.value.indicators ?? []);
    if (s.status === "fulfilled") setStix(s.value.objects ?? []);
    if (cfg.status === "fulfilled") setSettings(cfg.value);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    if (!form.value.trim()) {
      setMsg({ tone: "danger", text: "An indicator value is required." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      await apiPost("/threat-intel", { type: form.type, value: form.value.trim(), tlp: form.tlp, score: Number(form.score), tags: [] });
      setMsg({ tone: "ok", text: "Indicator added to the watchlist." });
      setForm({ type: "ip", value: "", tlp: "amber", score: 75 });
      setShow(false);
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Adding an indicator requires a senior analyst role." : e instanceof Error ? e.message : "Failed to add." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="Threat intelligence" sub="Watchlist indicators and STIX 2.1 objects powering alert enrichment" actions={<Button size="sm" onClick={() => setShow((v) => !v)}>{show ? "Cancel" : "Add indicator"}</Button>} />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {settings && (
        <Panel title="Match decay" sub="How a STIX match's confidence ages out (§6.10)" style={{ marginBottom: 20 }}>
          <div className="flex flex-wrap gap-6 text-sm">
            <div><span style={{ color: "var(--c-ink-3)" }}>Half-life</span> <span className="font-semibold">{settings.decay_half_life_days}d</span></div>
            <div><span style={{ color: "var(--c-ink-3)" }}>Min effective confidence</span> <span className="font-semibold">{settings.min_effective_confidence}</span></div>
            <div><span style={{ color: "var(--c-ink-3)" }}>Sighting boost cap</span> <span className="font-semibold">{settings.sighting_boost_cap}</span></div>
          </div>
        </Panel>
      )}

      {show && (
        <Panel title="Add a watchlist indicator" style={{ marginBottom: 8 }}>
          <div className="grid gap-2" style={{ gridTemplateColumns: "1fr 2fr 1fr 1fr auto" }}>
            <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
              {IND_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Value (e.g. 203.0.113.4)" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
            <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={form.tlp} onChange={(e) => setForm({ ...form, tlp: e.target.value })}>
              {TLPS.map((t) => <option key={t} value={t}>TLP:{t}</option>)}
            </select>
            <input type="number" min={0} max={100} className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Score" value={form.score} onChange={(e) => setForm({ ...form, score: Number(e.target.value) })} />
            <Button size="sm" disabled={busy} onClick={add}>{busy ? "…" : "Add"}</Button>
          </div>
        </Panel>
      )}

      <div className="my-4 flex items-center gap-2">
        {(["watchlist", "stix"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition"
            style={tab === t ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" } : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}
          >
            {t === "stix" ? "STIX objects" : "Watchlist"}
          </button>
        ))}
      </div>

      {tab === "watchlist" ? (
        <Panel bodyStyle={{ padding: indicators.length ? 0 : undefined }}>
          {loading ? (
            <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
          ) : indicators.length === 0 ? (
            <EmptyState title="No watchlist indicators" hint="Add IOCs here or import a STIX bundle; they enrich matching alerts automatically." />
          ) : (
            <Table head={<><Th>Type</Th><Th>Value</Th><Th>TLP</Th><Th>Score</Th><Th>Tags</Th><Th className="text-right">Added</Th></>}>
              {indicators.map((i) => (
                <tr key={i.id}>
                  <Td><span className="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{i.type}</span></Td>
                  <Td className="font-mono text-[12px]">{i.value}</Td>
                  <Td><StatusTag tone={tlpTone[i.tlp] ?? "neutral"}>TLP:{i.tlp}</StatusTag></Td>
                  <Td>{i.score}</Td>
                  <Td>{i.tags && i.tags.length > 0 ? <div className="flex flex-wrap gap-1">{i.tags.map((t) => <span key={t} className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}>{t}</span>)}</div> : "—"}</Td>
                  <Td className="text-right text-xs">{new Date(i.created_at).toLocaleDateString()}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      ) : (
        <Panel bodyStyle={{ padding: stix.length ? 0 : undefined }}>
          {loading ? (
            <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
          ) : stix.length === 0 ? (
            <EmptyState title="No STIX objects" hint="Import a STIX 2.1 bundle to populate indicators, malware, and threat actors." />
          ) : (
            <Table head={<><Th>Type</Th><Th>Observable / pattern</Th><Th>Labels</Th><Th>Confidence</Th><Th>TLP</Th><Th>Source</Th></>}>
              {stix.map((o) => (
                <tr key={o.id}>
                  <Td>
                    <span className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{o.type}</span>
                    {o.revoked && <span className="ml-1.5 text-[10px] uppercase" style={{ color: "var(--c-danger)" }}>revoked</span>}
                  </Td>
                  <Td className="max-w-xs truncate font-mono text-[11px]" title={o.value || o.pattern || ""}>{o.value || o.pattern || "—"}</Td>
                  <Td>{o.labels && o.labels.length > 0 ? <div className="flex flex-wrap gap-1">{o.labels.map((l) => <span key={l} className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "rgba(245,158,11,0.12)", color: "#fcd34d" }}>{l}</span>)}</div> : "—"}</Td>
                  <Td>{o.confidence}</Td>
                  <Td><StatusTag tone={tlpTone[o.tlp] ?? "neutral"}>TLP:{o.tlp}</StatusTag></Td>
                  <Td className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>{o.source || "—"}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      )}
    </div>
  );
}
