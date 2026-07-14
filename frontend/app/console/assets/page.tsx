"use client";

// Assets & exposure (SRS §6.15) — the tenant's asset inventory and open-vulnerability posture. GET /assets lists
// assets (ref/name/kind/criticality/owner/tags); GET /vulnerabilities lists open vulns mapped to assets by ref;
// GET /exposure/summary is the rollup (by-severity, exploited-open, past-due). Registering an asset is manager-gated
// (POST /assets, upsert on ref) → non-managers see the 403 surfaced. Exposure drives triage priority (§6.8/§6.15).

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Asset = { id: string; ref: string; name: string; kind: string; criticality: string; owner: string; tags: string[] | null; created_at: string };
type Vuln = { id: string; ref: string; cve: string; title: string; severity: string; cvss: number; exploited: boolean; status: string; remediation_due?: string; created_at: string };
type Exposure = { by_severity: Record<string, number> | null; open_total: number; exploited_open: number; past_due: number };

const CRITICALITIES = ["low", "medium", "high", "critical"];
const critTone: Record<string, "ok" | "warn" | "danger" | "neutral"> = { low: "neutral", medium: "warn", high: "danger", critical: "danger" };
const vulnStatusTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = { open: "danger", in_progress: "warn", remediated: "ok", accepted: "neutral", false_positive: "neutral" };
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"assets" | "vulns">("assets");
  const [vulnStatus, setVulnStatus] = useState("open");
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ ref: "", name: "", kind: "host", criticality: "medium", owner: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const loadVulns = useCallback(async (status: string) => {
    const v = await apiGet<{ vulnerabilities: Vuln[] | null }>(`/vulnerabilities?status=${encodeURIComponent(status)}`).catch(() => ({ vulnerabilities: [] }));
    setVulns(v.vulnerabilities ?? []);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    const [a, e] = await Promise.allSettled([
      apiGet<{ assets: Asset[] | null }>("/assets"),
      apiGet<Exposure>("/exposure/summary"),
    ]);
    if (a.status === "fulfilled") setAssets(a.value.assets ?? []);
    if (e.status === "fulfilled") setExposure(e.value);
    await loadVulns(vulnStatus);
    setLoading(false);
  }, [loadVulns, vulnStatus]);

  useEffect(() => {
    load();
  }, [load]);

  async function register() {
    if (!form.ref.trim() || !form.name.trim()) {
      setMsg({ tone: "danger", text: "Ref and name are required." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      await apiPost("/assets", { ref: form.ref.trim(), name: form.name.trim(), kind: form.kind, criticality: form.criticality, owner: form.owner.trim(), tags: [] });
      setMsg({ tone: "ok", text: "Asset registered." });
      setForm({ ref: "", name: "", kind: "host", criticality: "medium", owner: "" });
      setShow(false);
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Registering an asset requires a manager role." : e instanceof Error ? e.message : "Failed to register." });
    } finally {
      setBusy(false);
    }
  }

  async function changeVulnStatus(s: string) {
    setVulnStatus(s);
    await loadVulns(s);
  }

  return (
    <div>
      <PageHeader title="Assets" sub="Asset inventory and open-vulnerability exposure" actions={<Button size="sm" onClick={() => setShow((v) => !v)}>{show ? "Cancel" : "Register asset"}</Button>} />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {exposure && (
        <KpiStrip>
          <Kpi label="Open vulnerabilities" value={String(exposure.open_total)} />
          <Kpi label="Known-exploited (open)" value={String(exposure.exploited_open)} tone={exposure.exploited_open > 0 ? "danger" : "ok"} />
          <Kpi label="Past remediation due" value={String(exposure.past_due)} tone={exposure.past_due > 0 ? "warn" : "ok"} />
          <Kpi label="Assets tracked" value={String(assets.length)} />
        </KpiStrip>
      )}

      {show && (
        <Panel title="Register an asset" sub="Upsert on ref — re-registering the same ref updates it" style={{ marginTop: 20, marginBottom: 8 }}>
          <div className="grid gap-2" style={{ gridTemplateColumns: "1.4fr 1.4fr 1fr 1fr 1fr auto" }}>
            <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Ref (host:FIN-01)" value={form.ref} onChange={(e) => setForm({ ...form, ref: e.target.value })} />
            <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              {["host", "user", "service", "cloud", "network"].map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
            <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
              {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Owner" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
            <Button size="sm" disabled={busy} onClick={register}>{busy ? "…" : "Register"}</Button>
          </div>
        </Panel>
      )}

      <div className="my-4 flex items-center gap-2">
        {(["assets", "vulns"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition"
            style={tab === t ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" } : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}
          >
            {t === "vulns" ? "Vulnerabilities" : "Inventory"}
          </button>
        ))}
      </div>

      {tab === "assets" ? (
        <Panel bodyStyle={{ padding: assets.length ? 0 : undefined }}>
          {loading ? (
            <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
          ) : assets.length === 0 ? (
            <EmptyState title="No assets yet" hint="Register assets or import them in bulk to triage alerts by business criticality." />
          ) : (
            <Table head={<><Th>Ref</Th><Th>Name</Th><Th>Kind</Th><Th>Criticality</Th><Th>Owner</Th><Th>Tags</Th></>}>
              {assets.map((a) => (
                <tr key={a.id}>
                  <Td className="font-mono text-[12px]">{a.ref}</Td>
                  <Td className="font-medium">{a.name}</Td>
                  <Td>{a.kind}</Td>
                  <Td><StatusTag tone={critTone[a.criticality] ?? "neutral"}>{a.criticality}</StatusTag></Td>
                  <Td className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>{a.owner || "—"}</Td>
                  <Td>
                    {a.tags && a.tags.length > 0 ? (
                      <div className="flex flex-wrap gap-1">{a.tags.map((t) => <span key={t} className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}>{t}</span>)}</div>
                    ) : "—"}
                  </Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      ) : (
        <div>
          <div className="mb-3 flex items-center gap-2">
            <span className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Status</span>
            <select className="rounded-lg px-2.5 py-1.5 text-xs" style={inputStyle} value={vulnStatus} onChange={(e) => changeVulnStatus(e.target.value)}>
              {["open", "in_progress", "remediated", "accepted", "false_positive", ""].map((s) => <option key={s || "all"} value={s}>{s || "all"}</option>)}
            </select>
          </div>
          <Panel bodyStyle={{ padding: vulns.length ? 0 : undefined }}>
            {vulns.length === 0 ? (
              <EmptyState title="No vulnerabilities" hint={`No ${vulnStatus || ""} vulnerabilities to show.`} />
            ) : (
              <Table head={<><Th>Severity</Th><Th>CVE</Th><Th>Title</Th><Th>Asset</Th><Th>CVSS</Th><Th>Status</Th><Th>Due</Th></>}>
                {vulns.map((v) => (
                  <tr key={v.id}>
                    <Td>
                      <div className="flex items-center gap-1.5">
                        <SevBadge severity={v.severity} />
                        {v.exploited && <span className="rounded px-1 py-0.5 text-[9px] font-bold uppercase" style={{ background: "rgba(239,68,68,0.16)", color: "#fca5a5" }} title="Known-exploited">KEV</span>}
                      </div>
                    </Td>
                    <Td className="font-mono text-[12px]">{v.cve || "—"}</Td>
                    <Td className="font-medium">{v.title}</Td>
                    <Td className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{v.ref}</Td>
                    <Td>{v.cvss.toFixed(1)}</Td>
                    <Td><StatusTag tone={vulnStatusTone[v.status] ?? "neutral"}>{v.status.replace(/_/g, " ")}</StatusTag></Td>
                    <Td className="text-[12px]" style={{ color: v.remediation_due && new Date(v.remediation_due) < new Date() ? "var(--c-danger)" : "var(--c-ink-3)" }}>
                      {v.remediation_due ? new Date(v.remediation_due).toLocaleDateString() : "—"}
                    </Td>
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
