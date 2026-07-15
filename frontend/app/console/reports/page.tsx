"use client";

// Reports — operational metrics + report generation (§6.13). Top: the live SOC summary (GET /reports/summary,
// richer than the dashboard KPIs — MTTR, SLA breakdown). Bottom: generate a report (POST /reports {type,format}),
// poll its status (GET /reports/{id}) until ready, then download (GET /reports/{id}/download). Slice A generates
// the "service_review" type; formats CSV/JSON/XLSX/PDF. There is no server list route yet, so generated reports
// are tracked in-session with their download links.

import { useEffect, useRef, useState } from "react";
import { apiGet, apiGetCached, apiPost, API_BASE, ApiError } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, StatusTag, Button } from "@/components/ui";

type Summary = {
  open_alerts: number;
  open_incidents: number;
  events_last_24h: number;
  sla: { open_incidents: number; ack_breaching: number; resolve_breaching: number; resolved_late: number };
  mean_times: { mttr_seconds: number | null; resolved_count: number };
};
type Report = { id: string; type: string; format: string; status: string; row_count: number; byte_size: number; error?: string; created_at: string };

const FORMATS = ["csv", "json", "xlsx", "pdf"];

function mttr(sec: number | null): string {
  if (sec == null) return "—";
  const h = sec / 3600;
  return h >= 1 ? `${h.toFixed(1)}h` : `${Math.round(sec / 60)}m`;
}
function statusTone(s: string): "ok" | "warn" | "danger" | "neutral" {
  return s === "ready" ? "ok" : s === "failed" ? "danger" : "warn";
}

export default function ReportsPage() {
  const [sum, setSum] = useState<Summary | null>(null);
  const [format, setFormat] = useState("csv");
  const [reports, setReports] = useState<Report[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const timers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  useEffect(() => {
    apiGetCached<Summary>("/reports/summary").then(setSum).catch(() => {});
    return () => {
      Object.values(timers.current).forEach(clearTimeout);
    };
  }, []);

  function poll(id: string) {
    timers.current[id] = setTimeout(async () => {
      try {
        const r = await apiGet<Report>(`/reports/${id}`);
        setReports((rs) => rs.map((x) => (x.id === id ? r : x)));
        if (r.status === "running") poll(id);
      } catch {
        /* stop polling on error */
      }
    }, 1500);
  }

  async function generate() {
    setErr(null);
    setBusy(true);
    try {
      const r = await apiPost<Report>("/reports", { type: "service_review", format });
      setReports((rs) => [r, ...rs]);
      if (r.status === "running") poll(r.id);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Could not start report generation.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="Reports" sub="Operational metrics and exportable reports for your tenant" />

      <KpiStrip>
        <Kpi label="Open Incidents" value={sum?.open_incidents ?? "—"} sub="active cases" tone={sum && sum.open_incidents > 0 ? "warn" : "default"} />
        <Kpi label="Open Alerts" value={sum?.open_alerts ?? "—"} sub="awaiting triage" />
        <Kpi label="MTTR" value={mttr(sum?.mean_times.mttr_seconds ?? null)} sub={`${sum?.mean_times.resolved_count ?? 0} resolved`} />
        <Kpi label="SLA Breaching" value={sum ? sum.sla.ack_breaching + sum.sla.resolve_breaching : "—"} sub="ack + resolve overdue" tone={sum && sum.sla.ack_breaching + sum.sla.resolve_breaching > 0 ? "danger" : "ok"} />
        <Kpi label="Events · 24h" value={sum ? sum.events_last_24h.toLocaleString() : "—"} sub="ingested" />
      </KpiStrip>

      <div className="mt-6 grid gap-6" style={{ gridTemplateColumns: "1fr 1.4fr" }}>
        <Panel title="Generate report" sub="Service review — a summary of your SOC activity">
          <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            Format
            <select value={format} onChange={(e) => setFormat(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm uppercase" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}>
              {FORMATS.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
            </select>
          </label>
          {err && <p className="mt-2 text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</p>}
          <Button className="mt-3" disabled={busy} onClick={generate}>{busy ? "Starting…" : "Generate"}</Button>
        </Panel>

        <Panel title="Generated this session" sub="Reports you've generated — download once ready" bodyStyle={{ padding: reports.length ? 0 : undefined }}>
          {reports.length === 0 ? (
            <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No reports generated yet.</p>
          ) : (
            <ul>
              {reports.map((r) => (
                <li key={r.id} className="flex items-center gap-3 px-5 py-3.5" style={{ borderTop: "1px solid var(--c-border)" }}>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium capitalize" style={{ color: "var(--c-ink)" }}>{r.type.replace(/_/g, " ")}</span>
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{r.format}</span>
                      <StatusTag tone={statusTone(r.status)}>{r.status}</StatusTag>
                    </div>
                    <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                      {new Date(r.created_at).toLocaleString()}
                      {r.status === "ready" && ` · ${r.row_count} rows · ${(r.byte_size / 1024).toFixed(1)} KB`}
                      {r.error && ` · ${r.error}`}
                    </div>
                  </div>
                  {r.status === "ready" && (
                    <a href={`${API_BASE}/reports/${r.id}/download`} className="rounded-lg px-3 py-1.5 text-xs font-semibold" style={{ border: "1px solid var(--c-border-strong)", color: "var(--c-primary)" }}>
                      Download
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
