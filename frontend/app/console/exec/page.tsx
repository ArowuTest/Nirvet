"use client";

// Executive posture (SRS §6.13 exec view) — a CISO-grade, point-in-time security posture for the tenant, composed
// entirely from existing tenant-scoped read endpoints (NO bespoke backend): GET /reports/summary (open counts,
// by-severity, by-stage, SLA posture, MTTA/MTTR, top ATT&CK, events/24h), GET /exposure/summary (vuln posture),
// GET /compliance/frameworks + /compliance/coverage (framework score). Deliberately shows only real values — no
// fabricated trend lines; time-series trend would need a snapshot projection (a genuine backend gap, deferred).

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, KpiStrip, Kpi, StatusTag, EmptyState } from "@/components/ui";

type MeanTimes = { window_days: number; mtta_seconds: number | null; mttr_seconds: number | null; acknowledged_count: number; resolved_count: number };
type SLAPosture = { open_incidents: number; ack_breaching: number; resolve_breaching: number; resolved_late: number };
type Summary = {
  alerts_by_severity: Record<string, number> | null;
  open_alerts: number;
  incidents_by_stage: Record<string, number> | null;
  open_incidents: number;
  events_last_24h: number;
  top_mitre: { technique: string; count: number }[] | null;
  sla: SLAPosture;
  mean_times: MeanTimes;
};
type Exposure = { by_severity: Record<string, number> | null; open_total: number; exploited_open: number; past_due: number };
type Coverage = { framework: string; score: number };

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];
const sevColor: Record<string, string> = { critical: "#fca5a5", high: "#fcd34d", medium: "#fde68a", low: "#7dd3fc", informational: "#cbd5e1" };

// dur formats a duration in seconds as a compact "Xh Ym" / "Xm" / "Xs".
function dur(seconds: number | null): string {
  if (seconds == null) return "—";
  const s = Math.round(seconds);
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  if (s >= 60) return `${Math.floor(s / 60)}m`;
  return `${s}s`;
}

export default function ExecPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [state, setState] = useState<"loading" | "ready">("loading");

  useEffect(() => {
    (async () => {
      const [s, e] = await Promise.allSettled([
        apiGet<Summary>("/reports/summary"),
        apiGet<Exposure>("/exposure/summary"),
      ]);
      if (s.status === "fulfilled") setSummary(s.value);
      if (e.status === "fulfilled") setExposure(e.value);
      // Compliance is best-effort: pick the first framework and read its coverage score.
      try {
        const fw = await apiGet<{ frameworks: { key?: string; name?: string }[] | string[] | null }>("/compliance/frameworks");
        const list = fw.frameworks ?? [];
        const first = typeof list[0] === "string" ? (list[0] as string) : ((list[0] as { key?: string; name?: string })?.key ?? (list[0] as { key?: string; name?: string })?.name);
        if (first) {
          const cov = await apiGet<Coverage>(`/compliance/coverage?framework=${encodeURIComponent(first)}`);
          setCoverage(cov);
        }
      } catch {
        /* compliance optional */
      }
      setState("ready");
    })();
  }, []);

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading posture…</div>;
  if (!summary)
    return (
      <div>
        <PageHeader title="Executive posture" />
        <EmptyState title="No data yet" hint="Posture appears once telemetry is flowing and cases are being worked." />
      </div>
    );

  const sla = summary.sla;
  const slaBreaching = sla.ack_breaching + sla.resolve_breaching;
  const slaOnTrack = sla.open_incidents > 0 ? Math.round(((sla.open_incidents - slaBreaching) / sla.open_incidents) * 100) : 100;
  const alertsBySev = summary.alerts_by_severity ?? {};
  const totalAlerts = Object.values(alertsBySev).reduce((a, b) => a + b, 0);

  return (
    <div>
      <PageHeader title="Executive posture" sub={`Point-in-time security posture · rolling ${summary.mean_times.window_days}-day KPIs`} />

      <KpiStrip>
        <Kpi label="Open incidents" value={String(summary.open_incidents)} tone={summary.open_incidents > 0 ? "warn" : "ok"} />
        <Kpi label="Open alerts" value={String(summary.open_alerts)} />
        <Kpi label="SLA on-track" value={`${slaOnTrack}%`} tone={slaBreaching > 0 ? "danger" : "ok"} sub={slaBreaching > 0 ? `${slaBreaching} breaching` : "no breaches"} />
        <Kpi label="Mean time to resolve" value={dur(summary.mean_times.mttr_seconds)} sub={`${summary.mean_times.resolved_count} closed in-window`} />
      </KpiStrip>

      <div className="mt-6 grid gap-6" style={{ gridTemplateColumns: "1.3fr 1fr" }}>
        <Panel title="SLA posture" sub="Incident SLA health against the tenant's ack/resolve policy (§6.8)">
          <div className="grid grid-cols-2 gap-4">
            <Metric label="Acknowledgement breaching" value={sla.ack_breaching} tone={sla.ack_breaching > 0 ? "danger" : "ok"} />
            <Metric label="Resolution breaching" value={sla.resolve_breaching} tone={sla.resolve_breaching > 0 ? "danger" : "ok"} />
            <Metric label="Resolved late (window)" value={sla.resolved_late} tone={sla.resolved_late > 0 ? "warn" : "ok"} />
            <Metric label="Mean time to acknowledge" value={dur(summary.mean_times.mtta_seconds)} sub={`${summary.mean_times.acknowledged_count} acked`} />
          </div>
        </Panel>

        <Panel title="Alert severity mix" sub="Open alerts by severity">
          {totalAlerts === 0 ? (
            <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>No open alerts.</p>
          ) : (
            <div className="space-y-2.5">
              {SEV_ORDER.filter((s) => alertsBySev[s]).map((s) => {
                const pct = Math.round((alertsBySev[s] / totalAlerts) * 100);
                return (
                  <div key={s}>
                    <div className="mb-1 flex items-center justify-between text-[12px]">
                      <span className="capitalize" style={{ color: "var(--c-ink-2)" }}>{s}</span>
                      <span style={{ color: "var(--c-ink-3)" }}>{alertsBySev[s]} · {pct}%</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full" style={{ background: "var(--c-surface-2)" }}>
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: sevColor[s] }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      <div className="mt-6 grid gap-6" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        <Panel title="Exposure" sub="Open-vulnerability posture (§6.15)">
          {exposure ? (
            <div className="space-y-3">
              <Metric label="Open vulnerabilities" value={exposure.open_total} />
              <Metric label="Known-exploited (open)" value={exposure.exploited_open} tone={exposure.exploited_open > 0 ? "danger" : "ok"} />
              <Metric label="Past remediation due" value={exposure.past_due} tone={exposure.past_due > 0 ? "warn" : "ok"} />
              <Link href="/console/assets" className="text-[12px]" style={{ color: "var(--c-primary)" }}>View assets →</Link>
            </div>
          ) : <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>Unavailable.</p>}
        </Panel>

        <Panel title="Compliance" sub="Framework control coverage (§6.14)">
          {coverage ? (
            <div>
              <div className="text-4xl font-extrabold" style={{ color: coverage.score >= 80 ? "var(--c-ok)" : coverage.score >= 50 ? "var(--c-warn)" : "var(--c-danger)" }}>{coverage.score}%</div>
              <div className="mt-1 text-[12px]" style={{ color: "var(--c-ink-3)" }}>{coverage.framework}</div>
              <Link href="/console/compliance" className="mt-3 inline-block text-[12px]" style={{ color: "var(--c-primary)" }}>View compliance →</Link>
            </div>
          ) : <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>No framework mapped yet.</p>}
        </Panel>

        <Panel title="Activity" sub="Telemetry throughput">
          <div className="space-y-3">
            <Metric label="Events (last 24h)" value={summary.events_last_24h} />
            <Metric label="Alerts triaged (open)" value={summary.open_alerts} />
          </div>
        </Panel>
      </div>

      {summary.top_mitre && summary.top_mitre.length > 0 && (
        <div className="mt-6">
          <Panel title="Top ATT&CK techniques" sub="Most-observed MITRE techniques across your telemetry">
            <div className="flex flex-wrap gap-2">
              {summary.top_mitre.slice(0, 12).map((t) => (
                <span key={t.technique} className="rounded-lg px-2.5 py-1.5 text-[12px]" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>
                  <span className="font-mono font-semibold" style={{ color: "var(--c-ink)" }}>{t.technique}</span> · {t.count}
                </span>
              ))}
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, sub, tone }: { label: string; value: number | string; sub?: string; tone?: "ok" | "warn" | "danger" }) {
  const color = tone === "danger" ? "var(--c-danger)" : tone === "warn" ? "var(--c-warn)" : tone === "ok" ? "var(--c-ok)" : "var(--c-ink)";
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div>
      <div className="mt-0.5 flex items-baseline gap-2">
        <span className="text-2xl font-bold" style={{ color }}>{value}</span>
        {sub && <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{sub}</span>}
      </div>
    </div>
  );
}
