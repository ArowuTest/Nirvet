"use client";

// Customer security posture (read-model Slice B / riskscore) — GET /customer/risk-score. The composite risk
// score (0–100, higher = worse) with its EXPLAINABLE component breakdown: exposure, compliance, operational —
// each linking to the detail that drives it. Honest by construction: composed from real signals, no fabricated
// domain sub-scores. Renormalized when a component has no data.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, EmptyState } from "@/components/ui";

type Component = {
  key: string;
  label: string;
  risk: number;
  weight: number;
  present: boolean;
  drivers: Record<string, number>;
};
type RiskScore = { composite: number; band: string; tone: string; components: Component[] };

const TONE_COLOR: Record<string, string> = {
  ok: "var(--c-ok)",
  warn: "var(--c-warn)",
  danger: "var(--c-danger)",
  neutral: "var(--c-ink-3)",
};

// Where each component's drivers live, so a customer can act on the score.
const COMPONENT_LINK: Record<string, { href: string; cta: string }> = {
  exposure: { href: "/portal/vulnerabilities", cta: "View vulnerabilities" },
  compliance: { href: "/portal/compliance", cta: "View compliance" },
  operational: { href: "/portal/incidents", cta: "View incidents" },
};

const DRIVER_LABEL: Record<string, string> = {
  open_vulnerabilities: "open vulnerabilities",
  exploited: "known-exploited",
  past_due: "past remediation due",
  coverage_pct: "avg coverage %",
  open_incidents: "open incidents",
  ack_breaching: "ack SLA breaching",
  resolve_breaching: "resolve SLA breaching",
  resolved_late: "resolved late",
};

function Gauge({ value, tone }: { value: number; tone: string }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, value)) / 100;
  const color = TONE_COLOR[tone] ?? TONE_COLOR.neutral;
  return (
    <svg width="140" height="140" viewBox="0 0 140 140" aria-hidden="true">
      <circle cx="70" cy="70" r={r} fill="none" stroke="var(--c-surface-2)" strokeWidth="12" />
      <circle
        cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
        strokeDasharray={`${circ * pct} ${circ}`} transform="rotate(-90 70 70)"
      />
      <text x="70" y="66" textAnchor="middle" fontSize="34" fontWeight="800" fill="var(--c-ink)">{value}</text>
      <text x="70" y="88" textAnchor="middle" fontSize="11" fill="var(--c-ink-3)">/ 100 risk</text>
    </svg>
  );
}

export default function PortalPosture() {
  const [rs, setRs] = useState<RiskScore | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    apiGet<{ risk_score: RiskScore }>("/customer/risk-score")
      .then((r) => { setRs(r.risk_score); setState("ready"); })
      .catch(() => setState("error"));
  }, []);

  if (state === "loading") return <Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div></Panel>;
  if (state === "error" || !rs) {
    return (
      <div>
        <PageHeader title="Security posture" sub="Your composite risk score" />
        <Panel><EmptyState title="Posture unavailable" hint="Your risk score could not be computed right now." /></Panel>
      </div>
    );
  }

  const tone = TONE_COLOR[rs.tone] ?? TONE_COLOR.neutral;

  return (
    <div>
      <PageHeader title="Security posture" sub="Your composite risk score across exposure, compliance and operations" />

      <Panel>
        <div className="flex flex-col items-center gap-5 sm:flex-row sm:gap-8">
          <Gauge value={rs.composite} tone={rs.tone} />
          <div>
            <span className="rounded-full px-3 py-1 text-sm font-semibold" style={{ background: `color-mix(in srgb, ${tone} 15%, transparent)`, color: tone }}>
              {rs.band} risk
            </span>
            <p className="mt-3 max-w-md text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
              A weighted composite of your live exposure, compliance coverage and operational SLA posture. Higher is
              worse. Each component below is scored from your own estate and links to what&apos;s driving it.
            </p>
          </div>
        </div>
      </Panel>

      <h3 className="mb-3 mt-6 text-sm font-semibold" style={{ color: "var(--c-ink-2)" }}>Component breakdown</h3>
      <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
        {rs.components.map((c) => {
          const link = COMPONENT_LINK[c.key];
          const barTone = c.risk >= 60 ? "var(--c-danger)" : c.risk >= 30 ? "var(--c-warn)" : "var(--c-ok)";
          return (
            <Panel key={c.key}>
              <div className="mb-2 flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{c.label}</div>
                  <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>weight {Math.round(c.weight * 100)}%</div>
                </div>
                <div className="text-right">
                  <div className="text-xl font-bold" style={{ color: c.present ? barTone : "var(--c-ink-3)" }}>{c.present ? c.risk : "—"}</div>
                  <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>risk</div>
                </div>
              </div>
              {c.present ? (
                <div className="mb-3 h-1.5 w-full overflow-hidden rounded-full" style={{ background: "var(--c-surface-2)" }}>
                  <div className="h-full rounded-full" style={{ width: `${c.risk}%`, background: barTone }} />
                </div>
              ) : (
                <p className="mb-3 text-xs" style={{ color: "var(--c-ink-3)" }}>No data yet — excluded from the composite.</p>
              )}
              <div className="flex flex-col gap-1">
                {Object.entries(c.drivers ?? {}).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between text-xs" style={{ color: "var(--c-ink-2)" }}>
                    <span>{DRIVER_LABEL[k] ?? k}</span>
                    <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{v}{k === "coverage_pct" ? "%" : ""}</span>
                  </div>
                ))}
              </div>
              {link && (
                <Link href={link.href} className="mt-3 inline-block text-[11px] font-medium" style={{ color: "var(--c-primary)" }}>
                  {link.cta} →
                </Link>
              )}
            </Panel>
          );
        })}
      </div>
    </div>
  );
}
