// Nirvet console design-system primitives — the shared component vocabulary extracted from the approved
// mockups (outputs/Nirvet UI Designs). Every console screen composes from these so the brand stays consistent
// and new screens (not in the 52 mockups) match by construction. Colors/spacing come ONLY from the globals.css
// tokens — never hard-code a hex here.

import type { ReactNode, CSSProperties } from "react";

// ---- Panel (bordered surface card with an optional header + actions) ----

export function Panel({
  title,
  sub,
  actions,
  children,
  style,
  bodyStyle,
}: {
  title?: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  style?: CSSProperties;
  bodyStyle?: CSSProperties;
}) {
  return (
    <section
      className="rounded-2xl"
      style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)", ...style }}
    >
      {(title || actions) && (
        <header
          className="flex items-center justify-between px-5 py-3.5"
          style={{ borderBottom: "1px solid var(--c-border)" }}
        >
          <div>
            {title && <div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{title}</div>}
            {sub && <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{sub}</div>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-5" style={bodyStyle}>{children}</div>
    </section>
  );
}

// ---- KPI strip ----

export function KpiStrip({ children }: { children: ReactNode }) {
  return <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" }}>{children}</div>;
}

export function Kpi({
  label,
  value,
  sub,
  trend,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  trend?: { dir: "up" | "down" | "flat"; text: string; good?: boolean };
  tone?: "default" | "danger" | "warn" | "ok";
}) {
  const valColor =
    tone === "danger" ? "var(--c-danger)" : tone === "warn" ? "var(--c-warn)" : tone === "ok" ? "var(--c-ok)" : "var(--c-ink)";
  return (
    <div className="rounded-2xl p-4" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
      <div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div>
      <div className="mt-1.5 text-3xl font-extrabold leading-none" style={{ color: valColor }}>{value}</div>
      <div className="mt-1.5 flex items-center gap-2">
        {sub && <span className="text-[11px]" style={{ color: "var(--c-ink-2)" }}>{sub}</span>}
        {trend && (
          <span
            className="text-[11px] font-medium"
            style={{ color: trend.good === false ? "var(--c-danger)" : trend.good ? "var(--c-ok)" : "var(--c-ink-3)" }}
          >
            {trend.dir === "up" ? "▲" : trend.dir === "down" ? "▼" : "→"} {trend.text}
          </span>
        )}
      </div>
    </div>
  );
}

// ---- Badges (severity + generic status) ----

const SEV: Record<string, { bg: string; fg: string }> = {
  critical: { bg: "rgba(239,68,68,0.14)", fg: "#fca5a5" },
  high: { bg: "rgba(245,158,11,0.14)", fg: "#fcd34d" },
  medium: { bg: "rgba(234,179,8,0.12)", fg: "#fde68a" },
  low: { bg: "rgba(14,165,233,0.12)", fg: "#7dd3fc" },
  informational: { bg: "rgba(100,116,139,0.14)", fg: "#cbd5e1" },
};

export function SevBadge({ severity }: { severity: string }) {
  const s = SEV[severity?.toLowerCase()] ?? SEV.informational;
  return (
    <span
      className="inline-block rounded px-2 py-0.5 text-[11px] font-semibold capitalize"
      style={{ background: s.bg, color: s.fg }}
    >
      {severity}
    </span>
  );
}

// StatusTag — generic pill; tone drives color. Use for incident stage, alert status, connector health, etc.
export function StatusTag({ children, tone = "neutral" }: { children: ReactNode; tone?: "ok" | "warn" | "danger" | "info" | "neutral" }) {
  const map: Record<string, { bg: string; fg: string }> = {
    ok: { bg: "rgba(16,185,129,0.12)", fg: "#6ee7b7" },
    warn: { bg: "rgba(245,158,11,0.12)", fg: "#fcd34d" },
    danger: { bg: "rgba(239,68,68,0.12)", fg: "#fca5a5" },
    info: { bg: "rgba(14,165,233,0.12)", fg: "#7dd3fc" },
    neutral: { bg: "rgba(100,116,139,0.14)", fg: "#cbd5e1" },
  };
  const s = map[tone];
  return (
    <span className="inline-block rounded px-2 py-0.5 text-[11px] font-medium capitalize" style={{ background: s.bg, color: s.fg }}>
      {children}
    </span>
  );
}

// Backend connector health enum → tone. (healthy | degraded | silent | unknown)
export function healthTone(health: string): "ok" | "warn" | "danger" | "neutral" {
  switch (health) {
    case "healthy":
      return "ok";
    case "degraded":
      return "warn";
    case "silent":
      return "danger";
    default:
      return "neutral";
  }
}

// Backend incident stage enum → tone. (new | triage | investigating | contained | closed)
export function stageTone(stage: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  switch (stage) {
    case "closed":
      return "ok";
    case "contained":
      return "info";
    case "investigating":
    case "triage":
      return "warn";
    case "new":
      return "danger";
    default:
      return "neutral";
  }
}

// ---- Table primitives ----

export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-2xl" style={{ border: "1px solid var(--c-border)" }}>
      <table className="w-full text-left text-sm">
        <thead>
          <tr style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}>{head}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Th({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <th className={`px-4 py-3 text-[11px] font-semibold uppercase tracking-wide ${className}`}>{children}</th>;
}

export function Td({ children, className = "", title, style }: { children?: ReactNode; className?: string; title?: string; style?: CSSProperties }) {
  return (
    <td className={`px-4 py-3 ${className}`} title={title} style={{ borderTop: "1px solid var(--c-border)", color: "var(--c-ink-2)", ...style }}>
      {children}
    </td>
  );
}

// ---- Page header + empty state ----

export function PageHeader({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: "var(--c-ink)" }}>{title}</h1>
        {sub && <p className="mt-1 text-sm" style={{ color: "var(--c-ink-3)" }}>{sub}</p>}
      </div>
      {actions}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-2xl px-6 py-12 text-center" style={{ border: "1px dashed var(--c-border-strong)" }}>
      <div className="text-sm font-medium" style={{ color: "var(--c-ink-2)" }}>{title}</div>
      {hint && <div className="mt-1 text-[12px]" style={{ color: "var(--c-ink-3)" }}>{hint}</div>}
    </div>
  );
}

// ---- Button ----

export function Button({
  children,
  onClick,
  variant = "primary",
  size = "md",
  type = "button",
  disabled,
  title,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  size?: "sm" | "md";
  type?: "button" | "submit";
  disabled?: boolean;
  title?: string;
  className?: string;
}) {
  const pad = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm";
  const styles: Record<string, CSSProperties> = {
    primary: { background: "var(--c-primary)", color: "#04121f", fontWeight: 600 },
    ghost: { border: "1px solid var(--c-border-strong)", color: "var(--c-ink-2)" },
    danger: { background: "rgba(239,68,68,0.14)", color: "#fca5a5", border: "1px solid rgba(239,68,68,0.3)" },
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded-lg transition disabled:opacity-50 ${pad} ${className}`}
      style={styles[variant]}
    >
      {children}
    </button>
  );
}
