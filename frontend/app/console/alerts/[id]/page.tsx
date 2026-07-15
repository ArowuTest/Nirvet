"use client";

// Alert detail — the single-alert triage view. Wired to GET /alerts/{id} plus the disposition (DET-007
// feedback), self-assign and promote actions. Disposition vocabulary is the backend's exact set
// (true_positive|false_positive|benign|duplicate). Promote is senior-gated server-side; we surface the 403.

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiGet, apiPost, errorText } from "@/lib/api";
import { PageHeader, Panel, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type Alert = {
  id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  confidence: number;
  actor_ref: string;
  target_ref: string;
  mitre?: string[];
  dedupe_key: string;
  incident_id?: string;
  created_at: string;
};

const DISPOSITIONS = [
  { key: "true_positive", label: "True positive" },
  { key: "false_positive", label: "False positive" },
  { key: "benign", label: "Benign" },
  { key: "duplicate", label: "Duplicate" },
];

const statusTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  new: "danger",
  assigned: "warn",
  promoted: "info",
  closed: "neutral",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div>
      <div className="mt-1 text-sm" style={{ color: "var(--c-ink)" }}>{children}</div>
    </div>
  );
}

export default function AlertDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [related, setRelated] = useState<{ id: string; title: string; severity: string; status: string }[]>([]);
  const [ti, setTi] = useState<{ source: string; value: string; score: number; tlp: string; tags?: string[]; labels?: string[] }[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "notfound">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const a = await apiGet<Alert>(`/alerts/${id}`);
      setAlert(a);
      setState("ready");
      const ref = a.target_ref || a.actor_ref;
      if (ref) {
        const r = await apiGet<{ alerts: { id: string; title: string; severity: string; status: string }[] | null }>(`/alerts?ref=${encodeURIComponent(ref)}`).catch(() => ({ alerts: [] }));
        setRelated((r.alerts ?? []).filter((x) => x.id !== id).slice(0, 8));
      }
      const refs = [a.actor_ref, a.target_ref].filter(Boolean);
      if (refs.length > 0) {
        const e = await apiGet<{ matches: { source: string; value: string; score: number; tlp: string; tags?: string[]; labels?: string[] }[] | null }>(`/threat-intel/enrich?refs=${encodeURIComponent(refs.join(","))}`).catch(() => ({ matches: [] }));
        setTi(e.matches ?? []);
      }
    } catch {
      setState("notfound");
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    setBusy(true);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      await load();
    } catch (e) {
      const m = e instanceof Error ? e.message : "Action failed";
      setMsg({ tone: "danger", text: errorText(e, "That action requires a senior analyst role.") });
    } finally {
      setBusy(false);
    }
  }

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "notfound" || !alert)
    return (
      <div>
        <PageHeader title="Alert" />
        <EmptyState title="Alert not found" hint="It may have been closed, or you don't have access." />
      </div>
    );

  const open = alert.status === "new" || alert.status === "assigned";

  return (
    <div className="mx-auto max-w-4xl">
      <Link href="/console/alerts" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Alert queue</Link>
      <div className="mt-2">
        <PageHeader
          title={alert.title}
          sub={`Detected ${new Date(alert.created_at).toLocaleString()} · via ${alert.source}`}
          actions={<div className="flex items-center gap-2"><SevBadge severity={alert.severity} /><StatusTag tone={statusTone[alert.status] ?? "neutral"}>{alert.status}</StatusTag></div>}
        />
      </div>

      {msg && (
        <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>
      )}

      <div className="grid gap-6" style={{ gridTemplateColumns: "1.5fr 1fr" }}>
        <Panel title="Detection detail">
          <div className="grid grid-cols-2 gap-5">
            <Field label="Actor"><span className="font-mono text-xs">{alert.actor_ref || "—"}</span></Field>
            <Field label="Target"><span className="font-mono text-xs">{alert.target_ref || "—"}</span></Field>
            <Field label="Confidence">{alert.confidence}%</Field>
            <Field label="Source">{alert.source}</Field>
            <Field label="MITRE ATT&CK">
              {alert.mitre && alert.mitre.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {alert.mitre.map((t) => (
                    <span key={t} className="rounded px-1.5 py-0.5 font-mono text-[11px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{t}</span>
                  ))}
                </div>
              ) : "—"}
            </Field>
            <Field label="Dedupe key"><span className="font-mono text-[11px] break-all" style={{ color: "var(--c-ink-3)" }}>{alert.dedupe_key}</span></Field>
          </div>
          {alert.incident_id && (
            <div className="mt-5 rounded-lg p-3 text-sm" style={{ background: "rgba(14,165,233,0.08)", border: "1px solid var(--c-border)" }}>
              Promoted to incident{" "}
              <Link href={`/console/incidents/${alert.incident_id}`} className="font-medium hover:underline" style={{ color: "var(--c-primary)" }}>
                view case →
              </Link>
            </div>
          )}
        </Panel>

        <Panel title="Triage">
          {!open ? (
            <p className="text-sm" style={{ color: "var(--c-ink-3)" }}>
              This alert is {alert.status}. No further triage actions are available.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Button variant="ghost" size="sm" disabled={busy} onClick={() => act(() => apiPost(`/alerts/${id}/assign`), "Assigned to you.")}>
                  Assign to me
                </Button>
                <Button variant="primary" size="sm" disabled={busy} onClick={() => act(() => apiPost(`/alerts/${id}/promote`).then(() => router.push("/console/incidents")), "Promoted to an incident.")}>
                  Promote to incident
                </Button>
              </div>

              <div>
                <div className="mb-2 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Close with a verdict</div>
                <div className="grid grid-cols-2 gap-2">
                  {DISPOSITIONS.map((d) => (
                    <Button
                      key={d.key}
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onClick={() => act(() => apiPost(`/alerts/${id}/disposition`, { disposition: d.key }), `Closed — ${d.label.toLowerCase()}.`)}
                    >
                      {d.label}
                    </Button>
                  ))}
                </div>
                <p className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                  A verdict closes the alert and tunes the firing detection rule (DET-007).
                </p>
              </div>
            </div>
          )}
        </Panel>

        {ti.length > 0 && (
          <Panel title="Threat intelligence" sub="Watchlist / STIX matches on this alert's entities">
            <ul className="space-y-2">
              {ti.map((m, idx) => (
                <li key={`${m.value}-${idx}`} className="rounded-lg p-2.5" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                  <div className="flex items-center gap-2">
                    <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase" style={{ background: "rgba(239,68,68,0.14)", color: "#fca5a5" }}>{m.source}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px]" style={{ color: "var(--c-ink)" }} title={m.value}>{m.value}</span>
                    <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>score {m.score}</span>
                  </div>
                  {((m.labels && m.labels.length > 0) || (m.tags && m.tags.length > 0) || m.tlp) && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {m.tlp && <span className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ background: "var(--c-surface)", color: "var(--c-ink-2)" }}>TLP:{m.tlp}</span>}
                      {(m.labels ?? []).map((l) => (
                        <span key={l} className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "rgba(245,158,11,0.12)", color: "#fcd34d" }}>{l}</span>
                      ))}
                      {(m.tags ?? []).map((t) => (
                        <span key={t} className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "var(--c-surface)", color: "var(--c-ink-3)" }}>{t}</span>
                      ))}
                    </div>
                  )}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>Matched against your watchlist and imported STIX indicators (§6.10).</p>
          </Panel>
        )}

        {related.length > 0 && (
          <Panel title="Related alerts" sub="Other alerts on the same entity">
            <ul className="space-y-2">
              {related.map((a) => (
                <li key={a.id} className="flex items-center gap-3">
                  <SevBadge severity={a.severity} />
                  <Link href={`/console/alerts/${a.id}`} className="min-w-0 flex-1 truncate text-sm hover:underline" style={{ color: "var(--c-ink)" }}>{a.title}</Link>
                  <StatusTag tone={a.status === "new" ? "info" : "neutral"}>{a.status}</StatusTag>
                </li>
              ))}
            </ul>
          </Panel>
        )}
      </div>
    </div>
  );
}
