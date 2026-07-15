"use client";

// Customer incident detail (§6.3 / CASE-004) — GET /customer/incidents/{id}. Shows only the customer-safe
// projection: SLA adherence, the customer-visible timeline, and the closure summary the operator chose to
// disclose. Provider-internal notes/detection internals are absent by construction (readmodel projection).

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, SevBadge, StatusTag, stageTone, EmptyState } from "@/components/ui";

type TL = { at: string; kind: string; note: string };
type Incident = {
  incident_id: string; title: string; severity: string; category: string; status: string;
  created_at: string; closed_at?: string;
  acknowledged_at?: string; ack_due_at?: string; resolve_due_at?: string; ack_breached: boolean; resolve_breached: boolean;
  disposition?: string; impact?: string; actions_taken?: string; lessons_learned?: string; root_cause?: string; customer_ack: boolean;
  timeline: TL[] | null;
};

const fmt = (d?: string) => (d ? new Date(d).toLocaleString() : "—");

export default function PortalIncidentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [inc, setInc] = useState<Incident | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "notfound">("loading");

  useEffect(() => {
    apiGet<{ incident: Incident }>(`/customer/incidents/${id}`).then((r) => { setInc(r.incident); setState("ready"); }).catch(() => setState("notfound"));
  }, [id]);

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "notfound" || !inc)
    return <div><PageHeader title="Incident" /><EmptyState title="Incident not found" hint="It may not be visible to your organisation." /></div>;

  const summary = [
    ["Impact", inc.impact], ["Actions taken", inc.actions_taken], ["Root cause", inc.root_cause], ["Lessons learned", inc.lessons_learned],
  ].filter(([, v]) => v);
  // Evidence shared with the customer = the evidence-kind entries of the customer-visible timeline (the
  // projection already excludes internal ones). The full signed pack is a provider export by design, so we
  // state honestly where it lives rather than offering a download the customer cannot have.
  const evidence = (inc.timeline ?? []).filter((e) => e.kind === "evidence");

  return (
    <div>
      <Link href="/portal/incidents" className="text-[12px]" style={{ color: "var(--c-primary)" }}>← Incidents</Link>
      <div className="mt-2">
        <PageHeader
          title={inc.title}
          sub={`Opened ${fmt(inc.created_at)}${inc.category ? ` · ${inc.category}` : ""}`}
          actions={<div className="flex items-center gap-2"><SevBadge severity={inc.severity} /><StatusTag tone={stageTone(inc.status)}>{inc.status.replace(/_/g, " ")}</StatusTag></div>}
        />
      </div>

      <div className="grid gap-6" style={{ gridTemplateColumns: "1.6fr 1fr" }}>
        <div className="space-y-6">
          <Panel title="Updates" sub="Customer-visible activity on this case">
            {(inc.timeline ?? []).length === 0 ? <EmptyState title="No updates yet" hint="Your SOC will post customer-visible updates here." /> : (
              <ol className="space-y-4">
                {(inc.timeline ?? []).map((e, i) => (
                  <li key={i} className="relative pl-5">
                    <span className="absolute left-0 top-1.5 h-2 w-2 rounded-full" style={{ background: "var(--c-primary)" }} />
                    <div className="flex items-center gap-2"><StatusTag tone="info">{e.kind}</StatusTag><span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fmt(e.at)}</span></div>
                    {e.note && <p className="mt-1 text-sm" style={{ color: "var(--c-ink-2)" }}>{e.note}</p>}
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          <Panel title="Evidence & chain of custody" sub="Artifacts your SOC has shared for this case">
            {evidence.length === 0 ? (
              <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>
                No evidence artifacts have been shared with you for this case yet. Your SOC maintains a signed
                evidence pack and an unbroken chain of custody for every case — ask your service contact if you
                need it for an audit, claim or regulator submission.
              </p>
            ) : (
              <ul className="space-y-2">
                {evidence.map((e, i) => (
                  <li key={i} className="rounded-lg p-2.5" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                    <div className="flex items-center gap-2">
                      <StatusTag tone="ok">evidence</StatusTag>
                      <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fmt(e.at)}</span>
                    </div>
                    {e.note && <p className="mt-1 text-sm" style={{ color: "var(--c-ink-2)" }}>{e.note}</p>}
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {summary.length > 0 && (
            <Panel title="Resolution summary">
              <div className="space-y-3">
                {inc.disposition && <div className="text-sm"><span style={{ color: "var(--c-ink-3)" }}>Disposition: </span>{inc.disposition.replace(/_/g, " ")}</div>}
                {summary.map(([label, v]) => (
                  <div key={label as string}><div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div><p className="mt-0.5 text-sm" style={{ color: "var(--c-ink-2)" }}>{v}</p></div>
                ))}
              </div>
            </Panel>
          )}
        </div>

        <Panel title="Service level">
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between"><span style={{ color: "var(--c-ink-3)" }}>Acknowledged</span><span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.acknowledged_at)}</span></div>
            <div className="flex items-center justify-between"><span style={{ color: "var(--c-ink-3)" }}>Ack target</span>{inc.ack_breached ? <StatusTag tone="danger">Missed</StatusTag> : <span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.ack_due_at)}</span>}</div>
            <div className="flex items-center justify-between"><span style={{ color: "var(--c-ink-3)" }}>Resolve target</span>{inc.resolve_breached ? <StatusTag tone="danger">Missed</StatusTag> : <span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.resolve_due_at)}</span>}</div>
            {inc.closed_at && <div className="flex items-center justify-between"><span style={{ color: "var(--c-ink-3)" }}>Closed</span><span style={{ color: "var(--c-ink-2)" }}>{fmt(inc.closed_at)}</span></div>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
