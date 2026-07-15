"use client";

// Policies — the unified admin home for configuration governed by the no-hardcoding rule. Every threshold and
// policy in Nirvet is an admin-config DB record, but the surfaces were scattered (Flags / Risk / AI) with no
// place that answers "what governs this tenant?". This hub reads the REAL per-tenant policy records that already
// exist — authority-to-act, SLA targets, correlation, session, disclosure — for a selected tenant, and links to
// the instance-wide policy surfaces. Nothing here is synthesised: a family with no record shows its honest
// fail-safe default state rather than an invented value.
//
// All of these routes are padmin/ssoAdmin server-side (platform_admin in the console), so the page is RoleGated
// — a non-admin sees a denial, not a config surface they'd 403 on.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";
import { RoleGate } from "@/components/role-gate";

type Tenant = { id: string; name: string; status: string };
type Authority = { action_type: string; mode: string; approver_role: string; business_hours_only: boolean; active: boolean };
type SLA = { severity: string; ack_seconds: number; resolve_seconds: number };
type Correlation = { window_seconds: number; promote_threshold: number; min_alerts_for_promotion: number };
type Session = { access_ttl_seconds: number; ip_allowlist: string[] | null; geo_anomaly_logging: boolean };
type Disclosure = { customer_visible_stages?: string[] | null; disclose_closure_narrative?: boolean };

// Instance-wide policy surfaces that already have their own screens — this hub points at them rather than
// duplicating them.
const INSTANCE: { label: string; href: string; governs: string }[] = [
  { label: "Risk-score model", href: "/console/admin/risk", governs: "Component weights + bands for the composite posture score" },
  { label: "Feature flags", href: "/console/admin/flags", governs: "Instance capability toggles, with rollback" },
  { label: "AI configuration", href: "/console/admin/ai", governs: "LLM provider, endpoint allow-list and residency" },
  { label: "Branding", href: "/console/admin/branding", governs: "Operator identity on the login page and shell" },
];

// secs renders a duration in the unit an operator actually thinks in.
function secs(n: number): string {
  if (!n) return "—";
  if (n % 3600 === 0) return `${n / 3600}h`;
  if (n % 60 === 0) return `${n / 60}m`;
  return `${n}s`;
}

export default function Page() {
  return (
    <RoleGate allow={["platform_admin"]} title="Policies">
      <PoliciesHub />
    </RoleGate>
  );
}

function PoliciesHub() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tid, setTid] = useState("");
  const [authority, setAuthority] = useState<Authority[] | null>(null);
  const [sla, setSla] = useState<SLA[] | null>(null);
  const [corr, setCorr] = useState<Correlation | null>(null);
  const [sess, setSess] = useState<Session | null>(null);
  const [disc, setDisc] = useState<Disclosure | null>(null);
  const [loading, setLoading] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    apiGet<{ tenants: Tenant[] | null }>("/admin/tenants")
      .then((r) => {
        const list = r.tenants ?? [];
        setTenants(list);
        if (list[0]) setTid(list[0].id);
      })
      .catch((e) => setNote(e instanceof ApiError && e.status === 403 ? "Platform-admin only." : "Could not load tenants."));
  }, []);

  const load = useCallback(async (t: string) => {
    if (!t) return;
    setLoading(true);
    setNote(null);
    // Each family is read independently: one missing/erroring record must not blank the whole page — it shows
    // its own honest "not set" state instead.
    const [a, s, c, se, d] = await Promise.allSettled([
      apiGet<{ policies: Authority[] | null }>(`/admin/tenants/${t}/authority-policies`),
      apiGet<{ policies: SLA[] | null }>(`/admin/tenants/${t}/sla-policies`),
      apiGet<Correlation>(`/admin/tenants/${t}/correlation-policy`),
      apiGet<Session>(`/admin/tenants/${t}/session-policy`),
      apiGet<Disclosure>(`/admin/tenants/${t}/disclosure-policy`),
    ]);
    setAuthority(a.status === "fulfilled" ? a.value.policies ?? [] : null);
    setSla(s.status === "fulfilled" ? s.value.policies ?? [] : null);
    setCorr(c.status === "fulfilled" ? c.value : null);
    setSess(se.status === "fulfilled" ? se.value : null);
    setDisc(d.status === "fulfilled" ? d.value : null);
    setLoading(false);
  }, []);

  useEffect(() => {
    if (tid) load(tid);
  }, [tid, load]);

  const unset = (what: string) => <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No {what} record for this tenant — the fail-safe default applies until one is set.</p>;

  return (
    <div>
      <PageHeader
        title="Policies"
        sub="Every threshold is an admin-config record — this is what governs each tenant"
        actions={
          <div className="flex items-center gap-2">
            <select
              value={tid}
              onChange={(e) => setTid(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm"
              style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
            >
              {tenants.length === 0 && <option value="">No tenants</option>}
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <Button size="sm" variant="ghost" disabled={!tid || loading} onClick={() => load(tid)}>Refresh</Button>
          </div>
        }
      />
      {note && <p className="mb-3 text-[13px]" style={{ color: "var(--c-danger)" }}>{note}</p>}

      {tenants.length === 0 ? (
        <Panel><EmptyState title="No tenants" hint="Create a tenant to configure its policies." /></Panel>
      ) : loading ? (
        <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading policies…</div>
      ) : (
        <div className="space-y-6">
          <Panel title="Authority to act" sub="Which response actions may run, and who must approve (SOAR reads this before every action)">
            {authority === null ? unset("authority-policy") : authority.length === 0 ? unset("authority-policy") : (
              <Table head={<><Th>Action</Th><Th>Mode</Th><Th>Approver</Th><Th>Hours</Th><Th>State</Th></>}>
                {authority.map((p) => (
                  <tr key={p.action_type} style={{ borderTop: "1px solid var(--c-border)" }}>
                    <Td className="font-mono text-xs">{p.action_type}</Td>
                    <Td><StatusTag tone={p.mode === "automatic" ? "danger" : p.mode === "approval" ? "warn" : "neutral"}>{p.mode}</StatusTag></Td>
                    <Td className="text-xs">{p.approver_role || "—"}</Td>
                    <Td className="text-xs">{p.business_hours_only ? "business hours" : "any time"}</Td>
                    <Td><StatusTag tone={p.active ? "ok" : "neutral"}>{p.active ? "active" : "inactive"}</StatusTag></Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          <div className="grid gap-6" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <Panel title="SLA targets" sub="Ack/resolve deadlines stamped on every incident at creation">
              {sla === null ? unset("SLA-policy") : sla.length === 0 ? unset("SLA-policy") : (
                <Table head={<><Th>Severity</Th><Th>Ack</Th><Th>Resolve</Th></>}>
                  {sla.map((p) => (
                    <tr key={p.severity} style={{ borderTop: "1px solid var(--c-border)" }}>
                      <Td><StatusTag tone={p.severity === "critical" ? "danger" : p.severity === "high" ? "warn" : "neutral"}>{p.severity}</StatusTag></Td>
                      <Td className="text-xs">{secs(p.ack_seconds)}</Td>
                      <Td className="text-xs">{secs(p.resolve_seconds)}</Td>
                    </tr>
                  ))}
                </Table>
              )}
            </Panel>

            <Panel title="Correlation" sub="How alerts group into an incident">
              {corr === null ? unset("correlation-policy") : (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Window</span><span style={{ color: "var(--c-ink-2)" }}>{secs(corr.window_seconds)}</span></div>
                  <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Promote threshold</span><span style={{ color: "var(--c-ink-2)" }}>{corr.promote_threshold}</span></div>
                  <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Min alerts to promote</span><span style={{ color: "var(--c-ink-2)" }}>{corr.min_alerts_for_promotion}</span></div>
                </div>
              )}
            </Panel>

            <Panel title="Session" sub="Token lifetime and access constraints">
              {sess === null ? unset("session-policy") : (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Access TTL</span><span style={{ color: "var(--c-ink-2)" }}>{secs(sess.access_ttl_seconds)}</span></div>
                  <div className="flex justify-between"><span style={{ color: "var(--c-ink-3)" }}>Geo-anomaly logging</span><StatusTag tone={sess.geo_anomaly_logging ? "ok" : "neutral"}>{sess.geo_anomaly_logging ? "on" : "off"}</StatusTag></div>
                  <div>
                    <span style={{ color: "var(--c-ink-3)" }}>IP allow-list</span>
                    {(sess.ip_allowlist ?? []).length === 0 ? (
                      <p className="mt-1 text-[12px]" style={{ color: "var(--c-ink-3)" }}>Unrestricted — no allow-list set.</p>
                    ) : (
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {(sess.ip_allowlist ?? []).map((ip) => <span key={ip} className="rounded px-1.5 py-0.5 font-mono text-[11px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{ip}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </Panel>

            <Panel title="Disclosure" sub="What this tenant's customer users may see (read-model row-gate)">
              {disc === null ? unset("disclosure-policy") : (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span style={{ color: "var(--c-ink-3)" }}>Closure narrative</span>
                    <StatusTag tone={disc.disclose_closure_narrative ? "warn" : "ok"}>{disc.disclose_closure_narrative ? "disclosed" : "withheld"}</StatusTag>
                  </div>
                  <div>
                    <span style={{ color: "var(--c-ink-3)" }}>Customer-visible stages</span>
                    {(disc.customer_visible_stages ?? []).length === 0 ? (
                      <p className="mt-1 text-[12px]" style={{ color: "var(--c-ink-3)" }}>Fail-closed default applies.</p>
                    ) : (
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {(disc.customer_visible_stages ?? []).map((s) => <span key={s} className="rounded px-1.5 py-0.5 text-[11px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }}>{s.replace(/_/g, " ")}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </Panel>
          </div>

          <Panel title="Instance policies" sub="Configuration that applies across the whole instance, not per tenant">
            <ul className="space-y-2">
              {INSTANCE.map((s) => (
                <li key={s.href} className="flex items-center justify-between gap-3 rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                  <div className="min-w-0">
                    <div className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{s.label}</div>
                    <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{s.governs}</div>
                  </div>
                  <Link href={s.href}><Button size="sm" variant="ghost">Open</Button></Link>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      )}
    </div>
  );
}
