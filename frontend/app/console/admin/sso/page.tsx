"use client";

// Single sign-on (SRS §6.2 IAM-006/007) — the console surface for a tenant's OIDC and SAML identity providers.
// The backend routes (/admin/sso, /admin/sso/saml — create/list/delete, ssoAdmin-gated) shipped with the SSO work
// but had NO console consumer: across 250 agencies, an operator could not configure federated login without
// calling the API directly. This is that surface (84-route triage, pulled forward).
//
// default_role is deliberately limited to the two CUSTOMER roles the backend accepts. That is not cosmetic: it is
// Critical #2 (SSO default_role escalation) — a tenant admin who can manage SSO must not be able to register an IdP
// with default_role=platform_admin and mint a super-admin. The backend re-validates (complete.go ValidSSORole);
// the UI simply refuses to offer an invalid option so the operator is never surprised by a rejection.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiDelete, errorText } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";
import { RoleGate } from "@/components/role-gate";

// The ONLY roles a tenant SSO connection may JIT-provision (mirrors backend allowedSSORoles). Never add a
// provider/privileged role here — that is the escalation the backend guard exists to prevent.
const SSO_ROLES = ["customer_viewer", "customer_admin"];

type OIDCConn = { id: string; issuer: string; client_id: string; redirect_uri: string; default_role: string; email_domain: string; enabled: boolean; created_at: string };
type SAMLConn = { id: string; idp_entity_id: string; idp_sso_url: string; sp_entity_id: string; acs_url: string; email_attribute: string; default_role: string; email_domain: string; enabled: boolean; created_at: string };

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function Page() {
  return (
    <RoleGate allow={["platform_admin", "customer_admin"]} title="Single sign-on" hint="This area is limited to tenant and platform administrators.">
      <Sso />
    </RoleGate>
  );
}

function Sso() {
  const [tab, setTab] = useState<"oidc" | "saml">("oidc");
  const [oidc, setOidc] = useState<OIDCConn[] | null>(null);
  const [saml, setSaml] = useState<SAMLConn[] | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    apiGet<OIDCConn[]>("/admin/sso").then((r) => setOidc(r ?? [])).catch(() => setOidc([]));
    apiGet<SAMLConn[]>("/admin/sso/saml").then((r) => setSaml(r ?? [])).catch(() => setSaml([]));
  }, []);
  useEffect(load, [load]);

  const [oform, setOform] = useState({ issuer: "", client_id: "", client_secret: "", redirect_uri: "", default_role: "customer_viewer", email_domain: "" });
  const [sform, setSform] = useState({ idp_entity_id: "", idp_sso_url: "", idp_certificate: "", sp_entity_id: "", acs_url: "", email_attribute: "", default_role: "customer_viewer", email_domain: "" });

  async function createOidc() {
    setMsg(null);
    setBusy(true);
    try {
      await apiPost("/admin/sso", oform);
      setMsg({ tone: "ok", text: "OIDC connection created." });
      setOform({ issuer: "", client_id: "", client_secret: "", redirect_uri: "", default_role: "customer_viewer", email_domain: "" });
      load();
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "Configuring SSO requires a tenant or platform administrator role.", "Could not create the connection.") });
    } finally {
      setBusy(false);
    }
  }

  async function createSaml() {
    setMsg(null);
    setBusy(true);
    try {
      await apiPost("/admin/sso/saml", sform);
      setMsg({ tone: "ok", text: "SAML connection created." });
      setSform({ idp_entity_id: "", idp_sso_url: "", idp_certificate: "", sp_entity_id: "", acs_url: "", email_attribute: "", default_role: "customer_viewer", email_domain: "" });
      load();
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "Configuring SSO requires a tenant or platform administrator role.", "Could not create the connection.") });
    } finally {
      setBusy(false);
    }
  }

  async function remove(kind: "oidc" | "saml", id: string) {
    setMsg(null);
    try {
      await apiDelete(kind === "oidc" ? `/admin/sso/${id}` : `/admin/sso/saml/${id}`);
      load();
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "Removing an SSO connection requires an administrator role.", "Could not remove the connection.") });
    }
  }

  return (
    <div>
      <PageHeader title="Single sign-on" sub="Configure this tenant's OIDC and SAML identity providers for federated login" />
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <div className="mb-4 flex items-center gap-2">
        {(["oidc", "saml"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className="rounded-lg px-3 py-1.5 text-xs font-medium uppercase transition"
            style={tab === t ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" } : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}>
            {t === "oidc" ? "OIDC" : "SAML 2.0"}
          </button>
        ))}
      </div>

      {tab === "oidc" ? (
        <>
          <Panel title="OIDC connections" sub="OpenID Connect identity providers for this tenant">
            {oidc === null ? (
              <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
            ) : oidc.length === 0 ? (
              <EmptyState title="No OIDC providers configured" hint="Add one below to let this tenant's users sign in through their own identity provider." />
            ) : (
              <Table head={<><Th>Issuer</Th><Th>Client ID</Th><Th>Default role</Th><Th>Email domain</Th><Th>Status</Th><Th>{""}</Th></>}>
                {oidc.map((c) => (
                  <tr key={c.id}>
                    <Td className="font-mono text-[12px]">{c.issuer}</Td>
                    <Td className="font-mono text-[12px]">{c.client_id}</Td>
                    <Td><StatusTag tone="info">{c.default_role.replace(/_/g, " ")}</StatusTag></Td>
                    <Td>{c.email_domain || "—"}</Td>
                    <Td><StatusTag tone={c.enabled ? "ok" : "neutral"}>{c.enabled ? "enabled" : "disabled"}</StatusTag></Td>
                    <Td><Button variant="ghost" size="sm" onClick={() => remove("oidc", c.id)}>Remove</Button></Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>
          <Panel title="Add an OIDC provider" style={{ marginTop: 12 }}>
            <div className="grid gap-2" style={{ gridTemplateColumns: "1fr 1fr" }}>
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Issuer (https://idp.example.com)" value={oform.issuer} onChange={(e) => setOform({ ...oform, issuer: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Client ID" value={oform.client_id} onChange={(e) => setOform({ ...oform, client_id: e.target.value })} />
              <input type="password" className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Client secret" value={oform.client_secret} onChange={(e) => setOform({ ...oform, client_secret: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Redirect URI" value={oform.redirect_uri} onChange={(e) => setOform({ ...oform, redirect_uri: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Email domain (e.g. agency.gov.gh)" value={oform.email_domain} onChange={(e) => setOform({ ...oform, email_domain: e.target.value })} />
              <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={oform.default_role} onChange={(e) => setOform({ ...oform, default_role: e.target.value })}>
                {SSO_ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
              </select>
            </div>
            <div className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
              New users are provisioned as the default role. Only customer roles are available — provider roles cannot be SSO-provisioned.
            </div>
            <div className="mt-3">
              <Button disabled={busy || !oform.issuer.trim() || !oform.client_id.trim()} onClick={createOidc}>{busy ? "Saving…" : "Create OIDC connection"}</Button>
            </div>
          </Panel>
        </>
      ) : (
        <>
          <Panel title="SAML connections" sub="SAML 2.0 identity providers for this tenant">
            {saml === null ? (
              <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
            ) : saml.length === 0 ? (
              <EmptyState title="No SAML providers configured" hint="Add one below to federate login with a SAML 2.0 identity provider." />
            ) : (
              <Table head={<><Th>IdP entity ID</Th><Th>SSO URL</Th><Th>Default role</Th><Th>Email domain</Th><Th>Status</Th><Th>{""}</Th></>}>
                {saml.map((c) => (
                  <tr key={c.id}>
                    <Td className="font-mono text-[12px]">{c.idp_entity_id}</Td>
                    <Td className="font-mono text-[12px] break-all">{c.idp_sso_url}</Td>
                    <Td><StatusTag tone="info">{c.default_role.replace(/_/g, " ")}</StatusTag></Td>
                    <Td>{c.email_domain || "—"}</Td>
                    <Td><StatusTag tone={c.enabled ? "ok" : "neutral"}>{c.enabled ? "enabled" : "disabled"}</StatusTag></Td>
                    <Td><Button variant="ghost" size="sm" onClick={() => remove("saml", c.id)}>Remove</Button></Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>
          <Panel title="Add a SAML provider" style={{ marginTop: 12 }}>
            <div className="grid gap-2" style={{ gridTemplateColumns: "1fr 1fr" }}>
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="IdP entity ID" value={sform.idp_entity_id} onChange={(e) => setSform({ ...sform, idp_entity_id: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="IdP SSO URL" value={sform.idp_sso_url} onChange={(e) => setSform({ ...sform, idp_sso_url: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="SP entity ID" value={sform.sp_entity_id} onChange={(e) => setSform({ ...sform, sp_entity_id: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="ACS URL" value={sform.acs_url} onChange={(e) => setSform({ ...sform, acs_url: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Email attribute (blank = NameID)" value={sform.email_attribute} onChange={(e) => setSform({ ...sform, email_attribute: e.target.value })} />
              <input className="rounded-lg px-3 py-2 text-sm" style={inputStyle} placeholder="Email domain" value={sform.email_domain} onChange={(e) => setSform({ ...sform, email_domain: e.target.value })} />
              <select className="rounded-lg px-3 py-2 text-sm" style={inputStyle} value={sform.default_role} onChange={(e) => setSform({ ...sform, default_role: e.target.value })}>
                {SSO_ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
              </select>
            </div>
            <textarea className="mt-2 w-full rounded-lg px-3 py-2 font-mono text-[11px]" style={inputStyle} rows={4} placeholder="IdP signing certificate (PEM)" value={sform.idp_certificate} onChange={(e) => setSform({ ...sform, idp_certificate: e.target.value })} />
            <div className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
              The IdP certificate verifies signed assertions. Only customer roles can be SSO-provisioned.
            </div>
            <div className="mt-3">
              <Button disabled={busy || !sform.idp_entity_id.trim() || !sform.idp_sso_url.trim()} onClick={createSaml}>{busy ? "Saving…" : "Create SAML connection"}</Button>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
