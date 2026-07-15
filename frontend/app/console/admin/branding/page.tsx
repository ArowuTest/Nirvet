"use client";

// White-label branding (Ghana operator, SRS L-tier). Instance-level presentation config the login page and
// shell read from GET /branding (public). Padmin-only write via PUT /admin/branding. A live preview mirrors the
// backend validation (operator name ≤100, https/site-relative logo, #RRGGBB colour, valid support email) so an
// operator sees exactly what a customer's login screen will render before saving.

import { useEffect, useState } from "react";
import { apiGet, apiPut, ApiError } from "@/lib/api";
import { PageHeader, Panel, Button } from "@/components/ui";
import { RoleGate } from "@/components/role-gate";

type Branding = { operator_name: string; logo_url: string; primary_color: string; support_email: string; updated_at?: string };
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

const HEX = /^#[0-9a-fA-F]{6}$/;
function logoOk(s: string) { return s === "" || (s.startsWith("/") && !s.startsWith("//")) || /^https:\/\/.+/.test(s); }

export default function Page() {
  // White-label branding is platform-admin only (PUT /admin/branding is padmin). Gate the page so a non-admin
  // sees a denial rather than the Save-branding form (BUG-2).
  return (
    <RoleGate allow={["platform_admin"]} title="Branding">
      <BrandingPage />
    </RoleGate>
  );
}

function BrandingPage() {
  const [b, setB] = useState<Branding | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  useEffect(() => {
    // BUG-7: an unconfigured instance returns an empty primary_color, which failed the HEX check and left "Save
    // branding" disabled on load (the colour swatch already falls back to #2563eb, so the form looked valid).
    // Normalise a missing/invalid colour to the fallback in state so the control and validation agree.
    const norm = (r: Branding): Branding => ({ ...r, primary_color: HEX.test(r.primary_color) ? r.primary_color : "#2563eb" });
    apiGet<Branding>("/branding").then((r) => setB(norm(r))).catch(() => setB({ operator_name: "", logo_url: "", primary_color: "#2563eb", support_email: "" }));
  }, []);

  if (!b) return <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;

  const nameOk = b.operator_name.trim() !== "" && b.operator_name.length <= 100;
  const colorOk = HEX.test(b.primary_color);
  const emailOk = b.support_email === "" || (b.support_email.includes("@") && !/\s/.test(b.support_email));
  const valid = nameOk && colorOk && emailOk && logoOk(b.logo_url);

  async function save() {
    setMsg(null);
    try {
      const r = await apiPut<Branding>("/admin/branding", { operator_name: b!.operator_name, logo_url: b!.logo_url, primary_color: b!.primary_color, support_email: b!.support_email });
      setB(r);
      setMsg({ tone: "ok", text: "Branding saved — the login page and shell will reflect it." });
    } catch (e) { setMsg({ tone: "danger", text: `Save: ${e instanceof ApiError ? e.message : "failed"}` }); }
  }

  return (
    <div>
      <PageHeader title="White-label branding" sub="Operator name, logo, primary colour and support contact shown on the login page and shell" />

      {msg && <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: msg.tone === "ok" ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)", color: msg.tone === "ok" ? "#10b981" : "#ef4444", border: "1px solid var(--c-border)" }}>{msg.text}</div>}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Configuration">
          <div className="grid gap-3">
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Operator name
              <input value={b.operator_name} maxLength={100} onChange={(e) => setB({ ...b, operator_name: e.target.value })} placeholder="Acme Cyber Defence" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
              {!nameOk && <span className="mt-1 block text-[11px]" style={{ color: "#ef4444" }}>Required, ≤ 100 characters.</span>}
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Logo URL
              <input value={b.logo_url} onChange={(e) => setB({ ...b, logo_url: e.target.value })} placeholder="https://cdn… or /logo.png" className="mt-1 w-full rounded-lg px-3 py-2 font-mono text-sm" style={inputStyle} />
              <span className="mt-1 block text-[11px]" style={{ color: logoOk(b.logo_url) ? "var(--c-ink-3)" : "#ef4444" }}>Empty, an https URL, or a site-relative path. No http/data/javascript.</span>
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Primary colour
              <div className="mt-1 flex items-center gap-2">
                <input type="color" value={HEX.test(b.primary_color) ? b.primary_color : "#2563eb"} onChange={(e) => setB({ ...b, primary_color: e.target.value })} className="h-9 w-12 rounded" style={{ border: "1px solid var(--c-border)", background: "transparent" }} />
                <input value={b.primary_color} onChange={(e) => setB({ ...b, primary_color: e.target.value })} placeholder="#2563eb" className="w-32 rounded-lg px-3 py-2 font-mono text-sm" style={inputStyle} />
              </div>
              {!colorOk && <span className="mt-1 block text-[11px]" style={{ color: "#ef4444" }}>Must be a #RRGGBB hex value.</span>}
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Support email
              <input value={b.support_email} onChange={(e) => setB({ ...b, support_email: e.target.value })} placeholder="support@operator.example" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
              {!emailOk && <span className="mt-1 block text-[11px]" style={{ color: "#ef4444" }}>Not a valid address.</span>}
            </label>
            <div><Button size="sm" disabled={!valid} onClick={save}>Save branding</Button></div>
            {b.updated_at && <p className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Last updated {new Date(b.updated_at).toLocaleString()}</p>}
          </div>
        </Panel>

        <Panel title="Live preview" sub="How the login header renders">
          <div className="rounded-xl p-6" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
            <div className="flex items-center gap-3">
              {b.logo_url ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={b.logo_url} alt="logo" className="h-9 w-9 rounded object-contain" onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }} />
              ) : (
                <div className="flex h-9 w-9 items-center justify-center rounded font-bold text-white" style={{ background: colorOk ? b.primary_color : "#2563eb" }}>{(b.operator_name || "N").charAt(0).toUpperCase()}</div>
              )}
              <div className="text-lg font-bold" style={{ color: "var(--c-ink)" }}>{b.operator_name || "Your operator name"}</div>
            </div>
            <div className="mt-5 grid gap-2">
              <div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Sign in</div>
              <div className="h-9 rounded-lg" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }} />
              <div className="h-9 rounded-lg" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }} />
              <button className="mt-1 h-9 rounded-lg text-sm font-semibold text-white" style={{ background: colorOk ? b.primary_color : "#2563eb" }}>Continue</button>
              {b.support_email && <div className="mt-2 text-[11px]" style={{ color: "var(--c-ink-3)" }}>Need help? <span style={{ color: colorOk ? b.primary_color : "#2563eb" }}>{b.support_email}</span></div>}
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
