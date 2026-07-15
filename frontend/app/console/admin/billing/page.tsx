"use client";

// Platform-admin billing (SRS §6.17). The operator's commercial read model: the price book (packages + per-metric
// rate lines) and umbrella billing accounts with their contract value + payment status. Read-only here — pricing and
// account WRITES are padmin-gated elsewhere; this is the at-a-glance view. GET /admin/billing/packages and
// GET /admin/billing/accounts are padmin server-side → non-admins get 403, surfaced as an access notice.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, ApiError, errorText } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

// The metered dimensions a rate line can price (mirrors billing.Metric — the backend rejects any other value).
const METRICS = ["log_volume", "alert_count", "report_count", "playbook_actions", "connector_count", "asset_count", "api_usage", "storage", "ps_hours"] as const;
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

type Rate = { metric: string; included_qty: number; overage_minor: number };
type Package = { id: string; name: string; currency: string; rates: Rate[] | null };
type Account = {
  id: string;
  name: string;
  currency: string;
  contract_value_minor: number;
  payment_status: string;
  account_status: string;
};

const acctTone: Record<string, "ok" | "warn" | "danger" | "neutral"> = {
  active: "ok",
  onboarding: "warn",
  suspended: "danger",
  closed: "neutral",
};
const payTone: Record<string, "ok" | "warn" | "danger" | "neutral"> = {
  current: "ok",
  paid: "ok",
  overdue: "danger",
  pending: "warn",
};

// money formats integer minor-units (e.g. 150000 → "1,500.00") with the account/package currency code.
function money(minor: number, currency: string) {
  const major = (minor / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${currency} ${major}`;
}

export default function AdminBillingPage() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "forbidden">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // write-form state (padmin only — this whole page 403s to non-admins into the "forbidden" branch)
  const [showPkg, setShowPkg] = useState(false);
  const [pkg, setPkg] = useState({ name: "", currency: "USD" });
  const [rateFor, setRateFor] = useState<string | null>(null); // package id whose rate editor is open
  const [rate, setRate] = useState({ metric: "log_volume", included_qty: "0", overage_minor: "0" });
  const [showAcct, setShowAcct] = useState(false);
  const [acct, setAcct] = useState({ name: "", currency: "USD", contract_value: "0" });

  const load = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([
        apiGet<{ packages: Package[] | null }>("/admin/billing/packages"),
        apiGet<{ accounts: Account[] | null }>("/admin/billing/accounts"),
      ]);
      setPackages(p.packages ?? []);
      setAccounts(a.accounts ?? []);
      setState("ready");
    } catch (e) {
      setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "ready");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Run a write, surface success/403, then reload. money fields are entered in major units and sent as minor.
  async function act(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    setBusy(true);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: errorText(e, "This action requires the platform super-admin.", "Action failed.") });
    } finally {
      setBusy(false);
    }
  }
  const toMinor = (major: string) => Math.round((parseFloat(major) || 0) * 100);

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "forbidden")
    return (
      <div>
        <PageHeader title="Billing" />
        <EmptyState title="Platform-admin only" hint="The commercial read model is restricted to the platform super-admin." />
      </div>
    );

  return (
    <div>
      <PageHeader title="Billing" sub="Commercial packages and umbrella accounts" actions={<Button size="sm" variant="ghost" onClick={load}>Refresh</Button>} />

      {msg && <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: msg.tone === "ok" ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)", color: msg.tone === "ok" ? "#10b981" : "#ef4444", border: "1px solid var(--c-border)" }}>{msg.text}</div>}

      <Panel
        title="Packages"
        sub="The operator price book — packages and their per-metric rate lines"
        actions={<Button size="sm" onClick={() => { setShowPkg((v) => !v); setRateFor(null); }}>{showPkg ? "Cancel" : "New package"}</Button>}
      >
        {showPkg && (
          <div className="mb-4 flex flex-wrap items-end gap-2 rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
            <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Name
              <input value={pkg.name} onChange={(e) => setPkg({ ...pkg, name: e.target.value })} placeholder="Enterprise MDR" className="mt-1 block w-48 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
            </label>
            <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Currency
              <input value={pkg.currency} onChange={(e) => setPkg({ ...pkg, currency: e.target.value.toUpperCase().slice(0, 3) })} placeholder="USD" className="mt-1 block w-20 rounded-lg px-3 py-1.5 font-mono text-sm" style={inputStyle} />
            </label>
            <Button size="sm" disabled={busy || !pkg.name.trim() || pkg.currency.length !== 3}
              onClick={() => act(() => apiPost("/admin/billing/packages", { name: pkg.name.trim(), currency: pkg.currency }).then(() => { setPkg({ name: "", currency: "USD" }); setShowPkg(false); }), "Package created.")}>
              Create package
            </Button>
          </div>
        )}
        {packages.length === 0 ? (
          <EmptyState title="No packages defined" hint="Create a package above, then add per-metric rate lines to price it." />
        ) : (
          <div className="space-y-2">
            {packages.map((p) => (
              <div key={p.id} className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{p.name} <span className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{p.currency}</span></span>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => { setRateFor(rateFor === p.id ? null : p.id); setShowPkg(false); }}>{rateFor === p.id ? "Close" : "Set rate"}</Button>
                </div>
                {p.rates && p.rates.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {p.rates.map((r) => (
                      <span key={r.metric} className="rounded px-1.5 py-0.5 text-[11px]" style={{ background: "var(--c-surface)", color: "var(--c-ink-2)" }}>
                        {r.metric}: {r.included_qty} incl · {money(r.overage_minor, p.currency)}/over
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>No rate lines yet.</p>
                )}
                {rateFor === p.id && (
                  <div className="mt-3 flex flex-wrap items-end gap-2 border-t pt-3" style={{ borderColor: "var(--c-border)" }}>
                    <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Metric
                      <select value={rate.metric} onChange={(e) => setRate({ ...rate, metric: e.target.value })} className="mt-1 block w-40 rounded-lg px-2 py-1.5 text-sm" style={inputStyle}>
                        {METRICS.map((m) => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </label>
                    <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Included qty
                      <input type="number" min={0} value={rate.included_qty} onChange={(e) => setRate({ ...rate, included_qty: e.target.value })} className="mt-1 block w-28 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
                    </label>
                    <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Overage / unit ({p.currency})
                      <input type="number" min={0} step="0.01" value={rate.overage_minor} onChange={(e) => setRate({ ...rate, overage_minor: e.target.value })} className="mt-1 block w-32 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
                    </label>
                    <Button size="sm" disabled={busy}
                      onClick={() => act(() => apiPost(`/admin/billing/packages/${p.id}/rates`, { metric: rate.metric, included_qty: Math.max(0, parseInt(rate.included_qty, 10) || 0), overage_minor: toMinor(rate.overage_minor) }).then(() => setRateFor(null)), "Rate line set.")}>
                      Save rate
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="mt-6">
        <Panel
          title="Accounts"
          sub="Umbrella billing accounts covering one or more tenants"
          actions={<Button size="sm" onClick={() => setShowAcct((v) => !v)}>{showAcct ? "Cancel" : "New account"}</Button>}
        >
          {showAcct && (
            <div className="mb-4 flex flex-wrap items-end gap-2 rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
              <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Name
                <input value={acct.name} onChange={(e) => setAcct({ ...acct, name: e.target.value })} placeholder="Ministry of Defence" className="mt-1 block w-52 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
              </label>
              <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Currency
                <input value={acct.currency} onChange={(e) => setAcct({ ...acct, currency: e.target.value.toUpperCase().slice(0, 3) })} placeholder="USD" className="mt-1 block w-20 rounded-lg px-3 py-1.5 font-mono text-sm" style={inputStyle} />
              </label>
              <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Contract value
                <input type="number" min={0} step="0.01" value={acct.contract_value} onChange={(e) => setAcct({ ...acct, contract_value: e.target.value })} className="mt-1 block w-36 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
              </label>
              <Button size="sm" disabled={busy || !acct.name.trim() || acct.currency.length !== 3}
                onClick={() => act(() => apiPost("/admin/billing/accounts", { name: acct.name.trim(), currency: acct.currency, contract_value_minor: toMinor(acct.contract_value) }).then(() => { setAcct({ name: "", currency: "USD", contract_value: "0" }); setShowAcct(false); }), "Account created.")}>
                Create account
              </Button>
            </div>
          )}
          {accounts.length === 0 ? (
            <EmptyState title="No billing accounts" hint="Umbrella accounts are created for operators billing multiple tenants together." />
          ) : (
            <Table head={<><Th>Account</Th><Th>Currency</Th><Th>Contract value</Th><Th>Payment</Th><Th>Status</Th></>}>
              {accounts.map((a) => (
                <tr key={a.id} style={{ borderTop: "1px solid var(--c-border)" }}>
                  <Td className="font-medium">{a.name}</Td>
                  <Td>{a.currency}</Td>
                  <Td>{money(a.contract_value_minor, a.currency)}</Td>
                  <Td><StatusTag tone={payTone[a.payment_status] ?? "neutral"}>{a.payment_status}</StatusTag></Td>
                  <Td><StatusTag tone={acctTone[a.account_status] ?? "neutral"}>{a.account_status}</StatusTag></Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      </div>
    </div>
  );
}
