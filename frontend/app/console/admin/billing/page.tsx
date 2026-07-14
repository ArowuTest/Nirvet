"use client";

// Platform-admin billing (SRS §6.17). The operator's commercial read model: the price book (packages + per-metric
// rate lines) and umbrella billing accounts with their contract value + payment status. Read-only here — pricing and
// account WRITES are padmin-gated elsewhere; this is the at-a-glance view. GET /admin/billing/packages and
// GET /admin/billing/accounts are padmin server-side → non-admins get 403, surfaced as an access notice.

import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

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

      <Panel title="Packages" sub="The operator price book — packages and their per-metric rate lines" bodyStyle={{ padding: packages.length ? 0 : undefined }}>
        {packages.length === 0 ? (
          <EmptyState title="No packages defined" hint="Commercial packages are created from the pricing admin flow." />
        ) : (
          <Table head={<><Th>Package</Th><Th>Currency</Th><Th>Rate lines</Th></>}>
            {packages.map((p) => (
              <tr key={p.id} style={{ borderTop: "1px solid var(--c-border)" }}>
                <Td className="font-medium">{p.name}</Td>
                <Td>{p.currency}</Td>
                <Td>
                  {p.rates && p.rates.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {p.rates.map((r) => (
                        <span key={r.metric} className="rounded px-1.5 py-0.5 text-[11px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-2)" }} title={`${r.included_qty} included · ${money(r.overage_minor, p.currency)}/unit over`}>
                          {r.metric}: {r.included_qty} incl · {money(r.overage_minor, p.currency)}/over
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span style={{ color: "var(--c-ink-3)" }}>no rates set</span>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      <div className="mt-6">
        <Panel title="Accounts" sub="Umbrella billing accounts covering one or more tenants" bodyStyle={{ padding: accounts.length ? 0 : undefined }}>
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
