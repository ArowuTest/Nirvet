"use client";

// Protected targets — the D5 crown-jewel deny-lists the SOAR blast-radius guards consult before a destructive
// containment step. A designated host or identity is never auto-isolated/disabled: the run is WITHHELD and
// escalated to a human instead.
//
// This screen exists because the guards, the tables and the RLS have shipped since 0066/0098 — but nothing could
// ever write to them. The lists were empty in every deployment, and an empty list ALLOWS (the host guard returns
// allow on zero patterns), so the net silently caught nothing while every review read it as present. The honest
// empty state below is the point of the screen as much as the form is.
//
// Authority mirrors the backend gates, by DIRECTION of the change: any internal responder may read (it explains
// why a containment was withheld), a manager may add (tightens), and only a platform admin may remove (weakens —
// it makes a crown jewel auto-isolatable again).

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiDelete, errorText, getMe } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";
import { RoleGate } from "@/components/role-gate";

const PROVIDER = ["platform_admin", "soc_manager", "analyst_t1", "analyst_t2", "analyst_t3", "detection_engineer"];
const CAN_ADD = ["platform_admin", "soc_manager"];
const CAN_REMOVE = ["platform_admin"];

type Kind = "host" | "identity";
type Target = { id: string; kind: Kind; value: string; note: string; global: boolean; created_at: string };

// The two lists differ in how the guard matches them, and getting that wrong is silent — a partial UPN protects
// nothing, a short host fragment protects almost everything. The copy says so at the point of entry, not in a doc.
const KINDS: { kind: Kind; label: string; blurb: string; placeholder: string; matching: string }[] = [
  {
    kind: "host",
    label: "Protected hosts",
    blurb: "Hosts that must never be auto-isolated — a domain controller, the collector host, a life-critical server.",
    placeholder: "dc01",
    matching: "Matches as a case-insensitive substring: “dc01” also protects dc01.corp.gov.gh.",
  },
  {
    kind: "identity",
    label: "Protected identities",
    blurb: "Accounts that must never be auto-disabled — break-glass accounts, the last privileged admin.",
    placeholder: "breakglass@corp.gov.gh",
    matching: "Matches exactly: enter the full UPN or object id, or it will protect nothing.",
  },
];

export default function Page() {
  return (
    <RoleGate
      allow={PROVIDER}
      title="Protected targets"
      hint="This area is limited to the internal SOC team."
    >
      <ProtectedTargets />
    </RoleGate>
  );
}

function ProtectedTargets() {
  const [role, setRole] = useState<string>("");
  useEffect(() => {
    getMe()
      .then((u) => setRole(u.role ?? ""))
      .catch(() => setRole(""));
  }, []);
  return (
    <div>
      <PageHeader
        title="Protected targets"
        sub="Crown jewels the automated response must refuse to touch"
      />
      {KINDS.map((k) => (
        <KindPanel key={k.kind} meta={k} role={role} />
      ))}
    </div>
  );
}

function KindPanel({ meta, role }: { meta: (typeof KINDS)[number]; role: string }) {
  const [rows, setRows] = useState<Target[] | null>(null);
  const [err, setErr] = useState("");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const canAdd = CAN_ADD.includes(role);
  const canRemove = CAN_REMOVE.includes(role);

  const load = useCallback(() => {
    apiGet<Target[]>(`/soar/protected-targets/${meta.kind}`)
      .then((r) => setRows(r ?? []))
      .catch((e) => {
        setRows([]);
        setErr(errorText(e, "You do not have access to the protected-target list.", "Could not load protected targets."));
      });
  }, [meta.kind]);

  useEffect(load, [load]);

  async function add() {
    setErr("");
    setBusy(true);
    try {
      await apiPost(`/soar/protected-targets/${meta.kind}`, { value, note });
      setValue("");
      setNote("");
      load();
    } catch (e) {
      // The server's message carries the real reason — including the wildcard/exact-match explanations, which are
      // the whole point of the validation. Never overwrite it with a guess.
      setErr(errorText(e, "Adding a protected target requires the SOC manager role.", "Could not add the protected target."));
    } finally {
      setBusy(false);
    }
  }

  async function remove(t: Target) {
    setErr("");
    try {
      await apiDelete(`/soar/protected-targets/${meta.kind}/${t.id}`);
      load();
    } catch (e) {
      setErr(errorText(e, "Removing a protection requires the platform administrator role.", "Could not remove the protected target."));
    }
  }

  return (
    <Panel title={meta.label} sub={meta.blurb}>
      {err && <p className="mb-3 text-[13px]" style={{ color: "var(--c-danger)" }}>{err}</p>}

      {rows === null ? (
        <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
      ) : rows.length === 0 ? (
        // Honest, and deliberately blunt: an empty deny-list is not a neutral state, it is zero protection. Saying
        // "no protected hosts" would read as reassurance. This is the exact misreading that let the gap survive.
        <EmptyState
          title={`No ${meta.kind === "host" ? "hosts" : "identities"} are protected`}
          hint={`Nothing is exempt from automated response. Every ${meta.kind === "host" ? "host can be auto-isolated" : "account can be auto-disabled"} if a playbook and its authority allow it. ${meta.matching}`}
        />
      ) : (
        <Table
          head={
            <>
              <Th>{meta.kind === "host" ? "Pattern" : "Identity"}</Th>
              <Th>Reason</Th>
              <Th>Scope</Th>
              {canRemove && <Th>{""}</Th>}
            </>
          }
        >
          {rows.map((t) => (
            <tr key={t.id}>
              <Td><span className="font-mono text-[12px]">{t.value}</span></Td>
              <Td>{t.note || "—"}</Td>
              <Td>
                {/* Global rows are instance-wide and seeded by migration; RLS makes them unwritable here, so no
                    remove control is offered for them — an absent button is honest, a 403 is not. */}
                <StatusTag tone={t.global ? "info" : "neutral"}>{t.global ? "Instance-wide" : "This tenant"}</StatusTag>
              </Td>
              {canRemove && (
                <Td>
                  {!t.global && (
                    <Button variant="ghost" size="sm" onClick={() => remove(t)}>
                      Remove
                    </Button>
                  )}
                </Td>
              )}
            </tr>
          ))}
        </Table>
      )}

      {canAdd && (
        <div className="mt-4 border-t pt-4" style={{ borderColor: "var(--c-border)" }}>
          <div className="mb-2 text-[12px]" style={{ color: "var(--c-ink-3)" }}>{meta.matching}</div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="rounded-lg px-3 py-2 text-sm"
              style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)", minWidth: 240 }}
              placeholder={meta.placeholder}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <input
              className="rounded-lg px-3 py-2 text-sm"
              style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)", minWidth: 240 }}
              placeholder="Why this is a crown jewel"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <Button onClick={add} disabled={busy || !value.trim()}>
              {busy ? "Adding…" : "Protect"}
            </Button>
          </div>
        </div>
      )}
    </Panel>
  );
}
