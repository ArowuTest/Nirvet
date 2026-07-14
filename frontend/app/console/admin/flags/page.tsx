"use client";

// Platform-admin feature flags (SRS §6.18 config governance). Lists every configured flag with its derived safety
// class and secure default, and lets a padmin flip a flag via PUT /admin/flags. The guardrails are server-side and
// deliberately NOT re-implemented here: a "guarded"/"protected" change requires a reason (we prompt for it), and a
// protected *weakening* additionally requires a distinct four-eyes approver — which a simple toggle can't satisfy, so
// the server 403 is surfaced honestly rather than hidden. "immutable" flags cannot be changed at all.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPut, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

type Flag = {
  key: string;
  scope: string;
  scope_ref: string;
  enabled: boolean;
  safety_class: string;
  secure_default: boolean;
  expires_at?: string;
  updated_at: string;
};

const classTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  open: "neutral",
  guarded: "info",
  protected: "warn",
  immutable: "danger",
};

export default function AdminFlagsPage() {
  const [flags, setFlags] = useState<Flag[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "forbidden">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ flags: Flag[] | null }>("/admin/flags");
      setFlags(r.flags ?? []);
      setState("ready");
    } catch (e) {
      setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "ready");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function toggle(f: Flag) {
    if (f.safety_class === "immutable") {
      setMsg({ tone: "danger", text: `"${f.key}" is immutable and cannot be changed via config.` });
      return;
    }
    const next = !f.enabled;
    const weakening = f.safety_class === "protected" && next !== f.secure_default;
    let reason = "";
    if (f.safety_class === "guarded" || f.safety_class === "protected") {
      reason = window.prompt(`Reason for ${next ? "enabling" : "disabling"} "${f.key}"${weakening ? " (this weakens a protected flag — a four-eyes approver is also required and this attempt will be rejected without one)" : ""}:`, "") ?? "";
      if (!reason.trim()) {
        setMsg({ tone: "danger", text: "A reason is required for this change." });
        return;
      }
    }
    setMsg(null);
    setBusy(`${f.key}|${f.scope}|${f.scope_ref}`);
    try {
      await apiPut(`/admin/flags`, { key: f.key, scope: f.scope, scope_ref: f.scope_ref, enabled: next, reason });
      setMsg({ tone: "ok", text: `"${f.key}" set to ${next ? "enabled" : "disabled"}.` });
      await load();
    } catch (e) {
      const forbidden = e instanceof ApiError && e.status === 403;
      setMsg({ tone: "danger", text: forbidden ? "Rejected: this change needs a platform-admin and, for a protected weakening, a distinct four-eyes approver." : e instanceof Error ? e.message : "Change failed." });
    } finally {
      setBusy(null);
    }
  }

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "forbidden")
    return (
      <div>
        <PageHeader title="Feature flags" />
        <EmptyState title="Platform-admin only" hint="Configuration flags are restricted to the platform super-admin." />
      </div>
    );

  return (
    <div>
      <PageHeader title="Feature flags" sub="Platform configuration flags with safety governance" actions={<Button size="sm" variant="ghost" onClick={load}>Refresh</Button>} />
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <Panel title="Configured flags" sub="Guarded and protected flags require a reason; protected weakenings require four-eyes" bodyStyle={{ padding: flags.length ? 0 : undefined }}>
        {flags.length === 0 ? (
          <EmptyState title="No flags configured" hint="Flags appear here once set; unset flags use their secure default." />
        ) : (
          <Table head={<><Th>Flag</Th><Th>Scope</Th><Th>Class</Th><Th>State</Th><Th>Secure default</Th><Th className="text-right">Action</Th></>}>
            {flags.map((f) => {
              const id = `${f.key}|${f.scope}|${f.scope_ref}`;
              const atSecure = f.enabled === f.secure_default;
              return (
                <tr key={id} style={{ borderTop: "1px solid var(--c-border)" }}>
                  <Td className="font-mono text-[12px]" title={f.key}>{f.key}</Td>
                  <Td className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>{f.scope}{f.scope_ref ? ` · ${f.scope_ref.slice(0, 8)}` : ""}</Td>
                  <Td><StatusTag tone={classTone[f.safety_class] ?? "neutral"}>{f.safety_class}</StatusTag></Td>
                  <Td>
                    <StatusTag tone={f.enabled ? "ok" : "neutral"}>{f.enabled ? "enabled" : "disabled"}</StatusTag>
                    {!atSecure && <span className="ml-1.5 text-[10px] uppercase tracking-wide" style={{ color: "var(--c-warn)" }}>off-default</span>}
                    {f.expires_at && <span className="ml-1.5 text-[10px]" style={{ color: "var(--c-ink-3)" }} title="Auto-reverts to the secure default when the time-box expires">time-boxed</span>}
                  </Td>
                  <Td className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>{f.secure_default ? "enabled" : "disabled"}</Td>
                  <Td className="text-right">
                    {f.safety_class === "immutable" ? (
                      <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>locked</span>
                    ) : (
                      <Button size="sm" variant="ghost" disabled={busy === id} onClick={() => toggle(f)}>
                        {busy === id ? "…" : f.enabled ? "Disable" : "Enable"}
                      </Button>
                    )}
                  </Td>
                </tr>
              );
            })}
          </Table>
        )}
      </Panel>
    </div>
  );
}
