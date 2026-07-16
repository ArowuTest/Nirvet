"use client";

// RoleGate — page-level "hide, don't deny" guard (BUG-2). Some admin pages render their write form
// (Invite / Save provider / Save branding …) before their data fetch resolves, so a non-admin who navigates
// straight to the URL briefly sees controls that will only 403. This gates the whole subtree on GET /me:
// the child component (and its data fetches + write controls) is mounted ONLY for an allowed role; everyone
// else gets a clean access notice. Defence-in-depth UX only — the backend RLS + route gates are the real
// control, and they already 403 these routes (see rbac.spec / admin-deny.spec).

import { useEffect, useState, type ReactNode } from "react";
import { getMe } from "@/lib/api";
import { PageHeader, EmptyState } from "@/components/ui";

// `hint` states WHO the area is for. It defaults to the platform-admin wording every current caller wants, but it
// must be overridable: a gate that allows the whole SOC and still says "limited to platform administrators" tells
// a customer_admin something false and sends them hunting for privileges that would not help — the same defect as
// the J2 403s that guessed a role reason. If the gate does not know the reason, it should not invent one.
export function RoleGate({
  allow,
  title,
  hint = "This area is limited to platform administrators.",
  children,
}: {
  allow: readonly string[];
  title: string;
  hint?: string;
  children: ReactNode;
}) {
  const [state, setState] = useState<"loading" | "ok" | "deny">("loading");
  const allowKey = allow.join(",");

  useEffect(() => {
    let alive = true;
    getMe()
      .then((u) => alive && setState(allowKey.split(",").includes(u.role ?? "") ? "ok" : "deny"))
      .catch(() => alive && setState("deny"));
    return () => {
      alive = false;
    };
  }, [allowKey]);

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "deny")
    return (
      <div>
        <PageHeader title={title} />
        <EmptyState title="Access restricted" hint={hint} />
      </div>
    );
  return <>{children}</>;
}
