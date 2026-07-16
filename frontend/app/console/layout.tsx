"use client";

// Console shell — topbar + grouped sidebar + main, built to the approved SOC-Dashboard-v2 mockup. Client-side
// route guard (ADR-0007): the session lives in HttpOnly cookies JS can't read, so we probe GET /me — 200 renders,
// 401 → /login. Defence-in-depth UX only; the backend RLS + auth middleware are the real access control. Live
// nav badge counts come from GET /reports/summary (best-effort; the shell renders regardless of the API).

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { getMe, logout, logoutAll, apiGet, apiGetCached, ApiError, type Me } from "@/lib/api";
import { Icon, NirvetMark } from "@/components/icons";

// F1 — role-aware nav (hide, don't deny). `roles` lists who may SEE an item; undefined = every internal role.
// This mirrors the backend gate tiers so a role never sees a link it would only get a 403 from; the backend
// RLS + route middleware remain the real access control (this is UX only). Customer roles never reach the
// console (redirected to /portal below), so ssoAdmin surfaces are effectively platform_admin here.
const PADMIN = ["platform_admin"]; // Administration section — platform-admin only
const MANAGER = ["platform_admin", "soc_manager"]; // manager surfaces (Team workload)
const OVERSIGHT = ["platform_admin", "org_sub_admin", "payer"]; // fleet oversight audience
// The internal SOC roles (auth.ProviderRoles). Every Operations/Response/Platform route is provider-gated, so
// the oversight-only roles (org_sub_admin / payer) must not see those items — they can reach just three
// rollup routes and would 403 on everything else (F4).
const PROVIDER = ["platform_admin", "soc_manager", "analyst_t1", "analyst_t2", "analyst_t3", "detection_engineer"];
// Roles that live in the console but are NOT SOC operators: they get the oversight landing, not the SOC dashboard.
const OVERSIGHT_ONLY = ["org_sub_admin", "payer"];
// ALL_INTERNAL = every role that can reach the console. Say this explicitly when an item really is for everyone;
// it must never be expressed by leaving `roles` off (see NavItem).
const ALL_INTERNAL = [...PROVIDER, ...OVERSIGHT_ONLY];
// `roles` is REQUIRED, not optional. It was optional, with canSee() defaulting an unmarked item to visible-to-all —
// which is exactly how F4 happened: the oversight roles were shown a full SOC nav where every link 403s, because
// nobody remembered to mark the Operations items. A fail-OPEN default in a visibility rule will eventually be
// forgotten by someone; making it required moves that from "remember" to "the compiler won't let you forget".
// Use ALL_INTERNAL to say "everyone in the console" deliberately, rather than by omission.
type NavItem = { label: string; href: string; icon: string; badge?: "incidents" | "alerts"; ready: boolean; roles: readonly string[] };
const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: "Operations",
    items: [
      { label: "Dashboard", href: "/console", icon: "grid", ready: true, roles: PROVIDER },
      { label: "Executive", href: "/console/exec", icon: "activity", ready: true, roles: PROVIDER },
      { label: "Incidents", href: "/console/incidents", icon: "alert-circle", badge: "incidents", ready: true, roles: PROVIDER },
      { label: "Alerts", href: "/console/alerts", icon: "alert-triangle", badge: "alerts", ready: true, roles: PROVIDER },
      { label: "Threat Hunt", href: "/console/hunt", icon: "shield", ready: true, roles: PROVIDER },
      { label: "Notebooks", href: "/console/notebooks", icon: "file-text", ready: true, roles: PROVIDER },
      { label: "Detections", href: "/console/detections", icon: "target", ready: true, roles: PROVIDER },
      { label: "Assets", href: "/console/assets", icon: "box", ready: true, roles: PROVIDER },
      { label: "Entity graph", href: "/console/entities", icon: "share-2", ready: true, roles: PROVIDER },
      { label: "AI Copilot", href: "/console/copilot", icon: "activity", ready: true, roles: PROVIDER },
    ],
  },
  {
    section: "Response",
    items: [
      { label: "Playbooks", href: "/console/playbooks", icon: "activity", ready: true, roles: PROVIDER },
      // Read is provider-wide on purpose: when a containment is withheld, this list is the answer to "why?".
      { label: "Protected targets", href: "/console/protected-targets", icon: "shield", ready: true, roles: PROVIDER },
      { label: "Privileged access", href: "/console/pam", icon: "shield", ready: true, roles: PROVIDER },
      { label: "Team workload", href: "/console/workload", icon: "users", ready: true, roles: MANAGER },
      { label: "Evidence", href: "/console/evidence", icon: "server", ready: true, roles: PROVIDER },
      { label: "Notifications", href: "/console/notifications", icon: "bell", ready: true, roles: PROVIDER },
    ],
  },
  {
    section: "Platform",
    items: [
      { label: "Integrations", href: "/console/integrations", icon: "plug", ready: true, roles: PROVIDER },
      { label: "Threat Intel", href: "/console/threat-intel", icon: "shield", ready: true, roles: PROVIDER },
      { label: "Compliance", href: "/console/compliance", icon: "shield", ready: true, roles: PROVIDER },
      { label: "Reports", href: "/console/reports", icon: "file-text", ready: true, roles: PROVIDER },
    ],
  },
  {
    // Administration — platform-admin only (all /console/admin/* routes are padmin/ssoAdmin-gated). Fleet
    // oversight also admits the oversight audience (org_sub_admin / payer).
    section: "Administration",
    items: [
      { label: "Tenants", href: "/console/admin/tenants", icon: "box", ready: true, roles: PADMIN },
      { label: "Identity", href: "/console/admin/iam", icon: "users", ready: true, roles: PADMIN },
      { label: "Single sign-on", href: "/console/admin/sso", icon: "users", ready: true, roles: PADMIN },
      { label: "Policies", href: "/console/admin/policies", icon: "shield", ready: true, roles: PADMIN },
      { label: "Risk score", href: "/console/admin/risk", icon: "activity", ready: true, roles: PADMIN },
      { label: "Branding", href: "/console/admin/branding", icon: "settings", ready: true, roles: PADMIN },
      { label: "AI config", href: "/console/admin/ai", icon: "activity", ready: true, roles: PADMIN },
      { label: "Billing", href: "/console/admin/billing", icon: "file-text", ready: true, roles: PADMIN },
      { label: "Feature flags", href: "/console/admin/flags", icon: "settings", ready: true, roles: PADMIN },
      { label: "Audit trail", href: "/console/admin/audit", icon: "file-text", ready: true, roles: PADMIN },
      { label: "Fleet oversight", href: "/console/oversight", icon: "grid", ready: true, roles: OVERSIGHT },
      { label: "Platform health", href: "/console/admin/health", icon: "server", ready: true, roles: PADMIN },
    ],
  },
];

// A nav item is visible only when the current role is on its allow-list. Fail-CLOSED: no role, no item — there is
// no "unmarked means everyone" path any more (see NavItem.roles).
function canSee(item: NavItem, role?: string): boolean {
  return !!role && item.roles.includes(role);
}

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [state, setState] = useState<"loading" | "ready">("loading");
  const [counts, setCounts] = useState<{ incidents?: number; alerts?: number }>({});
  const [unread, setUnread] = useState(0);
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    // BUG-3: a transient /me failure (cold start, flaky link) used to bounce a valid session straight to /login.
    // Retry once before giving up — only a genuine 401 (or two failures) ends the session.
    async function verify(): Promise<Me> {
      try {
        return await getMe();
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) throw e; // definitively signed out — don't retry
        await new Promise((r) => setTimeout(r, 1200));
        return getMe();
      }
    }
    verify()
      .then((u) => {
        if (!alive) return;
        if (u.role?.startsWith("customer")) {
          router.replace("/portal"); // customer users belong in the customer portal, not the SOC console
          return;
        }
        setMe(u);
        setState("ready");
        if (!OVERSIGHT_ONLY.includes(u.role ?? "")) {
          // Provider-only badge counts; an oversight role would just 403 on these.
          apiGetCached<{ open_incidents: number; open_alerts: number }>("/reports/summary")
            .then((s) => alive && setCounts({ incidents: s.open_incidents, alerts: s.open_alerts }))
            .catch(() => {});
          apiGet<{ unread_count: number }>("/notify/inbox/unread-count")
            .then((n) => alive && setUnread(n.unread_count))
            .catch(() => {});
        }
      })
      .catch(() => alive && router.replace("/login"));
    return () => {
      alive = false;
    };
  }, [router]);

  // F4: the oversight roles are not SOC operators — every provider route 403s for them. Land them on their own
  // surface (fleet oversight) rather than the SOC dashboard they cannot read. Kept out of the verify effect so
  // navigating does not re-probe /me.
  useEffect(() => {
    if (me && OVERSIGHT_ONLY.includes(me.role ?? "") && pathname === "/console") {
      router.replace("/console/oversight");
    }
  }, [me, pathname, router]);

  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  async function signOut(everywhere: boolean) {
    try {
      await (everywhere ? logoutAll() : logout());
    } catch {
      /* best-effort; clear the UI regardless */
    }
    router.replace("/login");
  }

  if (state === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm" style={{ color: "var(--c-ink-3)" }}>
        Verifying session…
      </div>
    );
  }

  const initials = (me?.email ?? "?").slice(0, 2).toUpperCase();
  const role = me?.role?.replace(/_/g, " ") ?? "";
  // MFA nudge for platform admins. Deliberately a prompt, NOT a hard block: there is no server-side force-MFA
  // policy yet (login only demands a code when the account already has MFA enabled), so a client-side gate would
  // be theatre — bypassable, and it would lock out an admin who hasn't enrolled. Enforcing this properly means an
  // admin-config policy record + server-side enforcement (no-hardcoding rule); tracked, not faked here.
  const mfaNudge = me?.role === "platform_admin" && me?.mfa_enabled === false && !pathname.startsWith("/console/settings");

  return (
    <div className="flex h-screen flex-col overflow-hidden" style={{ background: "var(--c-bg)" }}>
      {/* Topbar */}
      <header
        className="flex h-14 shrink-0 items-center gap-3 px-4"
        style={{ background: "var(--c-surface)", borderBottom: "1px solid var(--c-border)" }}
      >
        <Link href="/console" className="flex items-center gap-2">
          <NirvetMark size={26} />
          <span className="text-sm font-extrabold tracking-tight">
            NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
          </span>
        </Link>
        <div className="mx-1 h-6 w-px" style={{ background: "var(--c-border)" }} />
        <div className="flex items-center gap-2 rounded-lg px-2.5 py-1.5" style={{ background: "var(--c-surface-2)" }}>
          <span className="h-2 w-2 rounded-full" style={{ background: "var(--c-accent)", boxShadow: "0 0 8px rgba(6,182,212,0.6)" }} />
          <span className="text-xs font-medium" style={{ color: "var(--c-ink)" }}>Your tenant</span>
          <span
            className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
            style={{ background: "rgba(14,165,233,0.1)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" }}
          >
            {me ? `#${me.tenant_id.slice(0, 6)}` : ""}
          </span>
        </div>

        <div className="ml-auto flex items-center gap-3">
          <span className="hidden items-center gap-1.5 text-[11px] md:flex" style={{ color: "var(--c-ink-3)" }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--c-ok)" }} />
            All systems operational
          </span>
          <div className="mx-1 h-6 w-px" style={{ background: "var(--c-border)" }} />
          <Link href="/console/notifications" className="relative rounded-lg p-1.5" style={{ color: "var(--c-ink-2)" }} aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`}>
            <Icon name="bell" size={17} />
            {unread > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold text-white" style={{ background: "var(--c-danger)" }}>
                {unread > 9 ? "9+" : unread}
              </span>
            )}
          </Link>

          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setMenu((m) => !m)}
              className="flex items-center gap-2 rounded-lg py-1 pl-1 pr-2"
              style={{ color: "var(--c-ink)" }}
              aria-haspopup="menu"
              aria-expanded={menu}
            >
              <span
                className="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold"
                style={{ background: "rgba(14,165,233,0.15)", border: "1.5px solid var(--c-border-strong)", color: "var(--c-primary)" }}
              >
                {initials}
              </span>
              <span className="hidden text-left sm:block">
                <span className="block max-w-[160px] truncate text-xs font-medium">{me?.email}</span>
                <span className="block text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{role}</span>
              </span>
            </button>
            {menu && (
              <div
                role="menu"
                className="absolute right-0 mt-2 w-56 overflow-hidden rounded-xl py-1 text-sm shadow-2xl"
                style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border-strong)" }}
              >
                <div className="px-3 py-2 text-[11px]" style={{ color: "var(--c-ink-3)", borderBottom: "1px solid var(--c-border)" }}>
                  Signed in as
                  <br />
                  <span style={{ color: "var(--c-ink-2)" }}>{me?.email}</span>
                </div>
                <button role="menuitem" onClick={() => signOut(false)} className="block w-full px-3 py-2 text-left hover:bg-white/5" style={{ color: "var(--c-ink-2)" }}>
                  Sign out
                </button>
                <button
                  role="menuitem"
                  onClick={() => signOut(true)}
                  className="block w-full px-3 py-2 text-left text-[12px] hover:bg-white/5"
                  style={{ color: "var(--c-ink-3)" }}
                  title="Ends every active session on all your devices"
                >
                  Sign out everywhere
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Body: sidebar + main */}
      <div className="flex flex-1 overflow-hidden">
        <aside
          className="flex w-56 shrink-0 flex-col gap-0.5 overflow-y-auto p-3"
          style={{ background: "var(--c-surface)", borderRight: "1px solid var(--c-border)" }}
          aria-label="Application navigation"
        >
          {NAV.map((group) => {
            const items = group.items.filter((i) => canSee(i, me?.role));
            if (items.length === 0) return null; // hide the whole section when the role sees nothing in it
            return (
            <div key={group.section} className="mb-1">
              <div className="px-2 pb-1.5 pt-3 text-[10px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--c-ink-3)" }}>
                {group.section}
              </div>
              {items.map((item) => {
                const active = item.href === "/console" ? pathname === item.href : pathname.startsWith(item.href);
                const count = item.badge ? counts[item.badge] : undefined;
                const inner = (
                  <>
                    <Icon name={item.icon} size={16} />
                    <span className="flex-1 text-sm">{item.label}</span>
                    {typeof count === "number" && count > 0 && (
                      <span
                        className="rounded-full px-1.5 py-0.5 text-[10px] font-bold"
                        style={{
                          background: item.badge === "incidents" ? "rgba(239,68,68,0.15)" : "rgba(245,158,11,0.15)",
                          color: item.badge === "incidents" ? "#fca5a5" : "#fcd34d",
                        }}
                      >
                        {count}
                      </span>
                    )}
                    {!item.ready && (
                      <span className="text-[9px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>soon</span>
                    )}
                  </>
                );
                const cls = "flex items-center gap-2.5 rounded-lg px-2.5 py-2 transition";
                return item.ready ? (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cls}
                    aria-current={active ? "page" : undefined}
                    style={active ? { background: "rgba(14,165,233,0.1)", color: "var(--c-ink)" } : { color: "var(--c-ink-2)" }}
                  >
                    {inner}
                  </Link>
                ) : (
                  <div key={item.href} className={`${cls} cursor-not-allowed opacity-50`} style={{ color: "var(--c-ink-3)" }} aria-disabled>
                    {inner}
                  </div>
                );
              })}
            </div>
            );
          })}

          <div className="mt-auto pt-3" style={{ borderTop: "1px solid var(--c-border)" }}>
            <Link
              href="/console/settings"
              className="flex items-center gap-2.5 rounded-lg px-2.5 py-2 transition"
              aria-current={pathname.startsWith("/console/settings") ? "page" : undefined}
              style={pathname.startsWith("/console/settings") ? { background: "rgba(14,165,233,0.1)", color: "var(--c-ink)" } : { color: "var(--c-ink-2)" }}
            >
              <Icon name="settings" size={16} />
              <span className="flex-1 text-sm">Settings</span>
            </Link>
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto p-8">
          {mfaNudge && (
            <div className="mb-6 flex items-center justify-between gap-3 rounded-xl px-4 py-3 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>
              <span>Multi-factor authentication is required for platform-admin accounts and is not yet enabled on yours.</span>
              <Link href="/console/settings" className="shrink-0 rounded-lg px-3 py-1.5 font-semibold" style={{ background: "#ef4444", color: "#fff" }}>Enable MFA</Link>
            </div>
          )}
          {children}
        </main>
      </div>
    </div>
  );
}
