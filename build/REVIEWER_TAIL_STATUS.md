# Reviewer tail — status (Jul 15 2026)

The whole UI-depth program (Bucket A + B) is reviewed-clean, 0 open findings. This tracks the non-blocker tail the
reviewer listed so nothing is lost. Split by what code can close vs. what only the operator/owner can do.

## Closed in code this session
| Item | Sev | Fix | Commit |
|------|-----|-----|--------|
| `/admin/audit` exposed the raw operator audit trail to `customer_admin` | HIGH | route `ssoAdmin`→`padmin` (platform_admin only) + regression test + class sweep | 9648320 |
| No CSP / security headers on the SPA | MED | `next.config.mjs` `headers()`: CSP (connect-src derives API origin; frame-ancestors 'none'; object-src 'none'; base-uri/form-action 'self'; upgrade-insecure-requests) + nosniff / X-Frame-Options DENY / Referrer-Policy / Permissions-Policy | 8790bc5 |
| `/reports/summary` fetched by shell + page (double request) | LOW | `apiGetCached` (shared in-flight promise + 10s TTL, never caches failures); routed shell+dashboard+exec+reports | 8790bc5 |
| Admin MFA un-enforceable (no enrollment UI existed) | — | built the TOTP enrollment flow in settings (enroll→secret+otpauth→verify→activate; disable) + a persistent non-dismissible "Enable MFA" prompt for platform_admin-without-MFA across the console (no hard lockout) | 8790bc5 |

**Verify-live note:** the CSP is the one change I could not exercise locally (`next build` is MAX_PATH-blocked
here). Confirm the deployed app loads with no CSP console violations on the first Vercel build after 8790bc5; if a
legit resource is blocked, widen exactly that directive (most likely `connect-src` if the API origin env differs,
or `img-src` for a branding logo host).

## Owner / infra actions — cannot be closed from code
1. **Rotate credentials in `outputs/The Cred.txt`** (GitHub PAT line 1, Render key line 3, Vercel token line 5).
   They've been used from this environment; rotate in each provider's dashboard, then update the file. *(I don't
   rotate tokens — provider-side action.)*
2. **Render always-on plan.** The backend spins down on the current plan → cold-start makes the UI look briefly
   broken, and a SOC API should not sleep. Move `nirvet-api` to an always-on instance (paid) before a real agency
   is on the box. *(Billing/plan change — owner.)*
3. **Wipe test data + seeded test-user invitations; rotate the seeded `platform_admin` credentials, and enrol its
   MFA** (now that the enrollment UI exists — commit 8790bc5). Same cutover class as the seeded-admin rotation
   already captured. *(Destructive prod-data + credential action — owner; I won't wipe prod data or set passwords
   unprompted.)*

## Platform-wide gates still genuinely open (from earlier, not this review)
- **Scale / soak gate** — the value loop has never run at volume; the one untested go-live prerequisite.
- **KMS at go-live** — envelope-encryption adapter is built + tested; provision the cloud KMS at go-live.

## Suggested next moves
- Fresh-session **live QA of the Bucket-B screens per role** on Vercel (needs the owner to log back in).
- Pick up the **soak gate** — the remaining untested go-live prerequisite.
