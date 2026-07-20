# Go-Live Arming Checklist (owner copy-paste)

The platform ships with its destructive / high-consequence controls **seeded OFF** (armed-but-dead prevention: a
control that could lock users out or delete evidence must be a deliberate operator act, never a default). This is the
exact, code-sourced sequence to ARM them for the Ghana sovereign go-live. Each step: what it does · the command ·
how to verify · how to reverse. Do them **in order** — KMS first (boot-level), then MFA floor, then retention.

Placeholders: `$API` = the API base (e.g. `https://nirvet-api.onrender.com`); `$PADMIN_TOKEN` = a platform-admin
session token; `$PGURL` = the production Postgres URL. **Never paste a real secret into a shared terminal/chat** — set
env vars in the Render dashboard, and run SQL from a trusted admin shell.

---

## 1. require-KMS (crypto boot mode) — makes the local master key UNREACHABLE

**What it does.** Flips the crypto layer from the dev/pilot `localCipher` (master key = KEK) to the sovereign KMS
provider (Vault Transit / Cloud KMS), and makes the local path **unreachable** — the app *refuses to boot* on the
local cipher. This is the go-live crypto posture (`crypto.Config.RequireKMS`, `internal/platform/crypto/crypto.go`).

**Precondition.** An in-country Vault (Transit) or Cloud KMS is provisioned, unsealed, and reachable from BOTH the
`api` and `worker` services, with a per-tenant key model. (The DR-failover drill proved decrypt-at-DR against real
Vault — same provider.)

**Command.** Set these env vars on **both** the `nirvet-api` and `nirvet-worker` services (Render dashboard), then
redeploy both. Sourced from `internal/platform/config/config.go`:

```
NIRVET_CRYPTO_PROVIDER=vault          # or: gcp
NIRVET_KMS_KEY_NAME=<transit-key-name>
NIRVET_VAULT_ADDR=https://vault.internal:8200
NIRVET_VAULT_TOKEN=<token>            # read by the crypto pkg; never logged
NIRVET_VAULT_MOUNT=transit            # default; omit unless customised
NIRVET_CRYPTO_REQUIRE_KMS=true        # <-- THE FLIP: local cipher unreachable, fail-closed boot
```

**Verify.**
- Both services boot healthy: `curl -s $API/readyz` → `database: ok`, `event_store: ok`.
- Fail-closed proof (do once in staging): set `NIRVET_CRYPTO_REQUIRE_KMS=true` with NO provider → the service
  **refuses to boot** (`errRequireKMSNoProvider`). That refusal is the guarantee the local key can't be used in prod.
- Decrypt works end-to-end: an existing tenant's encrypted data (connector creds / MFA secrets) still reads back.

**Reverse.** Set `NIRVET_CRYPTO_REQUIRE_KMS=false` and redeploy (drops back to whatever provider/master key is set).
Only do this in an emergency — it re-enables the non-sovereign path. Rotating keys later = KEY_ROTATION.md (dual-read).

---

## 2. MFA enforcement floor (operator instance minimum) — forces MFA at login

**What it does.** Sets the sovereign-operator MINIMUM for MFA that no tenant can weaken (tenant policy may only
*add* roles, never drop a floor role). Enforced at the single session-mint chokepoint (`MintSession` →
`mfaEnrollmentRequired`, `internal/iam/mfaenforce.go`): a covered user with no active MFA factor cannot get a full
session. Seeded OFF (`mfa_enforcement_floor` singleton, `require_all_roles=false`, `floor_roles='{}'`, mig 0136).

**Command.** The instance floor is a **system-context write** (RLS `mfa_floor_write` = `app_current_tenant() IS NULL`,
platform-admin only) and has **no HTTP endpoint yet** — arm it via SQL from a trusted admin shell (`$PGURL`):

```sql
-- Option A — gov "all users need MFA" (the strict sovereign posture):
UPDATE mfa_enforcement_floor SET require_all_roles = true, updated_at = now() WHERE id = 1;

-- Option B — MFA floor for privileged/mutating roles only (lighter posture):
UPDATE mfa_enforcement_floor
   SET require_all_roles = false,
       floor_roles = '{platform_admin,soc_manager,detection_eng,customer_admin}',
       updated_at = now()
 WHERE id = 1;
```

(Per-TENANT MFA — a customer tightening their own policy above the floor — DOES have an API:
`PUT $API/admin/tenants/{id}/session-policy` with `require_mfa` / `mfa_required_roles`, ssoAdmin-gated. The floor
above is the operator-wide minimum beneath all tenants.)

**Verify.**
```sql
SELECT require_all_roles, floor_roles FROM mfa_enforcement_floor WHERE id = 1;   -- shows the armed values
```
Then log in as a covered user with no MFA factor → login returns the `mfa_required` step (cannot get a full session
until enrolled). A user who already has MFA is unaffected.

**Effect timing & reverse.** Takes effect at the **next** session mint (existing live sessions are unaffected until
they re-mint; to force it platform-wide immediately, bump the session generation per INCIDENT_RECOVERY.md). Reverse =
`UPDATE mfa_enforcement_floor SET require_all_roles=false, floor_roles='{}' WHERE id=1;`. Note the zero-config floor
(`privilegedMFARoles`) still protects admin/mutating roles for any TENANT that arms `require_mfa` with an empty scope
— "never protect no one" — independent of this operator floor.

> Rough edge to flag: the operator floor has no padmin HTTP endpoint (SQL-only today). A tiny `PUT /admin/mfa-floor`
> padmin route would make this a UI toggle like retention — a clean small follow-on if the owner wants it.

---

## 3. Jurisdictional retention ceiling (destructive delete) — ARM LAST, it deletes data

**What it does.** Arms the **destructive** side of jurisdictional retention: deleting data past a jurisdiction's
`max_retain_days` ceiling. The FLOOR (retain ≥ `min_retain_days` — only *lengthens* retention, safe) is always on;
only the **ceiling delete** is gated behind this arm (`jurisdiction_delete_armed` singleton, seeded false, mig 0138).
This is genuinely irreversible (deleted evidence is gone) — arm it only when the retention config is confirmed correct.

**Command (platform-admin token; two steps — configure, THEN arm).**
```bash
# 3a. Configure each jurisdiction's floor/ceiling window FIRST (repeat per jurisdiction):
curl -sS -X PUT $API/admin/retention/jurisdictions \
  -H "Authorization: Bearer $PADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jurisdiction_key":"GH","name":"Ghana","min_retain_days":365,"max_retain_days":2555}'

# 3b. Confirm the config, THEN arm the ceiling delete:
curl -sS $API/admin/retention/jurisdictions -H "Authorization: Bearer $PADMIN_TOKEN"   # review windows
curl -sS -X PUT $API/admin/retention/arm \
  -H "Authorization: Bearer $PADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"armed": true}'
```

**Verify.**
```bash
curl -sS $API/admin/retention/arm -H "Authorization: Bearer $PADMIN_TOKEN"   # -> {"armed": true}
```

**Reverse.** `curl -X PUT $API/admin/retention/arm ... -d '{"armed": false}'` disarms future ceiling deletes (it
cannot un-delete already-deleted rows — hence arm last, after a fresh backup per BACKUP_RESTORE.md).

---

## Ordering & final check
1. **KMS require-mode** (§1) — boot-level; everything else assumes the sovereign crypto posture.
2. **MFA floor** (§2) — protects the accounts before you expose the platform.
3. **Retention ceiling** (§3) — LAST, and only after a confirmed backup (destructive).

Then: rotate the seeded super-admin credential (MFA-gated), confirm `/readyz` green, and run the pilot value loop
(ingest → alert → incident → close). Related operational procedures: INSTALL.md, INCIDENT_RECOVERY.md,
BACKUP_RESTORE.md, KEY_ROTATION.md.
