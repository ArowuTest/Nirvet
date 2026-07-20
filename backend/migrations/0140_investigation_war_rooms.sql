-- 0140 — §6.9 Investigation war-room (collaborative shared investigation space).
-- Gate: build/GATE_INVESTIGATION_WARROOM.md. This INVERTS the private-per-analyst model (notebooks 0125, saved views
-- 0139 are user_id-owned) into a SHARED, membership-gated space. The governing rule: the shared store holds
-- REFERENCES/re-runnable queries, never rendered/unmasked rows (a query_ref is re-run through RunHunt per viewer, so a
-- junior member sees only what their own field-visibility allows). Membership is enforced STRUCTURALLY in RLS (D4) —
-- not just in Go — via app_current_user() (set by database.WithTenantActor) + SECURITY DEFINER membership helpers.

-- Actor GUC (mirrors app_current_tenant): the current user id from the transaction-local GUC set by WithTenantActor.
CREATE OR REPLACE FUNCTION app_current_user() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_user', true), '')::uuid
$$;

-- ── tables ────────────────────────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigation_war_rooms (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid        NOT NULL DEFAULT app_current_tenant(),
  incident_ref uuid        NOT NULL,                       -- the incident this room investigates (access gate, D2)
  owner_id     uuid        NOT NULL,                       -- creator; the only principal who manages membership (D4)
  title        text        NOT NULL DEFAULT 'War room',
  status       text        NOT NULL DEFAULT 'active',      -- active | archived
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT war_room_status_chk CHECK (status IN ('active', 'archived'))
);
CREATE INDEX IF NOT EXISTS idx_war_rooms_tenant_incident ON investigation_war_rooms (tenant_id, incident_ref);

CREATE TABLE IF NOT EXISTS investigation_war_room_members (
  id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid        NOT NULL DEFAULT app_current_tenant(),
  room_id   uuid        NOT NULL REFERENCES investigation_war_rooms (id) ON DELETE CASCADE,
  user_id   uuid        NOT NULL,
  role      text        NOT NULL DEFAULT 'member',         -- member | moderator (owner is a moderator member row)
  added_by  uuid        NOT NULL,
  added_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (room_id, user_id),
  CONSTRAINT war_room_member_role_chk CHECK (role IN ('member', 'moderator'))
);
CREATE INDEX IF NOT EXISTS idx_war_room_members_user ON investigation_war_room_members (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS investigation_war_room_entries (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid        NOT NULL DEFAULT app_current_tenant(),
  room_id    uuid        NOT NULL REFERENCES investigation_war_rooms (id) ON DELETE CASCADE,
  author_id  uuid        NOT NULL,
  kind       text        NOT NULL,                         -- note (author prose) | query_ref (re-runnable, re-masked)
  body       text        NOT NULL DEFAULT '',              -- note prose (shared as-authored — D3 boundary)
  query      jsonb       NOT NULL DEFAULT '{}',            -- query_ref: {all,any,lookback_seconds,limit}
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT war_room_entry_kind_chk CHECK (kind IN ('note', 'query_ref'))
);
CREATE INDEX IF NOT EXISTS idx_war_room_entries_room ON investigation_war_room_entries (room_id, created_at);

-- ── SECURITY DEFINER membership helpers (D4) ──────────────────────────────────────────────────────────────
-- Used inside the RLS policies. They run as the table OWNER and read via owner_bypass (below), so they see the true
-- membership WITHOUT the policy recursing on itself. Each is scoped to the CURRENT actor+tenant (the GUCs), so it only
-- ever answers "is THIS caller a member/owner of this room". REVOKE PUBLIC + GRANT nirvet_app (SD-revoke fenced).
CREATE OR REPLACE FUNCTION war_room_is_member(p_room uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = public STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM investigation_war_room_members
                 WHERE room_id = p_room AND user_id = app_current_user() AND tenant_id = app_current_tenant())
$$;
REVOKE ALL ON FUNCTION war_room_is_member(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION war_room_is_member(uuid) TO nirvet_app;

CREATE OR REPLACE FUNCTION war_room_is_owner(p_room uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = public STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM investigation_war_rooms
                 WHERE id = p_room AND owner_id = app_current_user() AND tenant_id = app_current_tenant())
$$;
REVOKE ALL ON FUNCTION war_room_is_owner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION war_room_is_owner(uuid) TO nirvet_app;

-- owner_bypass loop for all three tables (mig 0118 pattern; also lets the SD helpers above read as owner).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['investigation_war_rooms','investigation_war_room_members','investigation_war_room_entries'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS owner_bypass ON %I', t);
    EXECUTE format('CREATE POLICY owner_bypass ON %I USING (current_user = %L) WITH CHECK (current_user = %L)', t, current_user, current_user);
  END LOOP;
END $$;

-- ── rooms RLS: read = owner or member; create = you own it; archive = owner only ──────────────────────────
DROP POLICY IF EXISTS war_rooms_select ON investigation_war_rooms;
CREATE POLICY war_rooms_select ON investigation_war_rooms FOR SELECT
  USING (tenant_id = app_current_tenant() AND (owner_id = app_current_user() OR war_room_is_member(id)));
DROP POLICY IF EXISTS war_rooms_insert ON investigation_war_rooms;
CREATE POLICY war_rooms_insert ON investigation_war_rooms FOR INSERT
  WITH CHECK (tenant_id = app_current_tenant() AND owner_id = app_current_user());
DROP POLICY IF EXISTS war_rooms_update ON investigation_war_rooms;
CREATE POLICY war_rooms_update ON investigation_war_rooms FOR UPDATE
  USING (tenant_id = app_current_tenant() AND owner_id = app_current_user())
  WITH CHECK (tenant_id = app_current_tenant() AND owner_id = app_current_user());
GRANT SELECT, INSERT, UPDATE ON investigation_war_rooms TO nirvet_app;

-- ── members RLS: read = members see the roster; INSERT/DELETE = OWNER ONLY (D4 self-join lock) ─────────────
DROP POLICY IF EXISTS war_room_members_select ON investigation_war_room_members;
CREATE POLICY war_room_members_select ON investigation_war_room_members FOR SELECT
  USING (tenant_id = app_current_tenant() AND war_room_is_member(room_id));
-- THE self-join lock: a member row may be inserted ONLY by the room owner. A member — or a non-member — cannot add
-- themselves (or anyone). This is the structural escalation guard; the handler owner-check is defense-in-depth.
DROP POLICY IF EXISTS war_room_members_insert ON investigation_war_room_members;
CREATE POLICY war_room_members_insert ON investigation_war_room_members FOR INSERT
  WITH CHECK (tenant_id = app_current_tenant() AND war_room_is_owner(room_id));
DROP POLICY IF EXISTS war_room_members_delete ON investigation_war_room_members;
CREATE POLICY war_room_members_delete ON investigation_war_room_members FOR DELETE
  USING (tenant_id = app_current_tenant() AND war_room_is_owner(room_id));
GRANT SELECT, INSERT, DELETE ON investigation_war_room_members TO nirvet_app;

-- ── entries RLS: read = members; INSERT = a member posting as THEMSELVES; append-only (no UPDATE/DELETE grant) ─
DROP POLICY IF EXISTS war_room_entries_select ON investigation_war_room_entries;
CREATE POLICY war_room_entries_select ON investigation_war_room_entries FOR SELECT
  USING (tenant_id = app_current_tenant() AND war_room_is_member(room_id));
DROP POLICY IF EXISTS war_room_entries_insert ON investigation_war_room_entries;
CREATE POLICY war_room_entries_insert ON investigation_war_room_entries FOR INSERT
  WITH CHECK (tenant_id = app_current_tenant() AND war_room_is_member(room_id) AND author_id = app_current_user());
GRANT SELECT, INSERT ON investigation_war_room_entries TO nirvet_app;
