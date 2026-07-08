-- §6.10 threat intel — real STIX 2.1 object store (TI-001..004).
--
-- The existing threat_indicators table (0005) is a flat {type,value,tlp,score,tags} watchlist: fine for
-- manual IOCs, but it is NOT STIX. It has no SDO/SRO/SCO typing, no confidence/valid_from/valid_until,
-- no revoked flag, no kill-chain / ATT&CK external references, no versioning by (id, modified). This
-- adds a real STIX 2.1 object store alongside it (the watchlist stays as the quick manual-IOC path).
--
-- Model per OASIS STIX 2.1: every object has a typed id `type--uuid`, spec_version, created/modified,
-- confidence, revoked, optional validity window, and a full raw JSON body. For matchable objects
-- (indicators / cyber-observables) we extract a single observable `value` into a column so enrichment
-- is an indexed lookup rather than a JSON scan. Global feeds (tenant_id NULL) are shared read-only;
-- tenant objects are isolated. RLS FORCE, per-command policies (global-or-own read, own-only write) —
-- same shape as detection_rules (0026) / soar_action_catalog (0037) so a tenant cannot re-home or
-- delete a shared global object.

CREATE TABLE IF NOT EXISTS stix_objects (
  id                  text PRIMARY KEY,               -- STIX id: `type--uuid` (e.g. indicator--<uuid>)
  tenant_id           uuid,                           -- NULL = global shared feed; else owning tenant
  type                text NOT NULL,                  -- SDO/SCO type (see CHECK)
  spec_version        text NOT NULL DEFAULT '2.1',
  created             timestamptz NOT NULL DEFAULT now(),   -- STIX created (object birth)
  modified            timestamptz NOT NULL DEFAULT now(),   -- STIX modified (version marker; upsert key)
  confidence          int  NOT NULL DEFAULT 0,        -- 0-100 (STIX confidence)
  revoked             boolean NOT NULL DEFAULT false,
  valid_from          timestamptz,                    -- indicator validity window (optional)
  valid_until         timestamptz,
  pattern             text NOT NULL DEFAULT '',       -- indicator pattern ([ipv4-addr:value = 'x'] etc.)
  pattern_type        text NOT NULL DEFAULT 'stix',   -- stix | sigma | snort | yara | suricata
  labels              text[] NOT NULL DEFAULT '{}',   -- malicious-activity, c2, phishing, ...
  external_references jsonb  NOT NULL DEFAULT '[]',    -- ATT&CK (mitre-attack Txxxx) / CVE / source urls
  kill_chain_phases   text[] NOT NULL DEFAULT '{}',   -- lockheed/mitre phase names (reconnaissance, ...)
  tlp                 text NOT NULL DEFAULT 'amber',  -- derived from object_marking_refs (TLP 2.0)
  source              text NOT NULL DEFAULT 'manual', -- feed/source name (manual, taxii:<collection>, ...)
  value               text NOT NULL DEFAULT '',       -- extracted observable for matching ('' if none)
  raw                 jsonb  NOT NULL DEFAULT '{}',    -- full STIX object as received (source of truth)
  created_at          timestamptz NOT NULL DEFAULT now(),  -- row insert (internal)
  updated_at          timestamptz NOT NULL DEFAULT now(),  -- row last upsert (internal)
  CONSTRAINT stix_objects_type_chk CHECK (type IN (
    -- SDOs
    'indicator','malware','attack-pattern','threat-actor','intrusion-set','campaign','tool',
    'vulnerability','infrastructure','course-of-action','identity','report','observed-data','note',
    'malware-analysis','grouping','location','incident','opinion',
    -- SROs
    'relationship','sighting',
    -- common SCOs (cyber-observables used directly as IOCs)
    'ipv4-addr','ipv6-addr','domain-name','url','file','email-addr','email-message',
    'user-account','mac-addr','autonomous-system','x509-certificate','windows-registry-key'
  )),
  CONSTRAINT stix_objects_tlp_chk CHECK (tlp IN ('red','amber+strict','amber','green','clear')),
  CONSTRAINT stix_objects_pattern_type_chk CHECK (pattern_type IN ('stix','sigma','snort','yara','suricata')),
  CONSTRAINT stix_objects_confidence_chk CHECK (confidence BETWEEN 0 AND 100)
);

-- Enrichment lookup: match an event entity against matchable objects (value <> '') within global+own.
CREATE INDEX IF NOT EXISTS stix_objects_value ON stix_objects (value) WHERE value <> '';
CREATE INDEX IF NOT EXISTS stix_objects_tenant_type ON stix_objects (tenant_id, type);
-- Fast "not stale" filter for enrichment (skip revoked / expired without a scan).
CREATE INDEX IF NOT EXISTS stix_objects_live ON stix_objects (tenant_id) WHERE NOT revoked;

ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_objects FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation      ON stix_objects;
DROP POLICY IF EXISTS stix_objects_select   ON stix_objects;
DROP POLICY IF EXISTS stix_objects_insert   ON stix_objects;
DROP POLICY IF EXISTS stix_objects_update   ON stix_objects;
DROP POLICY IF EXISTS stix_objects_delete   ON stix_objects;

-- Read: shared global feed (tenant_id IS NULL) + the tenant's own objects.
CREATE POLICY stix_objects_select ON stix_objects
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
-- Write: own-tenant only. Global objects are seeded by migrations / a system importer (owner role,
-- which bypasses RLS); a tenant can neither create a global row nor re-home/alter/delete a shared one.
CREATE POLICY stix_objects_insert ON stix_objects
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY stix_objects_update ON stix_objects
  FOR UPDATE USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY stix_objects_delete ON stix_objects
  FOR DELETE USING (tenant_id = app_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON stix_objects TO nirvet_app;

-- Sightings (SRO companion): a lightweight "this object was seen N times" counter, kept own-tenant so a
-- tenant's sightings of a global object are private to them. Full relationship-graph traversal is a
-- later slice; sightings are the one SRO that TI operations need now (last_seen / count for scoring).
CREATE TABLE IF NOT EXISTS stix_sightings (
  id               text PRIMARY KEY,                  -- sighting--<uuid>
  tenant_id        uuid NOT NULL DEFAULT app_current_tenant(),
  sighting_of_ref  text NOT NULL,                     -- stix_objects.id that was seen
  count            int  NOT NULL DEFAULT 1,
  first_seen       timestamptz NOT NULL DEFAULT now(),
  last_seen        timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, sighting_of_ref)
);
CREATE INDEX IF NOT EXISTS stix_sightings_ref ON stix_sightings (tenant_id, sighting_of_ref);

ALTER TABLE stix_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_sightings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON stix_sightings;
CREATE POLICY tenant_isolation ON stix_sightings
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON stix_sightings TO nirvet_app;

-- Seed a small GLOBAL reference set (attack-pattern SDOs mapped to ATT&CK). These carry no observable
-- value, so they do not match traffic — they are shared reference data every tenant can read and that
-- relationships/reports can point at. Concrete IOCs come from tenant submission or feed import, not a
-- baked-in global watchlist (which would false-positive across every tenant).
INSERT INTO stix_objects (id, tenant_id, type, confidence, labels, external_references, kill_chain_phases, tlp, source, raw)
VALUES
  ('attack-pattern--0f4d8e6a-1a2b-4c3d-9e5f-000000000001', NULL, 'attack-pattern', 75,
   ARRAY['reconnaissance'],
   '[{"source_name":"mitre-attack","external_id":"T1595","url":"https://attack.mitre.org/techniques/T1595/"}]'::jsonb,
   ARRAY['reconnaissance'], 'clear', 'seed',
   '{"type":"attack-pattern","name":"Active Scanning","spec_version":"2.1"}'::jsonb),
  ('attack-pattern--0f4d8e6a-1a2b-4c3d-9e5f-000000000002', NULL, 'attack-pattern', 80,
   ARRAY['credential-access'],
   '[{"source_name":"mitre-attack","external_id":"T1110","url":"https://attack.mitre.org/techniques/T1110/"}]'::jsonb,
   ARRAY['credential-access'], 'clear', 'seed',
   '{"type":"attack-pattern","name":"Brute Force","spec_version":"2.1"}'::jsonb),
  ('attack-pattern--0f4d8e6a-1a2b-4c3d-9e5f-000000000003', NULL, 'attack-pattern', 80,
   ARRAY['command-and-control'],
   '[{"source_name":"mitre-attack","external_id":"T1071","url":"https://attack.mitre.org/techniques/T1071/"}]'::jsonb,
   ARRAY['command-and-control'], 'clear', 'seed',
   '{"type":"attack-pattern","name":"Application Layer Protocol","spec_version":"2.1"}'::jsonb)
ON CONFLICT (id) DO NOTHING;
