-- 0058_threat_intel_settings.sql
-- §6.10 slice B: per-tenant threat-intel tuning (config-first, no hardcoding). Drives STIX confidence
-- decay + the sightings-corroboration boost. Lazy default — a tenant with no row uses the column
-- defaults (the service returns them); Set upserts. Tenant-scoped RLS.

CREATE TABLE IF NOT EXISTS threat_intel_settings (
  tenant_id                uuid PRIMARY KEY,
  decay_half_life_days     int NOT NULL DEFAULT 30 CHECK (decay_half_life_days >= 1 AND decay_half_life_days <= 3650),
  min_effective_confidence int NOT NULL DEFAULT 0  CHECK (min_effective_confidence >= 0 AND min_effective_confidence <= 100),
  sighting_boost_cap       int NOT NULL DEFAULT 20 CHECK (sighting_boost_cap >= 0 AND sighting_boost_cap <= 100),
  updated_at               timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE threat_intel_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS threat_intel_settings_rw ON threat_intel_settings;
CREATE POLICY threat_intel_settings_rw ON threat_intel_settings
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON threat_intel_settings TO nirvet_app;
