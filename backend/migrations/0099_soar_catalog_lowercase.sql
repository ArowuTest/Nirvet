-- H-1 (reviewer 2nd pass, HIGH): the SOAR actioner registry matches (connector_key, action_key)
-- case-INSENSITIVELY, but the D5 protected-target guards compared case-SENSITIVELY — so a mis-cased catalog
-- override (e.g. connector_key='Defender') fired the real actioner while SILENTLY skipping the protected-host /
-- protected-identity guard: it could isolate a crown-jewel host or disable a break-glass identity with no D5
-- refusal. Fixed in code (EqualFold in both guards + lower-casing at the catalog write chokepoint); this is the
-- DB defence-in-depth so a mis-cased key can never be persisted at all.

-- Normalise any existing rows, then constrain.
UPDATE soar_action_catalog SET connector_key = lower(connector_key) WHERE connector_key <> lower(connector_key);
UPDATE soar_action_catalog SET action_key    = lower(action_key)    WHERE action_key    <> lower(action_key);

ALTER TABLE soar_action_catalog
  ADD CONSTRAINT soar_action_catalog_lowercase_keys
  CHECK (connector_key = lower(connector_key) AND action_key = lower(action_key));
