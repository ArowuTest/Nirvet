-- FleetWide authority dimension (§6.11 / owner decision Option 1: fleet-wide actions are approval-ALWAYS,
-- human-runnable). A BREADTH gate axis INDEPENDENT of the risk/reversibility axis: Allowed(mode,risk) licenses a
-- High *reversible* action to auto-run under pre_authorized/contractual_auto, but reversibility is the wrong proxy
-- for "safe to automate" when the blast radius is the whole tenant (a false-positive fleet-wide block = fleet-wide
-- outage until reversed). fleet_wide=true ⇒ never auto-eligible under ANY authority mode; still approvable and
-- runnable by a manager (reachable control, not the business_critical phantom).
--
-- Config-izable with a seeded default (no-hardcoding rule), like risk_class. A tenant override may only RAISE
-- fleet_wide (false→true), never LOWER it (true→false) — the same "an override may only tighten a safety
-- guarantee" clamp enforced in code (catalog.go merge).
ALTER TABLE soar_action_catalog ADD COLUMN IF NOT EXISTS fleet_wide boolean NOT NULL DEFAULT false;

-- Retroactively harden the ALREADY-CATALOGED fleet-wide family. This closes a LATENT (not live) fail-open: these
-- Defender rows are seeded 'high' (0036) and are genuinely fleet-wide (a Defender custom-indicator block applies
-- across every endpoint), so they would auto-fire fleet-wide under a permissive mode the day a Defender block
-- actioner is registered. Not live today only because no Defender block actioner exists (they simulate) and the
-- seeded playbooks set requires_approval — i.e. safety rested on the author remembering. Now structural.
UPDATE soar_action_catalog SET fleet_wide = true
 WHERE tenant_id IS NULL
   AND action_key IN ('block_hash', 'block_ip', 'block_domain', 'network_block_all');

-- CrowdStrike IOC block — the first purpose-built FleetWide consumer (vendor-prefixed: Defender owns block_hash).
-- cs_allow_hash is the registry-only INVERSE (delete-what-we-made), not a catalog step action → not seeded.
INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key, fleet_wide) VALUES
  (NULL, 'cs_block_hash', 'Block file hash across the fleet (CrowdStrike IOC)', 'high', 'connector', 'crowdstrike', true)
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key) DO NOTHING;
