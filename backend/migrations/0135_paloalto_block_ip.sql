-- 0135: wire the Palo Alto network-block Actioner behind `block_ip` — closing an armed-but-dead gap.
--
-- `block_ip` was seeded (0036) against connector_key 'defender', which has NO block_ip actioner, so the seeded
-- "Block the source IP" playbook step silently hit the truthful `simulate` fallback (no live actioner registered).
-- It is also fleet_wide=true (0134). Now that a real Palo Alto block_ip⇄unblock_ip actioner exists (connector_key
-- 'palo-alto'), repoint the GLOBAL catalog row so `block_ip` has a real backing connector.
--
-- Resolution note (verified at source, service.go:264-269 / catalog.go:68): the actioner is looked up by the CATALOG
-- row's connector_key (resolveAction keys on action_key; the playbook step's connector_key is only a fallback used
-- when the catalog's is empty). The block_ip catalog row's connector_key is non-empty, so repointing THIS row is what
-- makes the step live. block_domain (needs an EDL + config commit) and network_block_all (business_critical
-- break-glass) are deliberately UNTOUCHED — separate follow-on slices, not silently covered here.
UPDATE soar_action_catalog
   SET connector_key = 'palo-alto'
 WHERE tenant_id IS NULL
   AND action_key = 'block_ip'
   AND connector_key = 'defender';

-- Audit-honesty (reviewer note): the seeded playbook step JSON in 0108 still reads "connector_key":"defender" for the
-- block_ip step. Execution now routes to palo-alto (catalog wins), so leaving the JSON as 'defender' is
-- "says-one-thing-does-another" drift in the audit trail. Repoint the step JSON to match execution. This is NOT
-- required for correctness (catalog wins regardless) — only for honesty. Idempotent (no-op once repointed).
UPDATE playbooks
   SET steps = REPLACE(steps::text,
                       '"connector_key":"defender","action":"block_ip"',
                       '"connector_key":"palo-alto","action":"block_ip"')::jsonb
 WHERE tenant_id IS NULL
   AND steps::text LIKE '%"connector_key":"defender","action":"block_ip"%';
