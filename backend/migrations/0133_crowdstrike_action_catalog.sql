-- §6.11 G1 #2 — CrowdStrike Falcon EDR host-containment action catalog row (isolate). Vendor-prefixed key
-- (cs_isolate_host) because soar_action_catalog is keyed by action_key alone with a routing connector_key column —
-- a bare 'isolate_endpoint' already maps to defender (0036), so a CrowdStrike isolate step would misroute.
-- cs_release_host is the registry-only INVERSE (invoked by reverse), not a catalog step action — not seeded here
-- (mirrors defender release_endpoint / entra enable_user / okta unsuspend). isolate = high (§9.5, single-host,
-- reversible). cs_block_hash (tenant-wide blast radius, CS-FLAG) + cs_kill_process (non-reversible/RTR) are
-- deliberate follow-ups — not built, not seeded (an un-actioned step simulates, honestly).
INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key) VALUES
  (NULL, 'cs_isolate_host', 'Isolate CrowdStrike host (network containment)', 'high', 'connector', 'crowdstrike')
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key) DO NOTHING;
