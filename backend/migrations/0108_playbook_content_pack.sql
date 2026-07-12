-- LAUNCH #3 (#186) — SOAR playbook content pack: the out-of-box incident-response playbooks a fresh tenant gets.
-- Global (tenant_id NULL) INERT TEMPLATES. Seeding a playbook does NOT arm anything — verified safety model
-- (soar/service.go:68 "nothing auto-runs"): a run exists only when a principal explicitly calls Run/RunForTarget;
-- resolveDecision fail-closes to 'observe'; every destructive step lands in pending_approval and needs a senior
-- Approve; real vendor actioners (Defender isolate, Entra disable — slices B/C) engage only under the tenant's
-- destructive_enabled + supervisor, else truthful-simulate. trigger_category is for discovery/authoring only and
-- does not cause auto-run.
--
-- INVARIANT — every step's `action` MUST be a key present in soar_action_catalog (seeded in 0036): an uncatalogued
-- action fails closed to 'business_critical' (max approval) and can never run — a silently-broken template. All 19
-- actions used below are catalog keys (enrich, add_watchlist, mark_email_review, notify_analyst, notify_customer,
-- create_ticket, create_note, inspect_mailbox, collect_evidence, quarantine_email, mass_quarantine, block_ip,
-- block_domain, block_hash, isolate_endpoint, revoke_sessions, reset_password, disable_user, network_block_all).
-- A CI fence (check-playbook-actions-cataloged.sh) asserts this for all current + future seeded content.
-- connector_key on each step matches the catalog's executor connector (entra-id / defender / microsoft-365; empty
-- for internal actions). Low-risk enrich/notify/ticket steps requires_approval=false; contain/disrupt steps
-- requires_approval=true. Idempotent by anti-join on (tenant_id IS NULL, name); the 0004 compromised-account
-- playbook is left untouched.

INSERT INTO playbooks (id, tenant_id, name, description, trigger_category, steps, enabled)
SELECT gen_random_uuid(), NULL, v.name, v.description, v.trigger_category, v.steps::jsonb, true
FROM (VALUES
  ('Phishing email response',
   'Triage a reported/detected phishing email, then contain the sender and message under authority-to-act.',
   'email',
   '[{"name":"Enrich sender, URLs & attachments","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Add IOCs to watchlist","connector_key":"","action":"add_watchlist","risk":"low","requires_approval":false},
     {"name":"Flag message for analyst review","connector_key":"microsoft-365","action":"mark_email_review","risk":"low","requires_approval":false},
     {"name":"Notify SOC analyst","connector_key":"","action":"notify_analyst","risk":"low","requires_approval":false},
     {"name":"Quarantine the malicious email","connector_key":"microsoft-365","action":"quarantine_email","risk":"high","requires_approval":true},
     {"name":"Block sender domain","connector_key":"defender","action":"block_domain","risk":"high","requires_approval":true}]'),

  ('Malware on endpoint — isolate & contain',
   'Contain a malware detection on a host: collect evidence, block the payload, isolate the endpoint.',
   'malware',
   '[{"name":"Enrich file hash & host","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Collect forensic evidence","connector_key":"","action":"collect_evidence","risk":"low","requires_approval":false},
     {"name":"Notify SOC analyst","connector_key":"","action":"notify_analyst","risk":"low","requires_approval":false},
     {"name":"Block malicious file hash","connector_key":"defender","action":"block_hash","risk":"high","requires_approval":true},
     {"name":"Isolate the endpoint","connector_key":"defender","action":"isolate_endpoint","risk":"high","requires_approval":true}]'),

  ('Brute-force / password-spray response',
   'Respond to a credential brute-force against one or more identities: block the source and cut live access.',
   'identity',
   '[{"name":"Enrich source IP & targeted users","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Notify SOC analyst","connector_key":"","action":"notify_analyst","risk":"low","requires_approval":false},
     {"name":"Block the source IP","connector_key":"defender","action":"block_ip","risk":"high","requires_approval":true},
     {"name":"Revoke user sessions","connector_key":"entra-id","action":"revoke_sessions","risk":"high","requires_approval":true},
     {"name":"Force password reset","connector_key":"entra-id","action":"reset_password","risk":"medium","requires_approval":true}]'),

  ('Data exfiltration response',
   'Investigate and contain suspected data exfiltration: preserve evidence, block the destination, disable the actor.',
   'exfiltration',
   '[{"name":"Enrich destination & data volume","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Collect evidence","connector_key":"","action":"collect_evidence","risk":"low","requires_approval":false},
     {"name":"Open incident ticket","connector_key":"","action":"create_ticket","risk":"low","requires_approval":false},
     {"name":"Notify customer contact","connector_key":"","action":"notify_customer","risk":"low","requires_approval":false},
     {"name":"Block destination domain","connector_key":"defender","action":"block_domain","risk":"high","requires_approval":true},
     {"name":"Disable the exfiltrating account","connector_key":"entra-id","action":"disable_user","risk":"high","requires_approval":true}]'),

  ('Ransomware early-stage containment',
   'Contain an early-stage ransomware indication: isolate the host and limit blast radius. Network-wide actions '
   || 'stay senior-gated (business-critical) by design.',
   'ransomware',
   '[{"name":"Enrich indicators","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Collect evidence","connector_key":"","action":"collect_evidence","risk":"low","requires_approval":false},
     {"name":"Notify SOC analyst","connector_key":"","action":"notify_analyst","risk":"low","requires_approval":false},
     {"name":"Isolate the endpoint","connector_key":"defender","action":"isolate_endpoint","risk":"high","requires_approval":true},
     {"name":"Mass-quarantine affected mailboxes","connector_key":"microsoft-365","action":"mass_quarantine","risk":"high","requires_approval":true},
     {"name":"Network-wide block (senior-gated)","connector_key":"","action":"network_block_all","risk":"business_critical","requires_approval":true}]'),

  ('Insider risk / account misuse',
   'Investigate suspected insider misuse of an identity, then cut access under approval.',
   'insider',
   '[{"name":"Enrich user activity","connector_key":"","action":"enrich","risk":"informational","requires_approval":false},
     {"name":"Inspect mailbox rules & OAuth grants","connector_key":"microsoft-365","action":"inspect_mailbox","risk":"low","requires_approval":false},
     {"name":"Add internal case note","connector_key":"","action":"create_note","risk":"informational","requires_approval":false},
     {"name":"Notify SOC analyst","connector_key":"","action":"notify_analyst","risk":"low","requires_approval":false},
     {"name":"Revoke user sessions","connector_key":"entra-id","action":"revoke_sessions","risk":"high","requires_approval":true},
     {"name":"Disable the account","connector_key":"entra-id","action":"disable_user","risk":"high","requires_approval":true}]')
) AS v(name, description, trigger_category, steps)
WHERE NOT EXISTS (
  SELECT 1 FROM playbooks p WHERE p.tenant_id IS NULL AND p.name = v.name
);
