-- LAUNCH #3 (#186) — detection content pack: the out-of-box identity/Microsoft use-cases a fresh tenant gets.
-- Global (tenant_id NULL) rules, ATT&CK-mapped, over the LAUNCH #1 Entra telemetry (sign-ins / directory audit /
-- risky users) that the poller now ingests. Three use STATEFUL kinds landed in 0106 (DET-002): brute-force and
-- MFA-fatigue are `threshold` (N contributing events for one entity in a window); impossible-travel is `distinct`
-- (N distinct values of a field for one entity in a window). The rest are single-event `simple` rules.
--
-- Field accuracy is verified against the normalizers, NOT guessed — a rule that can never fire manufactures false
-- coverage confidence (worse than no rule):
--   sign-in  → class_name='Authentication', action='signin', outcome in {success,failure}, actor_ref='user:<upn>',
--              data.countryOrRegion, data.clientAppUsed, data.mfaAuthMethod, data.failureReason  (poller.go:177)
--   audit    → class_name='Directory Audit', activity_name=data.activityDisplayName                (poller.go:203)
--   risky    → class_name='Identity Risk',  data.riskLevel                                         (poller.go:223)
-- A companion integration test synthesizes these events and asserts each stateful rule actually fires.
--
-- stage defaults to 'production' + enabled=true (active on ingest, like the 0023/0069 packs); a tenant may disable
-- or override any of them (DET-004 / RLS). Inserted by the migrator (bypasses RLS so NULL-tenant rows commit).
-- Idempotent by an anti-join on (tenant_id IS NULL, name) — no schema change, safe to re-apply.

INSERT INTO detection_rules
  (id, tenant_id, name, description, severity, confidence, mitre, condition,
   kind, window_seconds, threshold, entity_field, distinct_field)
SELECT gen_random_uuid(), NULL, v.name, v.description, v.severity, v.confidence, v.mitre, v.condition::jsonb,
       v.kind, v.window_seconds, v.threshold, v.entity_field, v.distinct_field
FROM (VALUES
  -- ── STATEFUL (DET-002) ──────────────────────────────────────────────────────────────────────────────────
  ('Identity: brute-force / password spray',
   'Repeated failed sign-ins for one identity within 15 minutes — credential brute-force or password spray (T1110). '
   || 'Threshold rule: fires once per user per window.',
   'high', 75, ARRAY['T1110']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Authentication"},{"field":"outcome","op":"eq","value":"failure"}]}',
   'threshold', 900, 10, 'actor_ref', ''),

  ('Identity: MFA fatigue / push bombing',
   'Repeated failed MFA-backed sign-ins for one identity within 10 minutes — MFA fatigue / push bombing (T1621). '
   || 'Threshold rule keyed on the presence of an MFA method on the failed attempt.',
   'high', 70, ARRAY['T1621']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Authentication"},{"field":"outcome","op":"eq","value":"failure"},{"field":"data.mfaAuthMethod","op":"exists","value":""}]}',
   'threshold', 600, 5, 'actor_ref', ''),

  ('Identity: impossible travel',
   'Successful sign-ins for one identity from 2+ distinct countries within an hour — impossible travel, possible '
   || 'account takeover (T1078). Distinct rule over data.countryOrRegion.',
   'high', 70, ARRAY['T1078']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Authentication"},{"field":"outcome","op":"eq","value":"success"}]}',
   'distinct', 3600, 2, 'actor_ref', 'data.countryOrRegion'),

  -- ── SIMPLE (single-event) ───────────────────────────────────────────────────────────────────────────────
  ('Identity Protection: high-risk user',
   'Entra Identity Protection flagged a user at HIGH risk — likely compromised identity (T1078.004).',
   'high', 80, ARRAY['T1078']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Identity Risk"},{"field":"data.riskLevel","op":"eq","value":"high"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: privileged role assignment',
   'A user was added to a privileged directory role — privilege escalation / persistence via role grant (T1098.003).',
   'high', 70, ARRAY['T1098']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Directory Audit"}],"any":[{"field":"activity_name","op":"contains","value":"add member to role"},{"field":"activity_name","op":"contains","value":"add eligible member to role"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: application consent granted',
   'A consent grant to an application — illicit OAuth consent / persistence (T1528).',
   'high', 65, ARRAY['T1528']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Directory Audit"},{"field":"activity_name","op":"contains","value":"consent to application"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: legacy authentication protocol used',
   'A sign-in over a legacy protocol (IMAP/POP/SMTP/MAPI/other clients) that bypasses modern auth / MFA (T1078).',
   'medium', 60, ARRAY['T1078']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Authentication"}],"any":[{"field":"data.clientAppUsed","op":"contains","value":"IMAP"},{"field":"data.clientAppUsed","op":"contains","value":"POP"},{"field":"data.clientAppUsed","op":"contains","value":"SMTP"},{"field":"data.clientAppUsed","op":"contains","value":"MAPI"},{"field":"data.clientAppUsed","op":"contains","value":"Other clients"},{"field":"data.clientAppUsed","op":"contains","value":"ActiveSync"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: sign-in to disabled or blocked account',
   'A failed sign-in whose reason indicates the account is disabled/locked/blocked — probing a dormant identity (T1078).',
   'medium', 55, ARRAY['T1078']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Authentication"},{"field":"outcome","op":"eq","value":"failure"}],"any":[{"field":"data.failureReason","op":"contains","value":"account is disabled"},{"field":"data.failureReason","op":"contains","value":"account is locked"},{"field":"data.failureReason","op":"contains","value":"blocked"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: conditional access policy modified',
   'A conditional-access / security policy was updated or deleted — possible defense evasion by weakening controls (T1556).',
   'high', 70, ARRAY['T1556']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Directory Audit"}],"any":[{"field":"activity_name","op":"contains","value":"conditional access"},{"field":"activity_name","op":"contains","value":"update policy"},{"field":"activity_name","op":"contains","value":"delete policy"}]}',
   'simple', 0, 0, '', ''),

  ('Identity: user authentication method changed',
   'A user''s security info / MFA method was registered or reset — persistence via credential/MFA registration (T1556.006).',
   'medium', 60, ARRAY['T1556']::text[],
   '{"all":[{"field":"class_name","op":"eq","value":"Directory Audit"}],"any":[{"field":"activity_name","op":"contains","value":"security info"},{"field":"activity_name","op":"contains","value":"strong authentication"},{"field":"activity_name","op":"contains","value":"reset password"}]}',
   'simple', 0, 0, '', '')
) AS v(name, description, severity, confidence, mitre, condition, kind, window_seconds, threshold, entity_field, distinct_field)
WHERE NOT EXISTS (
  SELECT 1 FROM detection_rules d WHERE d.tenant_id IS NULL AND d.name = v.name
);
