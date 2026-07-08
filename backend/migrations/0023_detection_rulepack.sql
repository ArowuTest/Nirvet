-- Baseline detection rule-pack expansion (SRS §6.6; doc 04 §6). Broadens the global
-- catalogue's ATT&CK coverage so a fresh tenant has meaningful out-of-box detection
-- across more tactics (execution, privilege escalation, defense evasion, exfiltration,
-- persistence, account manipulation). These are global (tenant_id NULL, applicable to
-- all tenants); tenants may still add their own via native/Sigma/CEL rules. Inserted
-- by the migrator (superuser, bypasses RLS) so the NULL-tenant rows commit.

INSERT INTO detection_rules (id, tenant_id, name, description, severity, confidence, mitre, condition) VALUES
 (gen_random_uuid(), NULL, 'Suspicious script execution',
  'Encoded/obfuscated PowerShell or script interpreter activity (execution).', 'high', 75, ARRAY['T1059'],
  '{"any":[{"field":"activity_name","op":"contains","value":"powershell"},{"field":"activity_name","op":"contains","value":"encoded command"},{"field":"activity_name","op":"contains","value":"cmd.exe"},{"field":"class_name","op":"contains","value":"script"}]}'),

 (gen_random_uuid(), NULL, 'Privilege escalation',
  'Elevation of privileges or exploitation of a privileged process (TA0004).', 'high', 75, ARRAY['TA0004'],
  '{"any":[{"field":"class_name","op":"contains","value":"privilege"},{"field":"activity_name","op":"contains","value":"elevation"},{"field":"activity_name","op":"contains","value":"escalation"},{"field":"activity_name","op":"contains","value":"uac bypass"}]}'),

 (gen_random_uuid(), NULL, 'Defense evasion: log cleared',
  'Audit/event log cleared or tampered — anti-forensics (T1070).', 'high', 80, ARRAY['T1070'],
  '{"any":[{"field":"activity_name","op":"contains","value":"log cleared"},{"field":"activity_name","op":"contains","value":"log_cleared"},{"field":"action","op":"eq","value":"clear_log"},{"field":"class_name","op":"contains","value":"log tamper"}]}'),

 (gen_random_uuid(), NULL, 'Data exfiltration',
  'Large or anomalous outbound data transfer to an external destination (TA0010).', 'high', 70, ARRAY['TA0010'],
  '{"any":[{"field":"action","op":"contains","value":"exfil"},{"field":"class_name","op":"contains","value":"exfiltration"},{"field":"outcome","op":"eq","value":"data_exfiltration"}]}'),

 (gen_random_uuid(), NULL, 'Persistence mechanism established',
  'Scheduled task, run key, or service created for persistence (TA0003).', 'medium', 65, ARRAY['TA0003'],
  '{"any":[{"field":"class_name","op":"contains","value":"persistence"},{"field":"activity_name","op":"contains","value":"scheduled task"},{"field":"activity_name","op":"contains","value":"run key"},{"field":"activity_name","op":"contains","value":"new service"}]}'),

 (gen_random_uuid(), NULL, 'Privileged account manipulation',
  'Account added to an administrative/privileged group or role (T1098).', 'high', 70, ARRAY['T1098'],
  '{"any":[{"field":"activity_name","op":"contains","value":"added to admin"},{"field":"activity_name","op":"contains","value":"privileged group"},{"field":"activity_name","op":"contains","value":"role assignment"},{"field":"class_name","op":"contains","value":"account manipulation"}]}');
