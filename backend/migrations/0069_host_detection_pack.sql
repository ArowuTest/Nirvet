-- §6.6/§6.5 #118 H-2 — seed host-telemetry detection pack. Global (tenant_id NULL) rules, ATT&CK-mapped, that fire
-- on the canonical §6.5 host field groups produced by the osquery/Wazuh normalizers (data.process.cmdline,
-- data.file.path, class_name = OCSF class). stage defaults to 'production' + enabled true, so these are active on
-- ingest exactly like the existing rule pack; a tenant may disable or override them (DET-004). Seeded from the
-- public osquery/Wazuh/SigmaHQ patterns named in the gate. Idempotent by name.

INSERT INTO detection_rules (id, tenant_id, name, description, severity, confidence, mitre, condition) VALUES
 (gen_random_uuid(), NULL, 'Host: ingress tool transfer',
  'A process on a monitored host invoked a download utility (curl/wget/certutil) — possible tool ingress (host telemetry).',
  'high', 70, ARRAY['T1105'],
  '{"all":[{"field":"class_name","op":"eq","value":"Process Activity"}],"any":[{"field":"data.process.cmdline","op":"contains","value":"curl "},{"field":"data.process.cmdline","op":"contains","value":"wget "},{"field":"data.process.cmdline","op":"contains","value":"certutil"}]}'),

 (gen_random_uuid(), NULL, 'Host: persistence via startup location',
  'A file was written to a persistence location (cron/systemd/LaunchDaemons/Startup) — possible persistence (host telemetry).',
  'high', 65, ARRAY['T1053','T1543'],
  '{"all":[{"field":"class_name","op":"eq","value":"File System Activity"}],"any":[{"field":"data.file.path","op":"contains","value":"/etc/cron"},{"field":"data.file.path","op":"contains","value":"/etc/systemd/system"},{"field":"data.file.path","op":"contains","value":"/Library/LaunchDaemons"},{"field":"data.file.path","op":"contains","value":"\\Start Menu\\Programs\\Startup"}]}'),

 (gen_random_uuid(), NULL, 'Host: sensitive credential file access',
  'A monitored host touched a credential-bearing file (/etc/shadow, SSH keys, cloud creds) — possible credential access (host telemetry).',
  'high', 70, ARRAY['T1003','T1552'],
  '{"all":[{"field":"class_name","op":"eq","value":"File System Activity"}],"any":[{"field":"data.file.path","op":"contains","value":"/etc/shadow"},{"field":"data.file.path","op":"contains","value":"/etc/passwd"},{"field":"data.file.path","op":"contains","value":".ssh/id_"},{"field":"data.file.path","op":"contains","value":".aws/credentials"}]}'),

 (gen_random_uuid(), NULL, 'Host: repeated failed authentication',
  'A failed authentication on a monitored host — a single event is low signal but correlates into brute-force (host telemetry).',
  'medium', 60, ARRAY['T1110'],
  '{"all":[{"field":"class_name","op":"eq","value":"Authentication"},{"field":"outcome","op":"eq","value":"failure"}]}')
ON CONFLICT DO NOTHING;
