package ingestion

// §6.5 #118 H-1 — host normalizer unit tests: the four OCSF classes round-trip for both osquery and Wazuh, populate
// the §6.5 field groups, and set the backbone (host target, user actor, severity, mitre). Pure, no DB.

import "testing"

func group(t *testing.T, in *IngestInput, key string) map[string]any {
	t.Helper()
	g, ok := in.Data[key].(map[string]any)
	if !ok {
		t.Fatalf("expected field group %q, got %T", key, in.Data[key])
	}
	return g
}

func TestNormalizeOsquery_Process(t *testing.T) {
	in := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "process_events", "hostIdentifier": "web-01", "action": "added",
		"columns": map[string]any{"pid": "4123", "path": "/usr/bin/curl", "cmdline": "curl http://evil", "parent": "4000", "username": "root"},
	}}
	normalizeOsquery(in)
	if in.ClassName != OCSFProcessActivity {
		t.Fatalf("class = %q", in.ClassName)
	}
	if in.TargetRef != "host:web-01" || in.ActorRef != "user:root" {
		t.Fatalf("backbone target=%q actor=%q", in.TargetRef, in.ActorRef)
	}
	p := group(t, in, FieldGroupProcess)
	if p["cmdline"] != "curl http://evil" || p["pid"] != "4123" || p["ppid"] != "4000" {
		t.Fatalf("process group = %v", p)
	}
}

func TestNormalizeOsquery_File(t *testing.T) {
	in := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "file_events", "hostIdentifier": "web-01",
		"columns": map[string]any{"target_path": "/etc/cron.d/x", "action": "CREATED", "sha256": "abc"},
	}}
	normalizeOsquery(in)
	if in.ClassName != OCSFFileSystemActivity {
		t.Fatalf("class = %q", in.ClassName)
	}
	f := group(t, in, FieldGroupFile)
	if f["path"] != "/etc/cron.d/x" || f["sha256"] != "abc" {
		t.Fatalf("file group = %v", f)
	}
}

func TestNormalizeOsquery_Network(t *testing.T) {
	in := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "socket_events", "hostIdentifier": "web-01",
		"columns": map[string]any{"remote_address": "1.2.3.4", "remote_port": "443", "local_address": "10.0.0.5", "protocol": "6", "pid": "4123"},
	}}
	normalizeOsquery(in)
	if in.ClassName != OCSFNetworkActivity {
		t.Fatalf("class = %q", in.ClassName)
	}
	n := group(t, in, FieldGroupNetwork)
	if n["dst_ip"] != "1.2.3.4" || n["dst_port"] != "443" {
		t.Fatalf("network group = %v", n)
	}
}

func TestNormalizeOsquery_Auth(t *testing.T) {
	in := &IngestInput{Source: "host_osquery", Data: map[string]any{
		"name": "logged_in_users", "hostIdentifier": "web-01",
		"columns": map[string]any{"user": "root", "tty": "pts/0", "host": "1.2.3.4"},
	}}
	normalizeOsquery(in)
	if in.ClassName != OCSFAuthentication || in.ActorRef != "user:root" {
		t.Fatalf("class=%q actor=%q", in.ClassName, in.ActorRef)
	}
}

func TestNormalizeWazuh_FileSyscheck(t *testing.T) {
	in := &IngestInput{Source: "host_wazuh", Data: map[string]any{
		"agent":    map[string]any{"name": "web-01"},
		"rule":     map[string]any{"level": float64(7), "description": "Integrity checksum changed", "groups": []any{"syscheck"}},
		"syscheck": map[string]any{"path": "/etc/passwd", "event": "modified", "sha256_after": "abc"},
	}}
	normalizeWazuh(in)
	if in.ClassName != OCSFFileSystemActivity || in.TargetRef != "host:web-01" || in.Severity != "medium" {
		t.Fatalf("class=%q target=%q sev=%q", in.ClassName, in.TargetRef, in.Severity)
	}
	f := group(t, in, FieldGroupFile)
	if f["path"] != "/etc/passwd" || f["action"] != "modified" {
		t.Fatalf("file group = %v", f)
	}
}

func TestNormalizeWazuh_AuthFailWithMitre(t *testing.T) {
	in := &IngestInput{Source: "host_wazuh", Data: map[string]any{
		"agent": map[string]any{"name": "web-01"},
		"rule":  map[string]any{"level": float64(10), "description": "sshd brute force", "groups": []any{"authentication_failed"}, "mitre": map[string]any{"id": []any{"T1110"}}},
		"data":  map[string]any{"srcuser": "admin", "srcip": "1.2.3.4"},
	}}
	normalizeWazuh(in)
	if in.ClassName != OCSFAuthentication || in.Severity != "high" || in.Outcome != "failure" {
		t.Fatalf("class=%q sev=%q outcome=%q", in.ClassName, in.Severity, in.Outcome)
	}
	if in.ActorRef != "user:admin" {
		t.Fatalf("actor=%q", in.ActorRef)
	}
	m, ok := in.Data["mitre"].([]string)
	if !ok || len(m) != 1 || m[0] != "T1110" {
		t.Fatalf("mitre = %v", in.Data["mitre"])
	}
}
