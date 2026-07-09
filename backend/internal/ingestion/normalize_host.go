package ingestion

// §6.5 #118 H-1 — host-telemetry normalizers (osquery + Wazuh). Each maps a raw host event to one of the four OCSF
// classes and populates the canonical §6.5 field groups (hostfields.go), so a seeded host detection pack and the
// existing detection/correlation pipeline work off canonical fields regardless of which open agent produced them.
// Best-effort like the other 8 vendor mappers: unknown shapes fall through to a generic Host Activity (a still-empty
// class_name is the normalization-drift signal the quality scorer already tracks).

import (
	"strconv"
	"strings"
)

func orDefault(cur, def string) string {
	if cur == "" {
		return def
	}
	return cur
}

// severityFromWazuh maps a Wazuh rule level (0–15) to the canonical severity.
func severityFromWazuh(n float64) string {
	switch {
	case n >= 12:
		return "critical"
	case n >= 9:
		return "high"
	case n >= 6:
		return "medium"
	case n >= 3:
		return "low"
	default:
		return "informational"
	}
}

// normalizeOsquery maps an osquery result-log row. Shape: {name, hostIdentifier, action, columns:{...}} (columns may
// be flattened to the top level by some log plugins). The query name selects the OCSF class.
func normalizeOsquery(in *IngestInput) {
	host := firstStr(in.Data, "hostIdentifier", "host_identifier", "host")
	name := strings.ToLower(firstStr(in.Data, "name", "query_name"))
	action := firstStr(in.Data, "action")
	cols, _ := in.Data["columns"].(map[string]any)
	if cols == nil {
		cols = in.Data // flattened log format
	}
	if host == "" {
		host = firstStr(cols, "hostname", "host")
	}
	if in.TargetRef == "" && host != "" {
		in.TargetRef = "host:" + host
	}
	if in.Action == "" && action != "" {
		in.Action = strings.ToLower(action)
	}
	setFieldGroup(in, FieldGroupHost, map[string]any{"name": host})

	switch {
	case strings.Contains(name, "process"):
		in.ClassName = orDefault(in.ClassName, OCSFProcessActivity)
		user := firstStr(cols, "username", "user")
		setFieldGroup(in, FieldGroupProcess, map[string]any{
			"name":    firstStr(cols, "path", "name"),
			"cmdline": firstStr(cols, "cmdline", "cmd"),
			"pid":     firstStr(cols, "pid"),
			"ppid":    firstStr(cols, "parent", "ppid"),
			"user":    user,
		})
		if in.ActorRef == "" && user != "" {
			in.ActorRef = "user:" + user
		}
	case strings.Contains(name, "file"):
		in.ClassName = orDefault(in.ClassName, OCSFFileSystemActivity)
		setFieldGroup(in, FieldGroupFile, map[string]any{
			"path":   firstStr(cols, "target_path", "path"),
			"action": firstStr(cols, "action"),
			"sha256": firstStr(cols, "sha256"),
			"user":   firstStr(cols, "username"),
		})
	case strings.Contains(name, "socket"), strings.Contains(name, "connection"), strings.Contains(name, "network"), strings.Contains(name, "dns"):
		in.ClassName = orDefault(in.ClassName, OCSFNetworkActivity)
		setFieldGroup(in, FieldGroupNetwork, map[string]any{
			"dst_ip":   firstStr(cols, "remote_address", "remote_ip"),
			"dst_port": firstStr(cols, "remote_port"),
			"src_ip":   firstStr(cols, "local_address", "local_ip"),
			"src_port": firstStr(cols, "local_port"),
			"protocol": firstStr(cols, "protocol"),
			"pid":      firstStr(cols, "pid"),
		})
	case strings.Contains(name, "logged_in"), strings.Contains(name, "login"), strings.Contains(name, "logon"), strings.Contains(name, "user"), strings.Contains(name, "last"), strings.Contains(name, "auth"):
		in.ClassName = orDefault(in.ClassName, OCSFAuthentication)
		user := firstStr(cols, "user", "username")
		setFieldGroup(in, FieldGroupUser, map[string]any{"name": user})
		if in.ActorRef == "" && user != "" {
			in.ActorRef = "user:" + user
		}
		if src := firstStr(cols, "host", "remote_address"); src != "" {
			setFieldGroup(in, FieldGroupNetwork, map[string]any{"src_ip": src})
		}
	default:
		in.ClassName = orDefault(in.ClassName, OCSFHostActivity)
		if name != "" {
			in.ActivityName = orDefault(in.ActivityName, name)
		}
	}
}

// normalizeWazuh maps a Wazuh alert JSON: {agent:{name}, rule:{level, description, groups[], mitre:{id[]}}, data:{...},
// syscheck:{...}}. Rule groups select the OCSF class; the manager itself is the in-scope §321-326 adjacent collector.
func normalizeWazuh(in *IngestInput) {
	host := nestedStr(in.Data, "agent", "name")
	if host == "" {
		host = firstStr(in.Data, "manager", "hostname")
	}
	if in.TargetRef == "" && host != "" {
		in.TargetRef = "host:" + host
	}
	setFieldGroup(in, FieldGroupHost, map[string]any{"name": host})

	rule, _ := in.Data["rule"].(map[string]any)
	data, _ := in.Data["data"].(map[string]any)
	desc := ""
	var groups []string
	if rule != nil {
		desc = firstStr(rule, "description")
		if in.Severity == "" {
			if lvl, ok := wazuhLevel(rule); ok {
				in.Severity = severityFromWazuh(lvl)
			}
		}
		if g, ok := rule["groups"].([]any); ok {
			for _, x := range g {
				if s, ok := x.(string); ok {
					groups = append(groups, strings.ToLower(s))
				}
			}
		}
		if m, ok := rule["mitre"].(map[string]any); ok {
			if ids, ok := m["id"].([]any); ok {
				var techs []string
				for _, t := range ids {
					if s, ok := t.(string); ok && s != "" {
						techs = append(techs, s)
					}
				}
				if len(techs) > 0 {
					in.Data["mitre"] = techs
				}
			}
		}
	}
	hasGroup := func(sub string) bool {
		for _, g := range groups {
			if strings.Contains(g, sub) {
				return true
			}
		}
		return false
	}

	switch {
	case in.Data["syscheck"] != nil || hasGroup("syscheck"):
		in.ClassName = orDefault(in.ClassName, OCSFFileSystemActivity)
		if sc, ok := in.Data["syscheck"].(map[string]any); ok {
			setFieldGroup(in, FieldGroupFile, map[string]any{
				"path":   firstStr(sc, "path"),
				"action": firstStr(sc, "event"),
				"sha256": firstStr(sc, "sha256_after", "sha256"),
			})
		}
	case hasGroup("authentication"), hasGroup("auth"):
		in.ClassName = orDefault(in.ClassName, OCSFAuthentication)
		user := firstStr(data, "dstuser", "srcuser", "user")
		setFieldGroup(in, FieldGroupUser, map[string]any{"name": user})
		if in.ActorRef == "" && user != "" {
			in.ActorRef = "user:" + user
		}
		if src := firstStr(data, "srcip", "src_ip"); src != "" {
			setFieldGroup(in, FieldGroupNetwork, map[string]any{"src_ip": src})
		}
		if in.Outcome == "" {
			switch {
			case hasGroup("failed"):
				in.Outcome = "failure"
			case hasGroup("success"):
				in.Outcome = "success"
			}
		}
	case hasGroup("process"), hasGroup("exec"):
		in.ClassName = orDefault(in.ClassName, OCSFProcessActivity)
		user := firstStr(data, "user", "srcuser")
		setFieldGroup(in, FieldGroupProcess, map[string]any{
			"name":    firstStr(data, "process", "exe", "command"),
			"cmdline": firstStr(data, "command", "cmdline"),
			"pid":     firstStr(data, "pid"),
			"user":    user,
		})
		if in.ActorRef == "" && user != "" {
			in.ActorRef = "user:" + user
		}
	case hasGroup("firewall"), hasGroup("network"), hasGroup("connection"), hasGroup("ids"):
		in.ClassName = orDefault(in.ClassName, OCSFNetworkActivity)
		setFieldGroup(in, FieldGroupNetwork, map[string]any{
			"src_ip":   firstStr(data, "srcip", "src_ip"),
			"dst_ip":   firstStr(data, "dstip", "dst_ip"),
			"dst_port": firstStr(data, "dstport", "dst_port"),
			"protocol": firstStr(data, "protocol"),
		})
	default:
		in.ClassName = orDefault(in.ClassName, OCSFHostActivity)
	}
	if in.ActivityName == "" && desc != "" {
		in.ActivityName = desc
	}
}

// wazuhLevel reads rule.level whether encoded as a JSON number or a string.
func wazuhLevel(rule map[string]any) (float64, bool) {
	if n, ok := firstNum(rule, "level"); ok {
		return n, true
	}
	if s := firstStr(rule, "level"); s != "" {
		if n, err := strconv.ParseFloat(s, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}
