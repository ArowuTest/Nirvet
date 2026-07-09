package ingestion

// §6.5 #118 H-1 — canonical host-telemetry field groups (the SRS §6.5 OCSF design-inclusion recorded in the gate).
// A host event from an open agent (osquery/Wazuh) normalizes to one of four OCSF classes, and its structured
// attributes land in well-known field GROUPS inside the canonical event's Data map — host / process / file / user /
// network — so detection rules reference `process.cmdline`, `file.path`, `network.dst_port`, etc. uniformly across
// every host source, present and future, instead of each vendor's raw column names. class_name carries the OCSF
// class; the backbone fields (TargetRef=host:<name>, ActorRef=user:<name>, Action, Severity) stay as they are for
// the other 8 vendors so the downstream pipeline is unchanged.

// OCSF class names for host telemetry (the canonical class_name; uid noted for reference).
const (
	OCSFProcessActivity    = "Process Activity"     // OCSF class_uid 1007
	OCSFFileSystemActivity = "File System Activity" // OCSF class_uid 1001
	OCSFAuthentication     = "Authentication"       // OCSF class_uid 3002
	OCSFNetworkActivity    = "Network Activity"     // OCSF class_uid 4001
	OCSFHostActivity       = "Host Activity"        // generic fallback for an unclassifiable host event
)

// Canonical §6.5 field-group keys within IngestInput.Data.
const (
	FieldGroupHost    = "host"
	FieldGroupProcess = "process"
	FieldGroupFile    = "file"
	FieldGroupUser    = "user"
	FieldGroupNetwork = "network"
)

// setFieldGroup stores the non-empty subset of fields under Data[group] as the canonical §6.5 field group. Empty
// strings / nil values are dropped so a partial host event does not fabricate empty structure (and normalization
// confidence stays honest). No-op if nothing survives.
func setFieldGroup(in *IngestInput, group string, fields map[string]any) {
	clean := make(map[string]any, len(fields))
	for k, v := range fields {
		switch t := v.(type) {
		case nil:
			continue
		case string:
			if t == "" {
				continue
			}
		}
		clean[k] = v
	}
	if len(clean) == 0 {
		return
	}
	if in.Data == nil {
		in.Data = map[string]any{}
	}
	in.Data[group] = clean
}
