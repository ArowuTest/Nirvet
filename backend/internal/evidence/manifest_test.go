package evidence

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/google/uuid"
)

// TestManifestChecksums locks the tamper-evidence guarantee: every section is
// checksummed, the manifest is deterministic, and altering any section changes both
// its section checksum and the overall pack checksum.
func TestManifestChecksums(t *testing.T) {
	inc := &incident.Incident{ID: uuid.New(), Title: "case", Severity: "high"}
	p := &Pack{
		Incident: inc,
		Alerts:   []alert.Alert{{ID: uuid.New(), Title: "a1", Severity: "high"}},
	}
	m := buildManifest(p)

	if m.Algorithm != "sha256" {
		t.Fatalf("algorithm = %q, want sha256", m.Algorithm)
	}
	for _, k := range []string{"incident", "timeline", "alerts", "events", "audit"} {
		if m.SectionChecksum[k] == "" {
			t.Fatalf("missing checksum for section %q", k)
		}
	}
	if m.PackChecksum == "" {
		t.Fatal("pack checksum must be set")
	}
	if m.Counts["alerts"] != 1 {
		t.Fatalf("alerts count = %d, want 1", m.Counts["alerts"])
	}

	// Deterministic: recomputing over unchanged data yields identical checksums.
	if buildManifest(p).PackChecksum != m.PackChecksum {
		t.Fatal("manifest must be deterministic for identical content")
	}

	// Tamper: altering the incident changes its section checksum AND the pack checksum.
	inc.Title = "tampered"
	m2 := buildManifest(p)
	if m2.SectionChecksum["incident"] == m.SectionChecksum["incident"] {
		t.Fatal("incident section checksum must change when the incident is altered")
	}
	if m2.PackChecksum == m.PackChecksum {
		t.Fatal("pack checksum must change when any section is altered")
	}
}
