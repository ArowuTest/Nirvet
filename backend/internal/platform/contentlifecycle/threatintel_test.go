package contentlifecycle

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type recordingTIStore struct {
	objects []STIXObject
	err     error
}

func (s *recordingTIStore) UpsertSTIX(object STIXObject) error {
	if s.err != nil {
		return s.err
	}
	s.objects = append(s.objects, object)
	return nil
}

func tiArtifact(t *testing.T, id, modified, validUntil string) Artifact {
	t.Helper()
	body := map[string]any{"id": id, "type": "indicator", "modified": modified}
	if validUntil != "" {
		body["valid_until"] = validUntil
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return Artifact{ID: id, Kind: "stix", Data: raw}
}

func TestApplyThreatIntel_DeduplicatesIDModifiedPair(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	pack := VerifiedPack{
		Manifest: Manifest{ContentType: "threat_intel"},
		Artifacts: []Artifact{
			tiArtifact(t, "indicator--one", "2026-07-21T00:00:00Z", "2027-01-01T00:00:00Z"),
			tiArtifact(t, "indicator--one", "2026-07-21T00:00:00Z", "2027-01-01T00:00:00Z"),
			tiArtifact(t, "indicator--one", "2026-07-22T00:00:00Z", "2027-01-01T00:00:00Z"),
		},
	}
	store := &recordingTIStore{}
	if err := ApplyThreatIntel(pack, now, store); err != nil {
		t.Fatal(err)
	}
	if len(store.objects) != 2 {
		t.Fatalf("want two unique (id, modified) objects, got %d", len(store.objects))
	}
}

func TestApplyThreatIntel_ValidatesWholePackBeforeWriting(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	pack := VerifiedPack{
		Manifest: Manifest{ContentType: "threat_intel"},
		Artifacts: []Artifact{
			tiArtifact(t, "indicator--valid", "2026-07-21T00:00:00Z", "2027-01-01T00:00:00Z"),
			{ID: "broken", Kind: "stix", Data: []byte(`{"id":""}`)},
		},
	}
	store := &recordingTIStore{}
	if err := ApplyThreatIntel(pack, now, store); !errors.Is(err, ErrInvalidSTIXObject) {
		t.Fatalf("want invalid STIX refusal, got %v", err)
	}
	if len(store.objects) != 0 {
		t.Fatalf("partial threat-intel pack was written: %d objects", len(store.objects))
	}
}

func TestApplyThreatIntel_ExpiredIndicatorRejectedAtomically(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	pack := VerifiedPack{
		Manifest: Manifest{ContentType: "threat_intel"},
		Artifacts: []Artifact{
			tiArtifact(t, "indicator--valid", "2026-07-21T00:00:00Z", "2027-01-01T00:00:00Z"),
			tiArtifact(t, "indicator--expired", "2026-07-20T00:00:00Z", "2026-07-21T00:00:00Z"),
		},
	}
	store := &recordingTIStore{}
	if err := ApplyThreatIntel(pack, now, store); !errors.Is(err, ErrExpiredIndicator) {
		t.Fatalf("want expired indicator refusal, got %v", err)
	}
	if len(store.objects) != 0 {
		t.Fatalf("partial threat-intel pack was written: %d objects", len(store.objects))
	}
}

func TestApplyThreatIntel_StoreFailureFailsClosed(t *testing.T) {
	pack := VerifiedPack{
		Manifest:  Manifest{ContentType: "threat_intel"},
		Artifacts: []Artifact{tiArtifact(t, "indicator--one", "2026-07-21T00:00:00Z", "")},
	}
	store := &recordingTIStore{err: errors.New("store unavailable")}
	if err := ApplyThreatIntel(pack, time.Now(), store); err == nil {
		t.Fatal("store failure must be surfaced")
	}
}
