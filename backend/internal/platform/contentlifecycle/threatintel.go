package contentlifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidSTIXObject = errors.New("content: invalid STIX object")
	ErrExpiredIndicator  = errors.New("content: STIX indicator expired")
)

// STIXObject is the minimal normalized shape required by the existing threat
// intelligence store. Raw retains the verified source object for the adapter.
type STIXObject struct {
	ID         string
	Type       string
	Modified   time.Time
	ValidUntil time.Time
	Raw        json.RawMessage
}

// ThreatIntelStore is implemented by the existing threat-intelligence adapter.
// UpsertSTIX must remain idempotent on the STIX (id, modified) pair.
type ThreatIntelStore interface {
	UpsertSTIX(object STIXObject) error
}

// ApplyThreatIntel normalizes a verified threat-intel pack and sends each unique
// (id, modified) object to the existing store. No parallel TI store is created.
func ApplyThreatIntel(pack VerifiedPack, now time.Time, store ThreatIntelStore) error {
	if pack.Manifest.ContentType != "threat_intel" {
		return fmt.Errorf("%w: expected threat_intel", ErrUnsupportedType)
	}
	if store == nil {
		return errors.New("content: threat-intelligence store unavailable")
	}

	seen := make(map[string]struct{}, len(pack.Artifacts))
	objects := make([]STIXObject, 0, len(pack.Artifacts))
	for _, artifact := range pack.Artifacts {
		var raw struct {
			ID         string    `json:"id"`
			Type       string    `json:"type"`
			Modified   time.Time `json:"modified"`
			ValidUntil time.Time `json:"valid_until,omitempty"`
		}
		if err := json.Unmarshal(artifact.Data, &raw); err != nil || raw.ID == "" || raw.Type == "" || raw.Modified.IsZero() {
			return ErrInvalidSTIXObject
		}
		if !raw.ValidUntil.IsZero() && !raw.ValidUntil.After(now) {
			return fmt.Errorf("%w: %s", ErrExpiredIndicator, raw.ID)
		}
		key := raw.ID + "\x00" + raw.Modified.UTC().Format(time.RFC3339Nano)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		objects = append(objects, STIXObject{
			ID: raw.ID, Type: raw.Type, Modified: raw.Modified,
			ValidUntil: raw.ValidUntil, Raw: append(json.RawMessage(nil), artifact.Data...),
		})
	}

	// Validation is complete before the first write, preserving fail-closed pack
	// semantics for malformed or expired objects.
	for _, object := range objects {
		if err := store.UpsertSTIX(object); err != nil {
			return fmt.Errorf("content: upsert STIX %s: %w", object.ID, err)
		}
	}
	return nil
}
