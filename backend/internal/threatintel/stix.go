package threatintel

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StixObject is a STIX 2.1 object (SDO / SRO / SCO) held in the intel store. It is the real threat-intel
// model behind the flat watchlist (Indicator): typed id, versioning by (id, modified), confidence,
// revocation, validity window, kill-chain / ATT&CK external references, TLP, and the full raw body.
type StixObject struct {
	ID                 string          `json:"id"`                  // STIX id: `type--uuid`
	TenantID           *uuid.UUID      `json:"tenant_id,omitempty"` // nil = global shared feed
	Type               string          `json:"type"`
	SpecVersion        string          `json:"spec_version"`
	Created            time.Time       `json:"created"`
	Modified           time.Time       `json:"modified"`
	Confidence         int             `json:"confidence"`
	Revoked            bool            `json:"revoked"`
	ValidFrom          *time.Time      `json:"valid_from,omitempty"`
	ValidUntil         *time.Time      `json:"valid_until,omitempty"`
	Pattern            string          `json:"pattern,omitempty"`
	PatternType        string          `json:"pattern_type,omitempty"`
	Labels             []string        `json:"labels"`
	ExternalReferences json.RawMessage `json:"external_references,omitempty"`
	KillChainPhases    []string        `json:"kill_chain_phases"`
	TLP                string          `json:"tlp"`
	Source             string          `json:"source"`
	Value              string          `json:"value,omitempty"` // extracted observable for matching
	Raw                json.RawMessage `json:"raw,omitempty"`
}

// stixObservable is the slim projection the enricher matches on (loaded into the per-tenant cache), so
// enrichment never carries the full object body per event. Slice B adds the pattern (multi-value
// expansion) and the age inputs (valid_from/created) the decay curve needs.
type stixObservable struct {
	ID         string
	Type       string
	Value      string
	Pattern    string
	Confidence int
	TLP        string
	Labels     []string
	KillChain  []string
	ValidFrom  *time.Time
	Created    time.Time
}

// knownStixTypes mirrors the DB CHECK (0041): the SDO/SRO/SCO types the store accepts.
var knownStixTypes = map[string]bool{
	"indicator": true, "malware": true, "attack-pattern": true, "threat-actor": true,
	"intrusion-set": true, "campaign": true, "tool": true, "vulnerability": true,
	"infrastructure": true, "course-of-action": true, "identity": true, "report": true,
	"observed-data": true, "note": true, "malware-analysis": true, "grouping": true,
	"location": true, "incident": true, "opinion": true,
	"relationship": true, "sighting": true,
	"ipv4-addr": true, "ipv6-addr": true, "domain-name": true, "url": true, "file": true,
	"email-addr": true, "email-message": true, "user-account": true, "mac-addr": true,
	"autonomous-system": true, "x509-certificate": true, "windows-registry-key": true,
}

// validStixType reports whether t is a STIX type the store persists.
func validStixType(t string) bool { return knownStixTypes[t] }

// scoTypes are cyber-observable types whose observable value lives in raw.value (used directly as an IOC).
var scoTypes = map[string]bool{
	"ipv4-addr": true, "ipv6-addr": true, "domain-name": true, "url": true,
	"email-addr": true, "mac-addr": true,
}

// patternValueRe extracts the compared literal from a STIX comparison, e.g.
//
//	[ipv4-addr:value = '1.2.3.4']       -> 1.2.3.4
//	[file:hashes.'SHA-256' = 'abc...']  -> abc...   (value after '=', not the property key)
//
// Slice A extracts the FIRST comparison's value; compound boolean patterns keep the first observable
// (deferred: full STIX patterning grammar — logged, not silently dropped, by the caller).
var patternValueRe = regexp.MustCompile(`=\s*'([^']*)'`)

// extractPatternValues returns EVERY quoted literal compared with '=' across all AND/OR branches of a
// STIX pattern, trimmed and de-duplicated in first-seen order (slice B):
//
//	[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']  -> ["1.2.3.4","5.6.7.8"]
//	[file:hashes.'SHA-256' = 'abc' AND file:name = 'x']           -> ["abc","x"]
//
// so a compound indicator matches an event carrying any of its observables (slice A kept only the first).
func extractPatternValues(pattern string) []string {
	ms := patternValueRe.FindAllStringSubmatch(pattern, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		v := strings.TrimSpace(m[1])
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// extractObservable computes the PRIMARY matchable value stored in the value column (display/back-compat):
// the first pattern literal for an indicator, or raw.value for a cyber-observable. The enricher expands
// the full pattern (extractPatternValues) for matching.
func extractObservable(typ, pattern string, raw json.RawMessage) string {
	if typ == "indicator" && pattern != "" {
		if vs := extractPatternValues(pattern); len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	if scoTypes[typ] && len(raw) > 0 {
		var probe struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(raw, &probe) == nil {
			return strings.TrimSpace(probe.Value)
		}
	}
	return ""
}

// observableValues returns ALL matchable IOC literals for an object: every pattern literal for an
// indicator, else the single already-extracted SCO value.
func observableValues(typ, pattern, value string) []string {
	if typ == "indicator" && pattern != "" {
		return extractPatternValues(pattern)
	}
	if value != "" {
		return []string{value}
	}
	return nil
}

// UpsertStix inserts or version-updates a STIX object within the tenant, returning applied=true when the
// row was written. Two idempotency modes:
//   - versioned (Modified is set): overwrite only when the incoming `modified` is strictly newer — the
//     STIX version rule; a re-import of the same version is skipped.
//   - unversioned (Modified is zero — an immutable SCO or a feed with no version stamp): insert-only, so
//     a re-import of the same id is a no-op. `created`/`modified` are stamped now() at first insert.
//
// RLS WITH CHECK constrains writes to the tenant's own rows.
func (r *Repository) UpsertStix(ctx context.Context, tenantID uuid.UUID, o *StixObject) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		extRefs := o.ExternalReferences
		if len(extRefs) == 0 {
			extRefs = json.RawMessage(`[]`)
		}
		raw := o.Raw
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		labels := o.Labels
		if labels == nil {
			labels = []string{}
		}
		phases := o.KillChainPhases
		if phases == nil {
			phases = []string{}
		}

		var conflict string // the ON CONFLICT clause differs per idempotency mode
		created, modified := o.Created, o.Modified
		// Round-5 H3: conflict on the per-tenant composite (NULL tenant → sentinel), so each tenant
		// upserts into ITS OWN copy of an id and can never collide with another tenant's row.
		const conflictTarget = `(COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), id)`
		if modified.IsZero() {
			// Unversioned: never overwrite; stamp now() so the stored timestamps stay sane.
			now := time.Now().UTC()
			created, modified = now, now
			conflict = `ON CONFLICT ` + conflictTarget + ` DO NOTHING`
		} else {
			// Versioned: overwrite only a strictly-older stored version.
			conflict = `ON CONFLICT ` + conflictTarget + ` DO UPDATE SET
			   type=EXCLUDED.type, spec_version=EXCLUDED.spec_version, modified=EXCLUDED.modified,
			   confidence=EXCLUDED.confidence, revoked=EXCLUDED.revoked, valid_from=EXCLUDED.valid_from,
			   valid_until=EXCLUDED.valid_until, pattern=EXCLUDED.pattern, pattern_type=EXCLUDED.pattern_type,
			   labels=EXCLUDED.labels, external_references=EXCLUDED.external_references,
			   kill_chain_phases=EXCLUDED.kill_chain_phases, tlp=EXCLUDED.tlp, source=EXCLUDED.source,
			   value=EXCLUDED.value, raw=EXCLUDED.raw, updated_at=now()
			 WHERE stix_objects.modified < EXCLUDED.modified`
		}

		var dummy string
		err := tx.QueryRow(ctx,
			`INSERT INTO stix_objects
			   (id, tenant_id, type, spec_version, created, modified, confidence, revoked,
			    valid_from, valid_until, pattern, pattern_type, labels, external_references,
			    kill_chain_phases, tlp, source, value, raw)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			 `+conflict+`
			 RETURNING id`,
			o.ID, tenantID, o.Type, o.SpecVersion, created, modified, o.Confidence, o.Revoked,
			o.ValidFrom, o.ValidUntil, o.Pattern, o.PatternType, labels, extRefs,
			phases, o.TLP, o.Source, o.Value, raw,
		).Scan(&dummy)
		if err == pgx.ErrNoRows {
			// Conflict with an equal-or-newer version (or DO NOTHING) → no row returned → not applied.
			return nil
		}
		if err != nil {
			return err
		}
		applied = true
		return nil
	})
	return applied, err
}

// ListStix returns global + own objects, newest-modified first, optionally filtered by type.
func (r *Repository) ListStix(ctx context.Context, tenantID uuid.UUID, typeFilter string, limit int) ([]StixObject, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []StixObject
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, type, spec_version, created, modified, confidence, revoked,
			        valid_from, valid_until, pattern, pattern_type, labels, external_references,
			        kill_chain_phases, tlp, source, value, raw
			   FROM stix_objects
			  WHERE ($1 = '' OR type = $1)
			  ORDER BY modified DESC LIMIT $2`, typeFilter, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, err := scanStix(rows)
			if err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// GetStix returns a single object (global or own) by id.
func (r *Repository) GetStix(ctx context.Context, tenantID uuid.UUID, id string) (*StixObject, error) {
	var o StixObject
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// With per-tenant copies (R5-H3) a tenant may see both its own row and a global row with the
		// same id; prefer the tenant's own copy deterministically.
		row := tx.QueryRow(ctx,
			`SELECT id, tenant_id, type, spec_version, created, modified, confidence, revoked,
			        valid_from, valid_until, pattern, pattern_type, labels, external_references,
			        kill_chain_phases, tlp, source, value, raw
			   FROM stix_objects WHERE id=$1
			  ORDER BY (tenant_id IS NOT NULL) DESC LIMIT 1`, id)
		var e error
		o, e = scanStix(row)
		return e
	})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// matchableObservables loads the slim, live (not revoked, not expired) observable set — global + own —
// for the enricher cache. Ordered so nothing depends on insertion order.
func (r *Repository) matchableObservables(ctx context.Context, tenantID uuid.UUID) ([]stixObservable, error) {
	var out []stixObservable
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, type, value, pattern, confidence, tlp, labels, kill_chain_phases, valid_from, created
			   FROM stix_objects
			  WHERE value <> '' AND NOT revoked
			    AND (valid_until IS NULL OR valid_until > now())
			    AND (valid_from  IS NULL OR valid_from  <= now())`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o stixObservable
			if err := rows.Scan(&o.ID, &o.Type, &o.Value, &o.Pattern, &o.Confidence, &o.TLP, &o.Labels, &o.KillChain, &o.ValidFrom, &o.Created); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// sightingCounts sums each sighting SRO's `count` (default 1) by the object it corroborates
// (sighting_of_ref), read from the raw body — the corroboration signal folded into effective
// confidence (slice B). Non-revoked sightings only.
func (r *Repository) sightingCounts(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	out := map[string]int{}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT raw FROM stix_objects WHERE type='sighting' AND NOT revoked`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var s struct {
				SightingOfRef string `json:"sighting_of_ref"`
				Count         int    `json:"count"`
			}
			if json.Unmarshal(raw, &s) != nil || s.SightingOfRef == "" {
				continue
			}
			c := s.Count
			if c <= 0 {
				c = 1
			}
			out[s.SightingOfRef] += c
		}
		return rows.Err()
	})
	return out, err
}

// GetTISettings returns the tenant's threat-intel tuning, or the seeded defaults when no row exists.
func (r *Repository) GetTISettings(ctx context.Context, tenantID uuid.UUID) (TISettings, error) {
	s := DefaultTISettings()
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT decay_half_life_days, min_effective_confidence, sighting_boost_cap
			   FROM threat_intel_settings WHERE tenant_id=$1`, tenantID).
			Scan(&s.DecayHalfLifeDays, &s.MinEffectiveConfidence, &s.SightingBoostCap)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return s, err
}

// SetTISettings upserts the tenant's threat-intel tuning.
func (r *Repository) SetTISettings(ctx context.Context, tenantID uuid.UUID, s TISettings) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO threat_intel_settings (tenant_id, decay_half_life_days, min_effective_confidence, sighting_boost_cap, updated_at)
			 VALUES ($1,$2,$3,$4, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   decay_half_life_days=$2, min_effective_confidence=$3, sighting_boost_cap=$4, updated_at=now()`,
			tenantID, s.DecayHalfLifeDays, s.MinEffectiveConfidence, s.SightingBoostCap)
		return err
	})
}

func scanStix(row pgx.Row) (StixObject, error) {
	var o StixObject
	var extRefs, raw []byte
	if err := row.Scan(&o.ID, &o.TenantID, &o.Type, &o.SpecVersion, &o.Created, &o.Modified,
		&o.Confidence, &o.Revoked, &o.ValidFrom, &o.ValidUntil, &o.Pattern, &o.PatternType,
		&o.Labels, &extRefs, &o.KillChainPhases, &o.TLP, &o.Source, &o.Value, &raw); err != nil {
		return o, err
	}
	o.ExternalReferences = json.RawMessage(extRefs)
	o.Raw = json.RawMessage(raw)
	return o, nil
}
