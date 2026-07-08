package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

// Incidents and Alerts are the narrow read dependencies (satisfied by
// incident.Service and alert.Service), keeping evidence decoupled and testable.
type Incidents interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*incident.Incident, error)
	Timeline(ctx context.Context, tenantID, id uuid.UUID) ([]incident.TimelineEntry, error)
}

// Alerts resolves the alerts promoted into an incident.
type Alerts interface {
	ListByIncident(ctx context.Context, tenantID, incidentID uuid.UUID) ([]alert.Alert, error)
}

// Assets resolves inventory assets by their canonical refs (affected-asset context).
type Assets interface {
	FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]asset.Asset, error)
}

// Vulns resolves the open vulnerabilities on a set of asset refs (exposure context).
type Vulns interface {
	FindOpenByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]vulnerability.Vuln, error)
}

// Service assembles evidence packs read-only from the case, alert, event, asset and
// audit stores. Every read is tenant-scoped, so a pack can only ever contain the
// caller's own tenant data.
type Service struct {
	incidents Incidents
	alerts    Alerts
	events    eventstore.EventStore
	assets    Assets
	vulns     Vulns
	db        *database.DB
	signer    ed25519.PrivateKey // signs the pack digest (R2 H-B)
}

// NewService builds the evidence service. signer signs each pack's digest; it must be
// non-nil (main wires a config key or an ephemeral dev key).
func NewService(incidents Incidents, alerts Alerts, events eventstore.EventStore, assets Assets, vulns Vulns, db *database.DB, signer ed25519.PrivateKey) *Service {
	return &Service{incidents: incidents, alerts: alerts, events: events, assets: assets, vulns: vulns, db: db, signer: signer}
}

// PublicKey returns the base64 Ed25519 public key that signs evidence packs, so it can
// be published for recipients to verify exported packs out-of-band.
func (s *Service) PublicKey() string {
	if s.signer == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.signer.Public().(ed25519.PublicKey))
}

// Build assembles the evidence pack for an incident in the caller's tenant, stamped
// at `now`. Events are the distinct events referenced by the incident's alerts; the
// audit trail is every log row whose action/target carries the incident id.
func (s *Service) Build(ctx context.Context, p auth.Principal, incidentID uuid.UUID, now time.Time) (*Pack, error) {
	inc, err := s.incidents.Get(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	timeline, err := s.incidents.Timeline(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrInternal("could not read timeline")
	}
	alerts, err := s.alerts.ListByIncident(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrInternal("could not read alerts")
	}
	// The underlying events are the distinct event ids the incident's alerts reference.
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, a := range alerts {
		if a.EventID != nil && !seen[*a.EventID] {
			seen[*a.EventID] = true
			ids = append(ids, *a.EventID)
		}
	}
	events, err := s.events.GetByIDs(ctx, p.TenantID, ids)
	if err != nil {
		return nil, httpx.ErrInternal("could not read events")
	}
	// Affected assets (§6.15): the distinct actor/target refs the alerts touch,
	// resolved against the tenant's inventory.
	var refs []string
	seenRef := map[string]bool{}
	for _, a := range alerts {
		for _, ref := range []string{a.TargetRef, a.ActorRef} {
			if ref != "" && !seenRef[ref] {
				seenRef[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	assets, err := s.assets.FindByRefs(ctx, p.TenantID, refs)
	if err != nil {
		return nil, httpx.ErrInternal("could not read assets")
	}
	// Exposure: the open vulnerabilities on those same affected assets (§6.15 ASSET-002/007).
	vulns, err := s.vulns.FindOpenByRefs(ctx, p.TenantID, refs)
	if err != nil {
		return nil, httpx.ErrInternal("could not read vulnerabilities")
	}
	auditRows, err := audit.FindByActionContains(ctx, s.db, p.TenantID, incidentID.String(), 500)
	if err != nil {
		return nil, httpx.ErrInternal("could not read audit trail")
	}
	pack := &Pack{
		SchemaVersion:   PackSchemaVersion,
		GeneratedAt:     now,
		GeneratedBy:     p.Email,
		TenantID:        p.TenantID,
		Incident:        inc,
		Timeline:        timeline,
		Alerts:          alerts,
		Events:          events,
		Assets:          assets,
		Vulnerabilities: vulns,
		Audit:           auditRows,
	}
	pack.Manifest = s.buildManifest(pack)
	return pack, nil
}

// checksum returns the hex SHA-256 of the canonical JSON of v.
func checksum(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// sectionChecksums recomputes the per-section SHA-256 checksums for a pack (used both
// when building and when verifying).
func sectionChecksums(p *Pack) map[string]string {
	return map[string]string{
		"incident":        checksum(p.Incident),
		"timeline":        checksum(p.Timeline),
		"alerts":          checksum(p.Alerts),
		"events":          checksum(p.Events),
		"assets":          checksum(p.Assets),
		"vulnerabilities": checksum(p.Vulnerabilities),
		"audit":           checksum(p.Audit),
	}
}

// digestInput is the canonical message that is signed: the ENVELOPE metadata folded
// with the (stably-ordered) section checksums. Because it includes generated_at/by,
// tenant and schema, altering any of those — not just a section — invalidates the
// signature (R2 H-B, envelope was previously unhashed).
func digestInput(schemaVersion, generatedBy string, generatedAt time.Time, tenantID uuid.UUID, sc map[string]string) []byte {
	keys := make([]string, 0, len(sc))
	for k := range sc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b []byte
	b = append(b, "schema="+schemaVersion+"\n"...)
	b = append(b, "generated_at="+generatedAt.UTC().Format(time.RFC3339Nano)+"\n"...)
	b = append(b, "generated_by="+generatedBy+"\n"...)
	b = append(b, "tenant="+tenantID.String()+"\n"...)
	for _, k := range keys {
		b = append(b, k+":"+sc[k]+";"...)
	}
	return b
}

// buildManifest computes per-section checksums + counts, the canonical pack digest, and
// an Ed25519 signature over that digest.
func (s *Service) buildManifest(p *Pack) Manifest {
	sc := sectionChecksums(p)
	counts := map[string]int{
		"timeline":        len(p.Timeline),
		"alerts":          len(p.Alerts),
		"events":          len(p.Events),
		"assets":          len(p.Assets),
		"vulnerabilities": len(p.Vulnerabilities),
		"audit":           len(p.Audit),
	}
	msg := digestInput(p.SchemaVersion, p.GeneratedBy, p.GeneratedAt, p.TenantID, sc)
	digest := sha256.Sum256(msg)
	m := Manifest{
		Algorithm:       "sha256",
		SectionChecksum: sc,
		Counts:          counts,
		PackDigest:      hex.EncodeToString(digest[:]),
	}
	if s.signer != nil {
		sig := ed25519.Sign(s.signer, msg)
		pub := s.signer.Public().(ed25519.PublicKey)
		m.Signature = &Signature{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			Value:     base64.StdEncoding.EncodeToString(sig),
		}
	}
	return m
}

// Verify checks a pack's integrity independently: it recomputes each section checksum
// from the section data (detecting any edited content), recomputes the canonical digest,
// and verifies the Ed25519 signature against trustedPubKey — the platform's published
// key, obtained OUT OF BAND. The public key embedded in the pack is NOT trusted for
// verification (a tamperer could swap it); it is only a hint. Returns nil iff the pack
// is authentic and unaltered.
func Verify(p *Pack, trustedPubKey ed25519.PublicKey) error {
	if p.Manifest.Signature == nil {
		return errors.New("evidence: pack is unsigned")
	}
	// 1. Section content must match the recorded checksums (no edited section).
	got := sectionChecksums(p)
	for k, want := range p.Manifest.SectionChecksum {
		if got[k] != want {
			return errors.New("evidence: section '" + k + "' has been altered")
		}
	}
	for k := range got {
		if _, ok := p.Manifest.SectionChecksum[k]; !ok {
			return errors.New("evidence: manifest is missing section '" + k + "'")
		}
	}
	// 2. Recompute the signed message from the (verified) section checksums + envelope.
	msg := digestInput(p.SchemaVersion, p.GeneratedBy, p.GeneratedAt, p.TenantID, got)
	// 3. Verify the signature against the TRUSTED key.
	sig, err := base64.StdEncoding.DecodeString(p.Manifest.Signature.Value)
	if err != nil {
		return errors.New("evidence: malformed signature")
	}
	if !ed25519.Verify(trustedPubKey, msg, sig) {
		return errors.New("evidence: signature verification failed")
	}
	return nil
}
