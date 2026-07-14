package threatintel

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// maxBundleObjects caps objects accepted in one ImportBundle request (Round-5 M1).
const maxBundleObjects = 5000

// minObservableLen is the shortest observable value the enricher will match on, so trivially-short or
// overly-generic indicators (".com", "a") cannot match nearly every event (Round-5 M2).
const minObservableLen = 4

// Match is a threat-intel hit against an event entity. A hit comes from either the flat manual watchlist
// (Source "watchlist") or the STIX object store (Source "stix"); STIX hits additionally carry the
// matched object id, confidence, labels, and kill-chain so downstream can explain WHY it matters (TI-004)
// and feed correlation (COR-002). Score is populated for both (watchlist score / STIX confidence) so
// existing consumers that only read Score keep working.
type Match struct {
	Source     string   `json:"source"` // "watchlist" | "stix"
	Value      string   `json:"value"`
	Score      int      `json:"score"`
	TLP        string   `json:"tlp"`
	Tags       []string `json:"tags,omitempty"`
	ObjectID   string   `json:"object_id,omitempty"`  // stix_objects.id for a STIX hit
	Confidence int      `json:"confidence,omitempty"` // STIX confidence (0-100)
	Labels     []string `json:"labels,omitempty"`     // STIX labels (malicious-activity, c2, ...)
	KillChain  []string `json:"kill_chain,omitempty"` // kill-chain phase names
}

// Enricher matches event entities against the tenant's threat intel — the manual watchlist AND the STIX
// observable set — cached per tenant (short TTL) so enrichment does not hit the DB per event.
type Enricher struct {
	repo  *Repository
	ttl   time.Duration
	mu    sync.Mutex
	cache map[uuid.UUID]entry
}

type entry struct {
	inds      []Indicator
	obs       []stixObservable // retained so the pointers in `stix` stay valid
	stix      []stixMatchEntry // one per matchable literal (multi-value pattern expansion, slice B)
	sightings map[string]int   // sighting count by object id (corroboration boost)
	settings  TISettings       // per-tenant decay/boost tuning
	expires   time.Time
}

// stixMatchEntry is one matchable literal (lower-cased) tied back to its parent object; a compound
// indicator expands into several of these (slice B), deduped to one Match by object id at hit time.
type stixMatchEntry struct {
	value string
	obs   *stixObservable
}

// NewEnricher builds the enricher.
func NewEnricher(repo *Repository) *Enricher {
	return &Enricher{repo: repo, ttl: 30 * time.Second, cache: map[uuid.UUID]entry{}}
}

// Enrich returns threat-intel matches for the given candidate strings (event entities). Watchlist and
// STIX observables are matched by case-insensitive substring; results are de-duplicated (watchlist by
// value, STIX by object id).
func (e *Enricher) Enrich(ctx context.Context, tenantID uuid.UUID, candidates []string) ([]Match, error) {
	snap, err := e.snapshot(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(snap.inds) == 0 && len(snap.stix) == 0 {
		return nil, nil
	}
	now := time.Now()
	lc := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c != "" {
			lc = append(lc, strings.ToLower(c))
		}
	}
	// Round-5 M2: match on a token boundary and require a minimum observable length, so an indicator
	// like "8.8.8.8" does not match inside "18.8.8.80" and a generic ".com" does not match every host.
	hit := func(needle string) bool {
		if len(needle) < minObservableLen {
			return false
		}
		for _, c := range lc {
			if tokenContains(c, needle) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	var out []Match
	for _, ind := range snap.inds {
		if hit(strings.ToLower(ind.Value)) && !seen["w:"+ind.Value] {
			seen["w:"+ind.Value] = true
			out = append(out, Match{Source: "watchlist", Value: ind.Value, Score: ind.Score, Confidence: ind.Score, Tags: ind.Tags, TLP: ind.TLP})
		}
	}
	// STIX matches: each entry is one literal from an indicator's (possibly compound) pattern. A hit on
	// ANY literal yields one Match per object (deduped by id). Effective confidence = age decay + bounded
	// sightings corroboration; a match decayed below the tenant's floor stops firing (slice B).
	for _, me := range snap.stix {
		o := me.obs
		if seen["s:"+o.ID] || !hit(me.value) {
			continue
		}
		eff := effectiveConfidence(o.Confidence, ageDays(o.ValidFrom, o.Created, now), snap.sightings[o.ID], snap.settings)
		if eff < snap.settings.MinEffectiveConfidence {
			continue // aged out below the freshness floor — no longer actionable
		}
		seen["s:"+o.ID] = true
		out = append(out, Match{Source: "stix", ObjectID: o.ID, Value: o.Value, Score: eff,
			Confidence: eff, Tags: o.Labels, Labels: o.Labels, TLP: o.TLP, KillChain: o.KillChain})
	}
	return out, nil
}

// snapshot returns the cached watchlist + STIX observable set for the tenant, reloading from the repo
// when the entry is missing or stale.
func (e *Enricher) snapshot(ctx context.Context, tenantID uuid.UUID) (entry, error) {
	e.mu.Lock()
	ent, ok := e.cache[tenantID]
	e.mu.Unlock()
	if ok && time.Now().Before(ent.expires) {
		return ent, nil
	}
	inds, err := e.repo.List(ctx, tenantID)
	if err != nil {
		return entry{}, err
	}
	obs, err := e.repo.matchableObservables(ctx, tenantID)
	if err != nil {
		return entry{}, err
	}
	sightings, err := e.repo.sightingCounts(ctx, tenantID)
	if err != nil {
		return entry{}, err
	}
	settings, err := e.repo.GetTISettings(ctx, tenantID)
	if err != nil {
		return entry{}, err
	}
	// Expand each object into one matchable entry per pattern literal (compound indicators → several),
	// pointing back into the retained obs slice so hit-time has the full object metadata + age inputs.
	var stix []stixMatchEntry
	for i := range obs {
		for _, v := range observableValues(obs[i].Type, obs[i].Pattern, obs[i].Value) {
			if v == "" {
				continue
			}
			stix = append(stix, stixMatchEntry{value: strings.ToLower(v), obs: &obs[i]})
		}
	}
	ent = entry{inds: inds, obs: obs, stix: stix, sightings: sightings, settings: settings, expires: time.Now().Add(e.ttl)}
	e.mu.Lock()
	e.cache[tenantID] = ent
	e.mu.Unlock()
	return ent, nil
}

// tokenContains reports whether needle occurs in haystack delimited by non-alphanumeric boundaries (or
// string edges) — so "8.8.8.8" matches "src=8.8.8.8;" but not "18.8.8.80", and "evil.com" matches
// "to evil.com/x" but ".com" does not match "evil.com". Both args are already lower-cased. Round-5 M2.
func tokenContains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	from := 0
	for from <= len(haystack)-len(needle) {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		beforeOK := start == 0 || !isAlnumByte(haystack[start-1])
		afterOK := end == len(haystack) || !isAlnumByte(haystack[end])
		if beforeOK && afterOK {
			return true
		}
		from = start + 1
	}
	return false
}

func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func (e *Enricher) invalidate(tenantID uuid.UUID) {
	e.mu.Lock()
	delete(e.cache, tenantID)
	e.mu.Unlock()
}

// Service manages the watchlist and the STIX object store.
type Service struct {
	repo *Repository
	enr  *Enricher
}

// NewService builds the service (shares the enricher for cache invalidation).
func NewService(repo *Repository, enr *Enricher) *Service { return &Service{repo: repo, enr: enr} }

// AddInput adds a manual watchlist indicator.
type AddInput struct {
	Type  string   `json:"type"`
	Value string   `json:"value"`
	TLP   string   `json:"tlp"`
	Score int      `json:"score"`
	Tags  []string `json:"tags"`
}

// Add validates and stores a manual watchlist indicator (the quick-IOC path; TI-001).
func (s *Service) Add(ctx context.Context, tenantID uuid.UUID, in AddInput) (*Indicator, error) {
	if in.Type == "" || in.Value == "" {
		return nil, httpx.ErrBadRequest("type and value are required")
	}
	if in.TLP == "" {
		in.TLP = "amber"
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	ind := &Indicator{ID: uuid.New(), TenantID: tenantID, Type: in.Type, Value: in.Value, TLP: in.TLP, Score: in.Score, Tags: in.Tags}
	if err := s.repo.Add(ctx, ind); err != nil {
		return nil, httpx.ErrInternal("could not add indicator")
	}
	s.enr.invalidate(tenantID)
	return ind, nil
}

// List returns the watchlist.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Indicator, error) {
	return s.repo.List(ctx, tenantID)
}

// Enrich looks up candidate observables (an alert's actor/target refs and any raw IOCs) against the tenant's
// watchlist + STIX store, returning the matches (§6.10). Read-only; used by the alert-detail enrichment panel.
func (s *Service) Enrich(ctx context.Context, tenantID uuid.UUID, candidates []string) ([]Match, error) {
	return s.enr.Enrich(ctx, tenantID, candidates)
}

// StixInput is an analyst-submitted STIX object (TI-001 manual add). A minimal indicator only needs
// type + pattern (or type + value for a cyber-observable); everything else is defaulted.
type StixInput struct {
	Type        string          `json:"type"`
	Pattern     string          `json:"pattern"`
	PatternType string          `json:"pattern_type"`
	Value       string          `json:"value"` // for SCOs / explicit observable
	Confidence  int             `json:"confidence"`
	TLP         string          `json:"tlp"`
	Labels      []string        `json:"labels"`
	KillChain   []string        `json:"kill_chain_phases"`
	ValidFrom   *time.Time      `json:"valid_from"`
	ValidUntil  *time.Time      `json:"valid_until"`
	Source      string          `json:"source"`
	Revoked     bool            `json:"revoked"`
	ExternalRef json.RawMessage `json:"external_references"`
}

// AddStix validates and stores a single STIX object submitted by an analyst.
func (s *Service) AddStix(ctx context.Context, tenantID uuid.UUID, in StixInput) (*StixObject, error) {
	if !validStixType(in.Type) {
		return nil, httpx.ErrBadRequest("unknown or unsupported STIX type")
	}
	if in.Type == "indicator" && in.Pattern == "" {
		return nil, httpx.ErrBadRequest("an indicator requires a pattern")
	}
	if in.Confidence < 0 || in.Confidence > 100 {
		return nil, httpx.ErrBadRequest("confidence must be 0-100")
	}
	now := time.Now().UTC()
	o := &StixObject{
		ID:                 in.Type + "--" + uuid.New().String(),
		Type:               in.Type,
		SpecVersion:        "2.1",
		Created:            now,
		Modified:           now,
		Confidence:         in.Confidence,
		Revoked:            in.Revoked,
		ValidFrom:          in.ValidFrom,
		ValidUntil:         in.ValidUntil,
		Pattern:            in.Pattern,
		PatternType:        defaultStr(in.PatternType, "stix"),
		Labels:             nonNil(in.Labels),
		ExternalReferences: in.ExternalRef,
		KillChainPhases:    nonNil(in.KillChain),
		TLP:                validTLP(in.TLP),
		Source:             defaultStr(in.Source, "manual"),
	}
	o.Value = firstNonEmpty(in.Value, extractObservable(o.Type, o.Pattern, o.Raw))
	// R6: bundle-imported objects keep their original bytes in Raw; a manually-added object had
	// none, leaving Raw empty (so a later TAXII/evidence export of it lost the canonical STIX JSON).
	// Serialize the assembled object as its own canonical 2.1 representation.
	if raw, merr := json.Marshal(o); merr == nil {
		o.Raw = json.RawMessage(raw)
	}
	if _, err := s.repo.UpsertStix(ctx, tenantID, o); err != nil {
		return nil, httpx.ErrInternal("could not store STIX object")
	}
	s.enr.invalidate(tenantID)
	return o, nil
}

// BundleResult reports the outcome of importing a STIX bundle.
type BundleResult struct {
	Imported int      `json:"imported"` // applied (inserted or version-updated)
	Skipped  int      `json:"skipped"`  // older-or-equal duplicates (idempotent re-import)
	Ignored  int      `json:"ignored"`  // unknown/unsupported types (logged, not errored)
	Errors   []string `json:"errors,omitempty"`
}

// ImportBundle ingests a STIX 2.1 bundle (TI-001), upserting each object by (id, modified). Unknown
// types are counted as ignored rather than failing the whole bundle.
func (s *Service) ImportBundle(ctx context.Context, tenantID uuid.UUID, raw json.RawMessage) (*BundleResult, error) {
	var bundle struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, httpx.ErrBadRequest("invalid STIX bundle JSON")
	}
	if len(bundle.Objects) == 0 {
		return nil, httpx.ErrBadRequest("bundle contains no objects")
	}
	// Round-5 M1: cap objects per bundle so a large upload can't fan out into an unbounded number of
	// sequential transactions in one request (API4 resource-exhaustion). Larger feeds import in batches.
	if len(bundle.Objects) > maxBundleObjects {
		return nil, httpx.ErrBadRequest("bundle exceeds the per-request object limit; split into batches")
	}
	res := &BundleResult{}
	for _, rawObj := range bundle.Objects {
		o, ok := parseBundleObject(rawObj)
		if !ok {
			res.Ignored++
			continue
		}
		applied, err := s.repo.UpsertStix(ctx, tenantID, o)
		if err != nil {
			res.Errors = append(res.Errors, o.ID+": store error")
			continue
		}
		if applied {
			res.Imported++
		} else {
			res.Skipped++
		}
	}
	if res.Imported > 0 {
		s.enr.invalidate(tenantID)
	}
	return res, nil
}

// ListStix returns global + own STIX objects (optionally by type).
func (s *Service) ListStix(ctx context.Context, tenantID uuid.UUID, typeFilter string, limit int) ([]StixObject, error) {
	return s.repo.ListStix(ctx, tenantID, typeFilter, limit)
}

// GetStix returns one STIX object by id (nil if not visible).
func (s *Service) GetStix(ctx context.Context, tenantID uuid.UUID, id string) (*StixObject, error) {
	return s.repo.GetStix(ctx, tenantID, id)
}

// Settings returns the tenant's threat-intel tuning (defaults if unset).
func (s *Service) Settings(ctx context.Context, tenantID uuid.UUID) (TISettings, error) {
	set, err := s.repo.GetTISettings(ctx, tenantID)
	if err != nil {
		return TISettings{}, httpx.ErrInternal("could not load threat-intel settings")
	}
	return set, nil
}

// SetSettings validates and upserts the tenant's threat-intel tuning, then invalidates the enricher
// cache so the new decay/boost takes effect on the next event.
func (s *Service) SetSettings(ctx context.Context, tenantID uuid.UUID, in TISettings) (TISettings, error) {
	if in.DecayHalfLifeDays < 1 || in.DecayHalfLifeDays > 3650 {
		return TISettings{}, httpx.ErrBadRequest("decay_half_life_days must be between 1 and 3650")
	}
	if in.MinEffectiveConfidence < 0 || in.MinEffectiveConfidence > 100 {
		return TISettings{}, httpx.ErrBadRequest("min_effective_confidence must be between 0 and 100")
	}
	if in.SightingBoostCap < 0 || in.SightingBoostCap > 100 {
		return TISettings{}, httpx.ErrBadRequest("sighting_boost_cap must be between 0 and 100")
	}
	if err := s.repo.SetTISettings(ctx, tenantID, in); err != nil {
		return TISettings{}, httpx.ErrInternal("could not save threat-intel settings")
	}
	s.enr.invalidate(tenantID)
	return in, nil
}

// parseBundleObject maps one raw STIX object to a StixObject, computing its matchable value and deriving
// TLP from object_marking_refs. Returns ok=false for objects without a known type or id.
func parseBundleObject(raw json.RawMessage) (*StixObject, bool) {
	var p struct {
		ID              string           `json:"id"`
		Type            string           `json:"type"`
		SpecVersion     string           `json:"spec_version"`
		Created         *time.Time       `json:"created"`
		Modified        *time.Time       `json:"modified"`
		Confidence      int              `json:"confidence"`
		Revoked         bool             `json:"revoked"`
		ValidFrom       *time.Time       `json:"valid_from"`
		ValidUntil      *time.Time       `json:"valid_until"`
		Pattern         string           `json:"pattern"`
		PatternType     string           `json:"pattern_type"`
		Labels          []string         `json:"labels"`
		ExternalRefs    json.RawMessage  `json:"external_references"`
		KillChainPhases []killChainPhase `json:"kill_chain_phases"`
		MarkingRefs     []string         `json:"object_marking_refs"`
		Value           string           `json:"value"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, false
	}
	if p.ID == "" || !validStixType(p.Type) {
		return nil, false
	}
	// STIX versioning is keyed on `modified`. Do NOT fabricate it: a fabricated now() would make every
	// re-import look strictly newer and defeat idempotency. When only `created` is present use it; when
	// neither is present the object is unversioned (e.g. an immutable SCO or a sloppy feed) — leave both
	// zero so UpsertStix treats it as insert-only.
	var created, modified time.Time
	if p.Created != nil {
		created = *p.Created
	}
	if p.Modified != nil {
		modified = *p.Modified
	} else {
		modified = created // may still be zero → insert-only
	}
	if created.IsZero() {
		created = modified
	}
	phases := make([]string, 0, len(p.KillChainPhases))
	for _, kp := range p.KillChainPhases {
		if kp.PhaseName != "" {
			phases = append(phases, kp.PhaseName)
		}
	}
	o := &StixObject{
		ID:                 p.ID,
		Type:               p.Type,
		SpecVersion:        defaultStr(p.SpecVersion, "2.1"),
		Created:            created,
		Modified:           modified,
		Confidence:         clampConfidence(p.Confidence),
		Revoked:            p.Revoked,
		ValidFrom:          p.ValidFrom,
		ValidUntil:         p.ValidUntil,
		Pattern:            p.Pattern,
		PatternType:        defaultStr(p.PatternType, "stix"),
		Labels:             nonNil(p.Labels),
		ExternalReferences: p.ExternalRefs,
		KillChainPhases:    phases,
		TLP:                tlpFromMarkings(p.MarkingRefs),
		Source:             "bundle",
		Raw:                raw,
	}
	o.Value = firstNonEmpty(p.Value, extractObservable(o.Type, o.Pattern, o.Raw))
	return o, true
}

type killChainPhase struct {
	PhaseName string `json:"phase_name"`
}

// tlpMarkingIDs maps the well-known STIX 2.1 TLP marking-definition ids to a TLP string. STIX 2.1 ships
// the TLP 1.0 markings (white/green/amber/red); TLP 2.0 renames white→clear, which we normalise here.
var tlpMarkingIDs = map[string]string{
	"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear", // TLP:WHITE -> CLEAR
	"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
	"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
	"marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}

func tlpFromMarkings(refs []string) string {
	for _, ref := range refs {
		if tlp, ok := tlpMarkingIDs[ref]; ok {
			return tlp
		}
	}
	return "amber" // default per FIRST TLP guidance when unmarked
}

func validTLP(t string) string {
	switch t {
	case "red", "amber+strict", "amber", "green", "clear":
		return t
	default:
		return "amber"
	}
}

func clampConfidence(c int) int {
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
