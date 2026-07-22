package contentlifecycle

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrPackNotFound       = errors.New("content: pack not found")
	ErrInvalidTransition  = errors.New("content: invalid lifecycle transition")
	ErrFourEyesRequired   = errors.New("content: four-eyes approval required")
	ErrReplay             = errors.New("content: replayed or equal version")
	ErrDowngrade          = errors.New("content: downgrade refused")
	ErrNoRollbackSnapshot = errors.New("content: no rollback snapshot")
)

type State string

const (
	StateQuarantined State = "quarantined"
	StateApproved    State = "approved"
	StateStaged      State = "staged"
	StateActive      State = "active"
	StateRolledBack  State = "rolled_back"
	StateSuperseded  State = "superseded"
)

type AuditEvent struct {
	At          time.Time
	Actor       string
	Action      string
	PublisherID string
	ContentType string
	Version     int64
	State       State
	Result      string
}

type Record struct {
	Pack         VerifiedPack
	State        State
	ImportedBy   string
	ApprovedBy   string
	ActivatedBy  string
	ImportedAt   time.Time
	ApprovedAt   time.Time
	ActivatedAt  time.Time
	PriorVersion int64
}

type Lifecycle struct {
	mu      sync.Mutex
	records map[string]map[string]map[int64]*Record
	active  map[string]map[string]int64
	audit   []AuditEvent
}

func NewLifecycle() *Lifecycle {
	return &Lifecycle{
		records: make(map[string]map[string]map[int64]*Record),
		active:  make(map[string]map[string]int64),
	}
}

func scopeKey(m Manifest) string {
	if m.Scope == "tenant" {
		return "tenant:" + m.TenantID
	}
	return "global"
}

func (l *Lifecycle) Import(pack VerifiedPack, importer string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := pack.Manifest
	key := scopeKey(m)
	if importer == "" {
		return fmt.Errorf("%w: importer required", ErrInvalidTransition)
	}
	if current := l.activeVersionLocked(key, m.ContentType); current >= m.Version {
		if current == m.Version {
			return ErrReplay
		}
		return ErrDowngrade
	}
	byType := l.records[key]
	if byType == nil {
		byType = make(map[string]map[int64]*Record)
		l.records[key] = byType
	}
	byVersion := byType[m.ContentType]
	if byVersion == nil {
		byVersion = make(map[int64]*Record)
		byType[m.ContentType] = byVersion
	}
	if _, exists := byVersion[m.Version]; exists {
		return ErrReplay
	}
	copyPack := pack
	copyPack.Artifacts = append([]Artifact(nil), pack.Artifacts...)
	byVersion[m.Version] = &Record{Pack: copyPack, State: StateQuarantined, ImportedBy: importer, ImportedAt: at}
	l.auditLocked(importer, "import", m, StateQuarantined, "accepted", at)
	return nil
}

func (l *Lifecycle) Approve(m Manifest, approver string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.recordLocked(m)
	if err != nil {
		return err
	}
	if r.State != StateQuarantined {
		return ErrInvalidTransition
	}
	if approver == "" || approver == r.ImportedBy {
		return ErrFourEyesRequired
	}
	r.State = StateApproved
	r.ApprovedBy = approver
	r.ApprovedAt = at
	l.auditLocked(approver, "approve", m, StateApproved, "accepted", at)
	return nil
}

func (l *Lifecycle) Activate(m Manifest, actor string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.recordLocked(m)
	if err != nil {
		return err
	}
	if r.State != StateApproved && r.State != StateStaged {
		return ErrInvalidTransition
	}
	if actor == "" {
		return ErrInvalidTransition
	}
	key := scopeKey(m)
	current := l.activeVersionLocked(key, m.ContentType)
	if current >= m.Version {
		if current == m.Version {
			return ErrReplay
		}
		return ErrDowngrade
	}
	if current > 0 {
		prior := l.records[key][m.ContentType][current]
		prior.State = StateSuperseded
		r.PriorVersion = current
	}
	if l.active[key] == nil {
		l.active[key] = make(map[string]int64)
	}
	l.active[key][m.ContentType] = m.Version
	r.State = StateActive
	r.ActivatedBy = actor
	r.ActivatedAt = at
	l.auditLocked(actor, "activate", m, StateActive, "accepted", at)
	return nil
}

func (l *Lifecycle) Rollback(m Manifest, actor string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.recordLocked(m)
	if err != nil {
		return err
	}
	if r.State != StateActive {
		return ErrInvalidTransition
	}
	if r.PriorVersion == 0 {
		return ErrNoRollbackSnapshot
	}
	key := scopeKey(m)
	prior := l.records[key][m.ContentType][r.PriorVersion]
	if prior == nil {
		return ErrNoRollbackSnapshot
	}
	r.State = StateRolledBack
	prior.State = StateActive
	l.active[key][m.ContentType] = prior.Pack.Manifest.Version
	l.auditLocked(actor, "rollback", m, StateRolledBack, "accepted", at)
	return nil
}

func (l *Lifecycle) Active(scope, tenantID, contentType string) (*Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := Manifest{Scope: scope, TenantID: tenantID}
	key := scopeKey(m)
	version := l.activeVersionLocked(key, contentType)
	if version == 0 {
		return nil, false
	}
	r := l.records[key][contentType][version]
	copyRecord := *r
	return &copyRecord, true
}

func (l *Lifecycle) Audit() []AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]AuditEvent(nil), l.audit...)
}

func (l *Lifecycle) recordLocked(m Manifest) (*Record, error) {
	byType := l.records[scopeKey(m)]
	if byType == nil || byType[m.ContentType] == nil || byType[m.ContentType][m.Version] == nil {
		return nil, ErrPackNotFound
	}
	return byType[m.ContentType][m.Version], nil
}

func (l *Lifecycle) activeVersionLocked(scope, contentType string) int64 {
	if l.active[scope] == nil {
		return 0
	}
	return l.active[scope][contentType]
}

func (l *Lifecycle) auditLocked(actor, action string, m Manifest, state State, result string, at time.Time) {
	l.audit = append(l.audit, AuditEvent{At: at, Actor: actor, Action: action, PublisherID: m.PublisherID, ContentType: m.ContentType, Version: m.Version, State: state, Result: result})
}
