package investigation

// §6.9 war-room (gate build/GATE_INVESTIGATION_WARROOM.md) — a SHARED, membership-gated investigation space, the one
// §6.9 surface that inverts private-per-analyst. Security model (all enforced here + structurally in mig 0140):
//   - D1 explicit invite: owner + explicit member set; only members read/write (membership RLS via app_current_user).
//   - D2 incident-scoped, revocation-aware: incident access is verified for the creator at create, the owner's invitee
//     is a real tenant user, and — the part a naive design misses — incident access is RE-CHECKED at every READ, so a
//     member whose incident access is later removed (incident offboarded/deleted) loses room content immediately;
//     membership is never a durable side-channel that outlives the incident.
//   - D3 per-viewer masking: a query_ref stores the QUERY, not rows; running it goes through RunHunt, re-masked for the
//     reader's role. A `note` is author prose shared as-authored — the honest boundary (references-not-rows stops the
//     SYSTEM unmasking a row into the shared store; it does not stop an author typing a value; that is insider trust).
//   - D4 self-join lock: a member row is insertable ONLY by the room owner (RLS WITH CHECK war_room_is_owner + the
//     owner-check here). A member cannot add themselves or anyone.
//   - D5 entries append-only; owner archives the room. D6 membership changes audited.

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	maxWarRoomTitle = 200
	maxWarRoomBody  = 8000
)

// WarRoom is a shared investigation space bound to an incident.
type WarRoom struct {
	ID          uuid.UUID       `json:"id"`
	IncidentRef uuid.UUID       `json:"incident_ref"`
	OwnerID     uuid.UUID       `json:"owner_id"`
	Title       string          `json:"title"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Members     []WarRoomMember `json:"members,omitempty"`
}

// WarRoomMember is a room participant.
type WarRoomMember struct {
	UserID  uuid.UUID `json:"user_id"`
	Role    string    `json:"role"`
	AddedBy uuid.UUID `json:"added_by"`
	AddedAt time.Time `json:"added_at"`
}

// WarRoomEntry is one shared contribution. A query_ref carries the re-runnable query (never rows); a note carries prose.
type WarRoomEntry struct {
	ID        uuid.UUID   `json:"id"`
	AuthorID  uuid.UUID   `json:"author_id"`
	Kind      string      `json:"kind"` // note | query_ref
	Body      string      `json:"body,omitempty"`
	All       []Predicate `json:"all,omitempty"`
	Any       []Predicate `json:"any,omitempty"`
	Lookback  int64       `json:"lookback_seconds,omitempty"`
	Limit     int         `json:"limit,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

// warRoomQueryRef is the jsonb persisted for a query_ref entry (predicates + relative window — no rows, no abs time).
type warRoomQueryRef struct {
	All      []Predicate `json:"all,omitempty"`
	Any      []Predicate `json:"any,omitempty"`
	Lookback int64       `json:"lookback_seconds"`
	Limit    int         `json:"limit,omitempty"`
}

func (r warRoomQueryRef) toQuery(now time.Time) HuntQuery {
	return HuntQuery{All: r.All, Any: r.Any, From: now.Add(-time.Duration(r.Lookback) * time.Second), To: now, Limit: r.Limit}
}

// WarRoomService owns the war-room surface. It uses WithTenantActor (tenant + actor GUC) so the membership RLS bites,
// reuses the investigation Service for the re-masked RunHunt on a query_ref, and re-checks incident access per read.
type WarRoomService struct {
	db             *database.DB
	hunt           *Service
	incidentAccess func(ctx context.Context, tenantID, incidentID uuid.UUID) error
}

// NewWarRoomService builds the service. hunt supplies the per-viewer-masked RunHunt for query_ref entries.
func NewWarRoomService(db *database.DB, hunt *Service) *WarRoomService {
	return &WarRoomService{db: db, hunt: hunt}
}

// WithIncidentAccess wires the revocation-aware incident-access check (D2). If unset, war-room content is unavailable
// (fail-closed) — the incident gate is not optional.
func (s *WarRoomService) WithIncidentAccess(f func(ctx context.Context, tenantID, incidentID uuid.UUID) error) *WarRoomService {
	s.incidentAccess = f
	return s
}

// checkIncident is the D2 gate: the actor must currently be able to access the room's incident. Fail-closed if unwired.
func (s *WarRoomService) checkIncident(ctx context.Context, p auth.Principal, incidentRef uuid.UUID) error {
	if s.incidentAccess == nil {
		return httpx.ErrForbidden("incident access check unavailable")
	}
	if err := s.incidentAccess(ctx, p.TenantID, incidentRef); err != nil {
		return httpx.ErrForbidden("no access to this room's incident")
	}
	return nil
}

// CreateRoom opens a war-room for an incident the creator can access; the creator becomes owner + first member. The
// owner member row inserts in the same tx as the room, so the members-INSERT RLS (war_room_is_owner) sees the room.
func (s *WarRoomService) CreateRoom(ctx context.Context, p auth.Principal, incidentRef uuid.UUID, title string) (*WarRoom, error) {
	if incidentRef == uuid.Nil {
		return nil, httpx.ErrBadRequest("incident_ref is required")
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "War room"
	}
	if len(title) > maxWarRoomTitle {
		return nil, httpx.ErrBadRequest("title too long")
	}
	if err := s.checkIncident(ctx, p, incidentRef); err != nil { // D2: creator must have incident access
		return nil, err
	}
	room := &WarRoom{IncidentRef: incidentRef, OwnerID: p.UserID, Title: title, Status: "active"}
	err := s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx,
			`INSERT INTO investigation_war_rooms (incident_ref, owner_id, title) VALUES ($1,$2,$3)
			 RETURNING id, created_at, updated_at`, incidentRef, p.UserID, title).
			Scan(&room.ID, &room.CreatedAt, &room.UpdatedAt); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO investigation_war_room_members (room_id, user_id, role, added_by) VALUES ($1,$2,'moderator',$2)`,
			room.ID, p.UserID); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "warroom.create",
			Target: "war_room:" + room.ID.String(), Metadata: map[string]any{"incident_ref": incidentRef.String()}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not create war room")
	}
	return room, nil
}

// getRoomRow reads a room the actor may see (RLS: owner or member; else no row → not-found).
func (s *WarRoomService) getRoomRow(ctx context.Context, p auth.Principal, roomID uuid.UUID) (*WarRoom, error) {
	var room *WarRoom
	err := s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		var r WarRoom
		if e := tx.QueryRow(ctx,
			`SELECT id, incident_ref, owner_id, title, status, created_at, updated_at FROM investigation_war_rooms WHERE id=$1`, roomID).
			Scan(&r.ID, &r.IncidentRef, &r.OwnerID, &r.Title, &r.Status, &r.CreatedAt, &r.UpdatedAt); e != nil {
			return e
		}
		room = &r
		return nil
	})
	if err != nil {
		return nil, httpx.ErrNotFound("war room not found")
	}
	return room, nil
}

// GetRoom returns a room (+ members) the caller belongs to, AFTER re-checking incident access (D2 revocation-aware).
func (s *WarRoomService) GetRoom(ctx context.Context, p auth.Principal, roomID uuid.UUID) (*WarRoom, error) {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return nil, err
	}
	if err := s.checkIncident(ctx, p, room.IncidentRef); err != nil {
		return nil, httpx.ErrNotFound("war room not found") // incident access gone → content unavailable
	}
	members, err := s.listMembers(ctx, p, roomID)
	if err != nil {
		return nil, err
	}
	room.Members = members
	return room, nil
}

// ListRooms returns the rooms the caller can see (owner or member — RLS scoped).
func (s *WarRoomService) ListRooms(ctx context.Context, p auth.Principal) ([]WarRoom, error) {
	var out []WarRoom
	err := s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, incident_ref, owner_id, title, status, created_at, updated_at FROM investigation_war_rooms
			  ORDER BY updated_at DESC LIMIT 200`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r WarRoom
			if e := rows.Scan(&r.ID, &r.IncidentRef, &r.OwnerID, &r.Title, &r.Status, &r.CreatedAt, &r.UpdatedAt); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list war rooms")
	}
	return out, nil
}

func (s *WarRoomService) listMembers(ctx context.Context, p auth.Principal, roomID uuid.UUID) ([]WarRoomMember, error) {
	var out []WarRoomMember
	err := s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT user_id, role, added_by, added_at FROM investigation_war_room_members WHERE room_id=$1 ORDER BY added_at`, roomID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m WarRoomMember
			if e := rows.Scan(&m.UserID, &m.Role, &m.AddedBy, &m.AddedAt); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// Invite adds a member — OWNER ONLY (handler + RLS). The invitee must be a real user in the tenant (no foreign/cross-
// tenant invitee; incident access for a tenant analyst is role+tenant, re-checked when they read). Audited (D6).
func (s *WarRoomService) Invite(ctx context.Context, p auth.Principal, roomID, invitee uuid.UUID) error {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return err
	}
	if room.OwnerID != p.UserID {
		return httpx.ErrForbidden("only the room owner may invite members")
	}
	if err := s.checkIncident(ctx, p, room.IncidentRef); err != nil {
		return err
	}
	if invitee == uuid.Nil {
		return httpx.ErrBadRequest("user_id is required")
	}
	return s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND tenant_id=app_current_tenant())`, invitee).Scan(&exists); e != nil {
			return httpx.ErrInternal("could not validate invitee")
		}
		if !exists {
			return httpx.ErrBadRequest("invitee is not a user in this tenant")
		}
		// RLS members-INSERT WITH CHECK war_room_is_owner enforces owner-only structurally; this handler path is the owner.
		if _, e := tx.Exec(ctx,
			`INSERT INTO investigation_war_room_members (room_id, user_id, role, added_by) VALUES ($1,$2,'member',$3)
			 ON CONFLICT (room_id, user_id) DO NOTHING`, roomID, invitee, p.UserID); e != nil {
			return httpx.ErrInternal("could not add member")
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "warroom.member_add",
			Target: "war_room:" + roomID.String(), Metadata: map[string]any{"member": invitee.String()}})
	})
}

// RemoveMember removes a member — OWNER ONLY (handler + RLS). The owner cannot remove themselves (keep an owner).
func (s *WarRoomService) RemoveMember(ctx context.Context, p auth.Principal, roomID, member uuid.UUID) error {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return err
	}
	if room.OwnerID != p.UserID {
		return httpx.ErrForbidden("only the room owner may remove members")
	}
	if member == room.OwnerID {
		return httpx.ErrBadRequest("the owner cannot be removed")
	}
	return s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM investigation_war_room_members WHERE room_id=$1 AND user_id=$2`, roomID, member); e != nil {
			return httpx.ErrInternal("could not remove member")
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "warroom.member_remove",
			Target: "war_room:" + roomID.String(), Metadata: map[string]any{"member": member.String()}})
	})
}

// Archive soft-archives the room — OWNER ONLY.
func (s *WarRoomService) Archive(ctx context.Context, p auth.Principal, roomID uuid.UUID) error {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return err
	}
	if room.OwnerID != p.UserID {
		return httpx.ErrForbidden("only the room owner may archive the room")
	}
	return s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE investigation_war_rooms SET status='archived', updated_at=now() WHERE id=$1`, roomID)
		return e
	})
}

// EntryInput adds an entry. kind=note → Body; kind=query_ref → All/Any/Lookback/Limit (validated for the author).
type EntryInput struct {
	Kind            string      `json:"kind"`
	Body            string      `json:"body"`
	All             []Predicate `json:"all"`
	Any             []Predicate `json:"any"`
	LookbackSeconds int64       `json:"lookback_seconds"`
	Limit           int         `json:"limit"`
}

// AddEntry posts a shared entry. RLS requires the author be a member posting as themselves; we also re-check incident
// access first (a member who lost it can't post). A query_ref is validated for the AUTHOR (can't share a query you
// couldn't run); its rows are never stored — only the re-runnable query.
func (s *WarRoomService) AddEntry(ctx context.Context, p auth.Principal, roomID uuid.UUID, in EntryInput) (*WarRoomEntry, error) {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return nil, err
	}
	if err := s.checkIncident(ctx, p, room.IncidentRef); err != nil {
		return nil, err
	}
	if room.Status != "active" {
		return nil, httpx.ErrConflict("room is archived")
	}
	body := ""
	var qb []byte
	switch in.Kind {
	case "note":
		body = strings.TrimSpace(in.Body)
		if body == "" || len(body) > maxWarRoomBody {
			return nil, httpx.ErrBadRequest("note body is required (<=8000 chars)")
		}
		qb = []byte("{}")
	case "query_ref":
		if in.LookbackSeconds <= 0 {
			return nil, httpx.ErrBadRequest("lookback_seconds must be > 0")
		}
		ref := warRoomQueryRef{All: in.All, Any: in.Any, Lookback: in.LookbackSeconds, Limit: in.Limit}
		// Validate the query for the AUTHOR — a ref you couldn't run cannot be shared (RunHunt re-validates per reader).
		q := ref.toQuery(time.Now())
		if err := q.Validate(p, s.hunt.repo.LoadLimits(ctx)); err != nil {
			return nil, err
		}
		qb, _ = json.Marshal(ref)
	default:
		return nil, httpx.ErrBadRequest("kind must be note or query_ref")
	}
	e := &WarRoomEntry{AuthorID: p.UserID, Kind: in.Kind, Body: body}
	err = s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO investigation_war_room_entries (room_id, author_id, kind, body, query) VALUES ($1,$2,$3,$4,$5)
			 RETURNING id, created_at`, roomID, p.UserID, in.Kind, body, qb).Scan(&e.ID, &e.CreatedAt)
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not add entry")
	}
	return e, nil
}

// ListEntries returns the room's entries (RLS members-only), after the D2 incident re-check. query_ref entries return
// the QUERY DEFINITION (what to search — not sensitive, not masked); note entries return prose; NO result rows.
func (s *WarRoomService) ListEntries(ctx context.Context, p auth.Principal, roomID uuid.UUID) ([]WarRoomEntry, error) {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return nil, err
	}
	if err := s.checkIncident(ctx, p, room.IncidentRef); err != nil {
		return nil, httpx.ErrNotFound("war room not found")
	}
	var out []WarRoomEntry
	err = s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, author_id, kind, body, query, created_at FROM investigation_war_room_entries WHERE room_id=$1 ORDER BY created_at`, roomID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var en WarRoomEntry
			var qb []byte
			if e := rows.Scan(&en.ID, &en.AuthorID, &en.Kind, &en.Body, &qb, &en.CreatedAt); e != nil {
				return e
			}
			if en.Kind == "query_ref" && len(qb) > 0 {
				var ref warRoomQueryRef
				_ = json.Unmarshal(qb, &ref)
				en.All, en.Any, en.Lookback, en.Limit = ref.All, ref.Any, ref.Lookback, ref.Limit
			}
			out = append(out, en)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not list entries")
	}
	return out, nil
}

// RunEntryQuery runs a query_ref entry for the CURRENT reader through RunHunt — re-masked for the reader's role +
// read-audited (D3 per-viewer masking). A junior member running a senior's ref sees only their own field-visibility.
func (s *WarRoomService) RunEntryQuery(ctx context.Context, p auth.Principal, roomID, entryID uuid.UUID) (HuntResult, error) {
	room, err := s.getRoomRow(ctx, p, roomID)
	if err != nil {
		return HuntResult{}, err
	}
	if err := s.checkIncident(ctx, p, room.IncidentRef); err != nil {
		return HuntResult{}, httpx.ErrNotFound("war room not found")
	}
	var ref warRoomQueryRef
	var kind string
	err = s.db.WithTenantActor(ctx, p.TenantID, p.UserID, func(ctx context.Context, tx pgx.Tx) error {
		var qb []byte
		if e := tx.QueryRow(ctx,
			`SELECT kind, query FROM investigation_war_room_entries WHERE id=$1 AND room_id=$2`, entryID, roomID).Scan(&kind, &qb); e != nil {
			return e
		}
		if len(qb) > 0 {
			_ = json.Unmarshal(qb, &ref)
		}
		return nil
	})
	if err != nil {
		return HuntResult{}, httpx.ErrNotFound("entry not found")
	}
	if kind != "query_ref" {
		return HuntResult{}, httpx.ErrBadRequest("entry is not a query_ref")
	}
	// RunHunt re-validates + re-masks for THIS reader (field-visibility + cost ceiling + read-audit).
	return s.hunt.RunHunt(ctx, p, ref.toQuery(time.Now()))
}
