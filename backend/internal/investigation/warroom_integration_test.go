package investigation

// §6.9 war-room DB-gated tests (gate §3, two-analyst harness). Load-bearing: #2 self-join blocked, #3 references-not-
// rows, #4 revocation-aware read. All run under RequireDSN (skip locally, run in CI).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// wrUser inserts a real user in the tenant and returns a principal for it (war-room invite requires a real tenant user).
func wrUser(t *testing.T, db *database.DB, tid uuid.UUID, role auth.Role) auth.Principal {
	t.Helper()
	id := uuid.New()
	email := id.String() + "@wr"
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,'x',$3)`, id, email, string(role))
		return e
	}); err != nil {
		t.Fatalf("make user: %v", err)
	}
	return auth.Principal{UserID: id, TenantID: tid, Role: role, Email: email}
}

// wrService builds a war-room service whose incident-access check returns *accessErr (flip it to simulate revocation).
func wrService(db *database.DB, accessErr *error) *WarRoomService {
	hunt := NewService(NewRepository(db))
	return NewWarRoomService(db, hunt).WithIncidentAccess(func(ctx context.Context, tid, iid uuid.UUID) error { return *accessErr })
}

// #1 (gate §3.1): a member reads the room; a non-member and a cross-tenant actor get not-found.
func TestWarRoom_MembershipReadIsolation(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	member := wrUser(t, db, tid, auth.RoleAnalystT1)
	stranger := wrUser(t, db, tid, auth.RoleAnalystT1)
	incident := uuid.New()

	room, err := s.CreateRoom(ctx, owner, incident, "case A")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Invite(ctx, owner, room.ID, member.UserID); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := s.GetRoom(ctx, member, room.ID); err != nil {
		t.Fatalf("member must read the room: %v", err)
	}
	if _, err := s.GetRoom(ctx, stranger, room.ID); err == nil {
		t.Fatal("a non-member must NOT read the room")
	}
	// cross-tenant actor
	tid2 := invTenant(t, db)
	other := wrUser(t, db, tid2, auth.RoleAnalystT1)
	if _, err := s.GetRoom(ctx, other, room.ID); err == nil {
		t.Fatal("a cross-tenant actor must NOT read the room")
	}
}

// #2 LOAD-BEARING (gate §3.2, D4 self-join): a non-owner (member OR stranger) cannot INSERT a member row directly —
// the RLS WITH CHECK war_room_is_owner blocks it. This is THE escalation guard.
func TestWarRoom_SelfJoinBlocked(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	stranger := wrUser(t, db, tid, auth.RoleAnalystT1)
	room, err := s.CreateRoom(ctx, owner, uuid.New(), "case B")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The stranger tries to add THEMSELVES directly, as their own actor — RLS members-INSERT WITH CHECK war_room_is_owner
	// must reject it (they are not the owner).
	selfJoin := db.WithTenantActor(ctx, tid, stranger.UserID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO investigation_war_room_members (room_id, user_id, role, added_by) VALUES ($1,$2,'member',$2)`,
			room.ID, stranger.UserID)
		return e
	})
	if selfJoin == nil {
		t.Fatal("SELF-JOIN: a non-owner must NOT be able to insert their own member row (RLS write-policy lock)")
	}
	if _, err := s.GetRoom(ctx, stranger, room.ID); err == nil {
		t.Fatal("after a blocked self-join the stranger still must not read the room")
	}
}

// #3 (gate §3.3): a query_ref entry stores the QUERY, never rendered rows; running it goes through RunHunt (re-masked
// per viewer). We assert the reference-not-rows property + that a member can run it and a non-member cannot.
func TestWarRoom_QueryRefIsReferenceNotRows(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	member := wrUser(t, db, tid, auth.RoleAnalystT1)
	stranger := wrUser(t, db, tid, auth.RoleAnalystT1)
	seedEvent(t, db, tid, time.Now().Add(-30*time.Minute), "high", "user:alice", "edr")
	room, _ := s.CreateRoom(ctx, owner, uuid.New(), "case C")
	_ = s.Invite(ctx, owner, room.ID, member.UserID)

	e, err := s.AddEntry(ctx, owner, room.ID, EntryInput{Kind: "query_ref",
		All: []Predicate{{Field: "severity", Op: "eq", Value: "high"}}, LookbackSeconds: 3600, Limit: 50})
	if err != nil {
		t.Fatalf("add query_ref: %v", err)
	}
	// Listed entry carries the query DEFINITION, never result rows (WarRoomEntry has no rows field by construction).
	entries, err := s.ListEntries(ctx, member, room.ID)
	if err != nil || len(entries) != 1 || entries[0].Kind != "query_ref" || len(entries[0].All) != 1 {
		t.Fatalf("member must see the query_ref definition; got %+v err=%v", entries, err)
	}
	// A member runs it → routes through RunHunt (re-masked for the member); a non-member cannot run it.
	if _, err := s.RunEntryQuery(ctx, member, room.ID, e.ID); err != nil {
		t.Fatalf("member must be able to run the shared query_ref: %v", err)
	}
	if _, err := s.RunEntryQuery(ctx, stranger, room.ID, e.ID); err == nil {
		t.Fatal("a non-member must NOT run a room's query_ref")
	}
}

// #4 (gate §3.4, D2): a member who loses incident access loses room content (revocation-aware read); and an owner-
// removed member loses content (membership RLS).
func TestWarRoom_RevocationAwareRead(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	member := wrUser(t, db, tid, auth.RoleAnalystT1)
	room, _ := s.CreateRoom(ctx, owner, uuid.New(), "case D")
	_ = s.Invite(ctx, owner, room.ID, member.UserID)
	if _, err := s.GetRoom(ctx, member, room.ID); err != nil {
		t.Fatalf("member reads while access holds: %v", err)
	}
	// Incident access revoked → content unavailable at read (not just at invite).
	accessErr = errTestNoIncident
	if _, err := s.GetRoom(ctx, member, room.ID); err == nil {
		t.Fatal("revocation-aware: a member who lost incident access must lose room content")
	}
	accessErr = nil
	// Owner removes the member → membership RLS denies content.
	if err := s.RemoveMember(ctx, owner, room.ID, member.UserID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.GetRoom(ctx, member, room.ID); err == nil {
		t.Fatal("a removed member must lose room content")
	}
}

var errTestNoIncident = pgTestErr("incident access revoked")

type pgTestErr string

func (e pgTestErr) Error() string { return string(e) }

// #5 (gate §3.5): entries are append-only — a member cannot UPDATE or DELETE an entry (no grant on the table).
func TestWarRoom_EntriesAppendOnly(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	room, _ := s.CreateRoom(ctx, owner, uuid.New(), "case E")
	e, err := s.AddEntry(ctx, owner, room.ID, EntryInput{Kind: "note", Body: "finding"})
	if err != nil {
		t.Fatalf("add note: %v", err)
	}
	upd := db.WithTenantActor(ctx, tid, owner.UserID, func(ctx context.Context, tx pgx.Tx) error {
		_, e2 := tx.Exec(ctx, `UPDATE investigation_war_room_entries SET body='tampered' WHERE id=$1`, e.ID)
		return e2
	})
	if upd == nil {
		t.Fatal("entries must be append-only: UPDATE must be denied")
	}
	del := db.WithTenantActor(ctx, tid, owner.UserID, func(ctx context.Context, tx pgx.Tx) error {
		_, e2 := tx.Exec(ctx, `DELETE FROM investigation_war_room_entries WHERE id=$1`, e.ID)
		return e2
	})
	if del == nil {
		t.Fatal("entries must be append-only: DELETE must be denied")
	}
}

// #6 (gate §3.6, D6): a membership change writes an audit row naming actor + target room + member.
func TestWarRoom_MembershipAudited(t *testing.T) {
	db := invDB(t)
	var accessErr error
	s := wrService(db, &accessErr)
	ctx := context.Background()
	tid := invTenant(t, db)
	owner := wrUser(t, db, tid, auth.RoleAnalystT2)
	member := wrUser(t, db, tid, auth.RoleAnalystT1)
	room, _ := s.CreateRoom(ctx, owner, uuid.New(), "case F")
	if err := s.Invite(ctx, owner, room.ID, member.UserID); err != nil {
		t.Fatalf("invite: %v", err)
	}
	var n int
	_ = db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM audit_log WHERE action='warroom.member_add' AND target=$1`,
			"war_room:"+room.ID.String()).Scan(&n)
	})
	if n == 0 {
		t.Fatal("a member invite must write an audit row (data-sharing grant)")
	}
}
