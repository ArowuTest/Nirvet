package recovery

import (
	"strings"
	"testing"
)

func safeStalenessState() (StalenessSnapshot, StalenessAuthority) {
	restored := StalenessSnapshot{
		ActiveContentVersions: map[string]int64{"global:tip": 4, "tenant-a:rules": 8},
		ErasureWatermark:      120,
		ConsumedIdempotency:   map[string]struct{}{"idem-1": {}},
		SentNotifications:     map[string]struct{}{"notification-1": {}},
		CompletedSOARRuns:     map[string]struct{}{"soar-1": {}},
		SessionGeneration:     15,
	}
	authority := StalenessAuthority{
		MinimumContentVersions:   map[string]int64{"global:tip": 4, "tenant-a:rules": 8},
		MinimumErasureWatermark:  120,
		ConsumedIdempotency:      map[string]struct{}{"idem-1": {}},
		SentNotifications:        map[string]struct{}{"notification-1": {}},
		CompletedSOARRuns:        map[string]struct{}{"soar-1": {}},
		MinimumSessionGeneration: 15,
	}
	return restored, authority
}

func TestValidateStalenessSafetyPassesCompleteAuthoritativeState(t *testing.T) {
	restored, authority := safeStalenessState()
	evidence, err := ValidateStalenessSafety(restored, authority)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(evidence) == "" {
		t.Fatal("successful staleness validation returned no evidence")
	}
}

func TestValidateStalenessSafetyDetectsSupersededContent(t *testing.T) {
	restored, authority := safeStalenessState()
	restored.ActiveContentVersions["tenant-a:rules"] = 7
	if _, err := ValidateStalenessSafety(restored, authority); err == nil || !strings.Contains(err.Error(), "content:tenant-a:rules") {
		t.Fatalf("superseded content was not detected: %v", err)
	}
}

func TestValidateStalenessSafetyDetectsErasureResurrection(t *testing.T) {
	restored, authority := safeStalenessState()
	restored.ErasureWatermark = 119
	if _, err := ValidateStalenessSafety(restored, authority); err == nil || !strings.Contains(err.Error(), "erasure-watermark") {
		t.Fatalf("stale erasure watermark was not detected: %v", err)
	}
}

func TestValidateStalenessSafetyDetectsReplayableDurableWork(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*StalenessSnapshot)
		want   string
	}{
		{name: "idempotency", mutate: func(s *StalenessSnapshot) { delete(s.ConsumedIdempotency, "idem-1") }, want: "idempotency:idem-1:missing"},
		{name: "notification", mutate: func(s *StalenessSnapshot) { delete(s.SentNotifications, "notification-1") }, want: "notification:notification-1:missing"},
		{name: "soar", mutate: func(s *StalenessSnapshot) { delete(s.CompletedSOARRuns, "soar-1") }, want: "soar:soar-1:missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restored, authority := safeStalenessState()
			tc.mutate(&restored)
			if _, err := ValidateStalenessSafety(restored, authority); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("replayable state was not detected: %v", err)
			}
		})
	}
}

func TestValidateStalenessSafetyDetectsRevivedSessions(t *testing.T) {
	restored, authority := safeStalenessState()
	restored.SessionGeneration = 14
	if _, err := ValidateStalenessSafety(restored, authority); err == nil || !strings.Contains(err.Error(), "session-generation") {
		t.Fatalf("stale session generation was not detected: %v", err)
	}
}

func TestValidateStalenessSafetyRequiresExternalAuthority(t *testing.T) {
	restored, _ := safeStalenessState()
	if _, err := ValidateStalenessSafety(restored, StalenessAuthority{}); err == nil {
		t.Fatal("restore certified itself without an authoritative post-backup ledger")
	}
}
