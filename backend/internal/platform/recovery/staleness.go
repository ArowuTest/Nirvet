package recovery

import (
	"fmt"
	"sort"
	"strings"
)

// StalenessSnapshot is the state recovered from the backup. The authoritative
// values are captured outside that backup (for example in the recovery catalogue
// or post-backup tombstone ledger) so a restore cannot certify itself by comparing
// only with its own stale contents.
type StalenessSnapshot struct {
	ActiveContentVersions map[string]int64
	ErasureWatermark      int64
	ConsumedIdempotency   map[string]struct{}
	SentNotifications     map[string]struct{}
	CompletedSOARRuns     map[string]struct{}
	SessionGeneration     int64
}

// StalenessAuthority is the minimum state the restored deployment must honour
// before serving. It represents decisions made at or after the backup boundary.
type StalenessAuthority struct {
	MinimumContentVersions map[string]int64
	MinimumErasureWatermark int64
	ConsumedIdempotency     map[string]struct{}
	SentNotifications       map[string]struct{}
	CompletedSOARRuns       map[string]struct{}
	MinimumSessionGeneration int64
}

// ValidateStalenessSafety refuses a restore that would reactivate superseded
// content, resurrect data erased after the snapshot, replay durable work, or
// revive pre-failure sessions. Empty authoritative state is not accepted because
// the absence of a post-backup ledger is itself a recovery finding.
func ValidateStalenessSafety(restored StalenessSnapshot, authority StalenessAuthority) (string, error) {
	if len(authority.MinimumContentVersions) == 0 {
		return "", fmt.Errorf("recovery: authoritative content-version ledger is empty")
	}
	if authority.MinimumErasureWatermark <= 0 {
		return "", fmt.Errorf("recovery: authoritative erasure watermark is unavailable")
	}
	if authority.MinimumSessionGeneration <= 0 {
		return "", fmt.Errorf("recovery: authoritative session generation is unavailable")
	}

	var failures []string
	for scope, minimum := range authority.MinimumContentVersions {
		if strings.TrimSpace(scope) == "" || minimum <= 0 {
			return "", fmt.Errorf("recovery: invalid authoritative content version entry")
		}
		if restored.ActiveContentVersions[scope] < minimum {
			failures = append(failures, fmt.Sprintf("content:%s:%d<%d", scope, restored.ActiveContentVersions[scope], minimum))
		}
	}
	if restored.ErasureWatermark < authority.MinimumErasureWatermark {
		failures = append(failures, fmt.Sprintf("erasure-watermark:%d<%d", restored.ErasureWatermark, authority.MinimumErasureWatermark))
	}
	failures = append(failures, missingKeys("idempotency", restored.ConsumedIdempotency, authority.ConsumedIdempotency)...)
	failures = append(failures, missingKeys("notification", restored.SentNotifications, authority.SentNotifications)...)
	failures = append(failures, missingKeys("soar", restored.CompletedSOARRuns, authority.CompletedSOARRuns)...)
	if restored.SessionGeneration < authority.MinimumSessionGeneration {
		failures = append(failures, fmt.Sprintf("session-generation:%d<%d", restored.SessionGeneration, authority.MinimumSessionGeneration))
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return "", fmt.Errorf("recovery: stale or replayable restored state: %s", strings.Join(failures, ", "))
	}

	return fmt.Sprintf("content scopes=%d; erasure watermark=%d; replay ledgers=%d/%d/%d; session generation=%d",
		len(authority.MinimumContentVersions), restored.ErasureWatermark,
		len(authority.ConsumedIdempotency), len(authority.SentNotifications), len(authority.CompletedSOARRuns),
		restored.SessionGeneration), nil
}

func missingKeys(kind string, restored, authority map[string]struct{}) []string {
	var failures []string
	for key := range authority {
		if strings.TrimSpace(key) == "" {
			failures = append(failures, kind+":empty-authoritative-key")
			continue
		}
		if _, ok := restored[key]; !ok {
			failures = append(failures, kind+":"+key+":missing")
		}
	}
	return failures
}
