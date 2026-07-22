package contentlifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

var (
	ErrOutboundDisabled = errors.New("content: outbound acquisition disabled in air-gap mode")
	ErrSourceNotAllowed = errors.New("content: TAXII source not allowlisted")
)

type AcquisitionMode string

const (
	ModeAirGap    AcquisitionMode = "air-gap"
	ModeConnected AcquisitionMode = "connected"
)

// BundleFetcher is implemented by the platform's outbound adapter. The content
// lifecycle core never owns an HTTP client; connected acquisition remains behind
// the existing SSRF-safe outbound boundary.
type BundleFetcher interface {
	FetchSignedBundle(ctx context.Context, collectionURL string) ([]byte, error)
}

type Acquirer struct {
	Mode           AcquisitionMode
	AllowedSources map[string]struct{}
	Fetcher        BundleFetcher
}

// Acquire returns signed envelope bytes only. Both connected and manual paths
// must subsequently enter Verifier.VerifyAndParse and the same quarantine flow.
func (a Acquirer) Acquire(ctx context.Context, collectionURL string) ([]byte, error) {
	if a.Mode == ModeAirGap {
		return nil, ErrOutboundDisabled
	}
	if a.Mode != ModeConnected {
		return nil, fmt.Errorf("content: unsupported acquisition mode %q", a.Mode)
	}
	u, err := url.Parse(collectionURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, ErrSourceNotAllowed
	}
	canonical := u.Scheme + "://" + u.Host + u.EscapedPath()
	if _, ok := a.AllowedSources[canonical]; !ok {
		return nil, ErrSourceNotAllowed
	}
	if a.Fetcher == nil {
		return nil, errors.New("content: connected acquisition fetcher unavailable")
	}
	return a.Fetcher.FetchSignedBundle(ctx, canonical)
}
