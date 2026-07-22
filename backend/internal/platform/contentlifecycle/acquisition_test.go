package contentlifecycle

import (
	"context"
	"errors"
	"testing"
)

type countingFetcher struct {
	calls int
	body  []byte
}

func (f *countingFetcher) FetchSignedBundle(_ context.Context, _ string) ([]byte, error) {
	f.calls++
	return append([]byte(nil), f.body...), nil
}

func TestAcquirer_AirGapMakesZeroOutboundCalls(t *testing.T) {
	fetcher := &countingFetcher{body: []byte("signed")}
	a := Acquirer{Mode: ModeAirGap, Fetcher: fetcher}
	_, err := a.Acquire(context.Background(), "https://tip.example/taxii/collection")
	if !errors.Is(err, ErrOutboundDisabled) {
		t.Fatalf("want outbound disabled, got %v", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("air-gap attempted %d outbound calls", fetcher.calls)
	}
}

func TestAcquirer_ConnectedRequiresExactAllowlistedHTTPSCollection(t *testing.T) {
	fetcher := &countingFetcher{body: []byte("signed")}
	a := Acquirer{
		Mode: ModeConnected,
		AllowedSources: map[string]struct{}{
			"https://tip.example/taxii/collection": {},
		},
		Fetcher: fetcher,
	}
	got, err := a.Acquire(context.Background(), "https://tip.example/taxii/collection")
	if err != nil || string(got) != "signed" || fetcher.calls != 1 {
		t.Fatalf("allowlisted acquire failed: body=%q calls=%d err=%v", got, fetcher.calls, err)
	}
	for _, source := range []string{
		"http://tip.example/taxii/collection",
		"https://evil.example/taxii/collection",
		"https://user@tip.example/taxii/collection",
	} {
		if _, err := a.Acquire(context.Background(), source); !errors.Is(err, ErrSourceNotAllowed) {
			t.Fatalf("source %q should be refused, got %v", source, err)
		}
	}
	if fetcher.calls != 1 {
		t.Fatalf("refused sources reached fetcher; calls=%d", fetcher.calls)
	}
}
