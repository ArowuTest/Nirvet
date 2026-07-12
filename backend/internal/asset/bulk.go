package asset

// #188 LAUNCH #5 (LIGHT) — asset bulk ingest. Import many assets in one request (e.g. from an asset/CMDB export
// the frontend parsed to JSON). A bulk endpoint is a NEW INPUT SURFACE, so it is bounded: a row cap, a per-field
// length guard, and the platform's 1 MiB body cap (httpx.Decode). Each row goes through the EXISTING Create — so
// validation, kind/criticality checks, idempotent upsert-on-ref, and the criticality-change audit are IDENTICAL
// to single create (no divergence). CSV formula-injection is handled at EXPORT (the reporting serializer), so a
// value like "=cmd()" is stored verbatim here and neutralised only when it leaves as CSV — the round-trip is safe.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

const (
	maxBulkRows = 1000 // per request (body is additionally capped at 1 MiB by httpx.Decode)
	maxFieldLen = 512  // per identifying field — bounds a single pathological row
)

// BulkResult reports a partial-success import: how many rows landed and which failed (with why).
type BulkResult struct {
	Imported int           `json:"imported"`
	Failed   int           `json:"failed"`
	Failures []BulkFailure `json:"failures,omitempty"`
}

// BulkFailure is one row that did not import (a data/validation problem — infrastructure errors abort the batch).
type BulkFailure struct {
	Index int    `json:"index"`
	Ref   string `json:"ref,omitempty"`
	Error string `json:"error"`
}

// BulkCreate imports many assets, reusing Create per row. Data errors (4xx — bad kind/criticality, missing ref)
// are recorded per row and the batch continues; an infrastructure error (5xx — DB/RLS failure) ABORTS the whole
// batch and is returned, so a partial import can never silently mask an outage. Tenant-scoped via the principal.
func (s *Service) BulkCreate(ctx context.Context, p auth.Principal, items []CreateInput) (*BulkResult, error) {
	if len(items) == 0 {
		return nil, httpx.ErrBadRequest("no items to import")
	}
	if len(items) > maxBulkRows {
		return nil, httpx.ErrBadRequest("too many rows (max 1000 per request)")
	}
	res := &BulkResult{}
	for i := range items {
		in := items[i]
		if len(strings.TrimSpace(in.Ref)) > maxFieldLen || len(strings.TrimSpace(in.Name)) > maxFieldLen {
			res.Failed++
			res.Failures = append(res.Failures, BulkFailure{Index: i, Ref: trunc(in.Ref), Error: "ref/name too long (max 512)"})
			continue
		}
		if _, err := s.Create(ctx, p, in); err != nil {
			var ae *httpx.APIError
			if errors.As(err, &ae) && ae.Status >= http.StatusInternalServerError {
				return nil, err // infrastructure failure — abort, don't silently half-import
			}
			res.Failed++
			res.Failures = append(res.Failures, BulkFailure{Index: i, Ref: trunc(in.Ref), Error: rowErr(err)})
			continue
		}
		res.Imported++
	}
	return res, nil
}

func trunc(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func rowErr(err error) string {
	var ae *httpx.APIError
	if errors.As(err, &ae) {
		return ae.Message
	}
	return err.Error()
}
