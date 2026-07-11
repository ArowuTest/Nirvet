// Package httpx holds HTTP helpers: JSON responses, typed API errors, and middleware.
package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
)

// APIError is a typed error that maps to an HTTP status and a stable code.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Message }

// Common constructors.
func ErrBadRequest(msg string) *APIError { return &APIError{http.StatusBadRequest, "bad_request", msg} }
func ErrUnauthorized(msg string) *APIError {
	return &APIError{http.StatusUnauthorized, "unauthorized", msg}
}
func ErrForbidden(msg string) *APIError { return &APIError{http.StatusForbidden, "forbidden", msg} }
func ErrNotFound(msg string) *APIError  { return &APIError{http.StatusNotFound, "not_found", msg} }
func ErrConflict(msg string) *APIError  { return &APIError{http.StatusConflict, "conflict", msg} }
func ErrInternal(msg string) *APIError {
	return &APIError{http.StatusInternalServerError, "internal", msg}
}
func ErrTooManyRequests(msg string) *APIError {
	return &APIError{http.StatusTooManyRequests, "rate_limited", msg}
}

// ErrBadGateway signals an upstream dependency failure (e.g. an external IdP).
func ErrBadGateway(msg string) *APIError { return &APIError{http.StatusBadGateway, "bad_gateway", msg} }

// ErrUnavailable signals a TRANSIENT, retryable failure (503) — e.g. a dependency needed to make a fail-closed
// security decision is momentarily unreachable, so the request is denied-when-uncertain WITHOUT being treated as a
// permanent failure (the caller may retry and succeed on recovery).
func ErrUnavailable(msg string) *APIError {
	return &APIError{http.StatusServiceUnavailable, "unavailable", msg}
}

// JSON writes v as a JSON response with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// Error writes an error response, mapping *APIError to its status and hiding
// internal error detail from clients.
func Error(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		JSON(w, apiErr.Status, map[string]any{"error": apiErr})
		return
	}
	JSON(w, http.StatusInternalServerError, map[string]any{
		"error": &APIError{Status: 500, Code: "internal", Message: "internal server error"},
	})
}

// maxBodyBytes caps JSON request bodies (defence against oversized payloads).
const maxBodyBytes = 1 << 20 // 1 MiB

// Decode reads a JSON request body into v, returning a bad-request APIError on
// failure. The body is size-limited and unknown fields are rejected.
func Decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBadRequest("invalid request body: " + err.Error())
	}
	return nil
}
