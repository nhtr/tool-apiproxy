// Package observe provides the proxy's observability surface: a redacting
// request log, a bounded in-memory history, and the local /_proxy endpoints.
//
// The goal is to let an AI agent debug a failing integration test without ever
// handing it the credential. Everything here is designed so that no code path
// can emit a token value.
package observe

import "time"

// Event is one completed proxy transaction, recorded after the response.
//
// Every field is safe to display. There is deliberately no field for header
// values, request bodies, or response bodies, because those are exactly where
// credentials and PII live. Keeping them out of the type means a future change
// cannot accidentally log them.
type Event struct {
	// Seq is a monotonic counter assigned by the Recorder, useful for spotting
	// dropped entries when the ring buffer wraps.
	Seq uint64 `json:"seq"`

	// At is when the request was received.
	At time.Time `json:"at"`

	// Alias is the route that matched, or "" if none did.
	Alias string `json:"alias"`

	Method string `json:"method"`

	// InPath is the path as the client sent it (after normalization).
	InPath string `json:"in_path"`

	// OutURL is the absolute upstream URL the request was sent to, with any
	// query string removed since queries often carry tokens or PII.
	OutURL string `json:"out_url"`

	// Status is the HTTP status returned to the client. 0 means the request
	// never produced a response.
	Status int `json:"status"`

	// DurationMS is the full round trip in milliseconds.
	DurationMS int64 `json:"duration_ms"`

	// RespBytes is the response body size written to the client.
	RespBytes int64 `json:"resp_bytes"`

	// Injected reports whether a credential header was added to this request.
	// This is the single most useful debugging signal the proxy offers: it
	// distinguishes "my test is wrong" from "the proxy did not authenticate".
	Injected bool `json:"injected"`

	// Error is a short, non-sensitive description of a transport failure.
	// Empty on success. Upstream response bodies never appear here.
	Error string `json:"error,omitempty"`
}

// Recorder accepts completed events. Implementations must be safe for
// concurrent use and must never block the request path for long.
type Recorder interface {
	Record(Event)
}

// NopRecorder discards events. Useful in tests and when history is disabled.
type NopRecorder struct{}

// Record implements Recorder.
func (NopRecorder) Record(Event) {}
