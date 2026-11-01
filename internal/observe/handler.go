package observe

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RouteInfo is the safe-to-display view of one configured route. It is
// built by the caller (the command that owns internal/config and
// internal/secret), never by this package — that's the whole reason
// Inspector exists instead of this package importing those types directly.
// Keeping that import boundary means a credential can never reach this
// package's code paths in the first place, not just "isn't printed".
type RouteInfo struct {
	Alias       string    `json:"alias"`
	Upstream    string    `json:"upstream"`
	Profile     string    `json:"profile,omitempty"`
	Header      string    `json:"header,omitempty"`
	HasToken    bool      `json:"has_token"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	Expired     bool      `json:"expired"`
}

// Inspector is everything the /_proxy endpoints need, supplied by the
// caller. Routes() returns the already-redacted route view; Recent and
// Dropped mirror Ring's read side so the handler doesn't need a concrete
// *Ring.
type Inspector interface {
	Routes() []RouteInfo
	Recent(n int) []Event
	Dropped() uint64
}

// maxRequestsN caps how many events /_proxy/requests can return in one
// call, so a careless "?n=1000000" can't force a huge response body.
const maxRequestsN = 500

// requestsResponse is the JSON body for GET /_proxy/requests.
type requestsResponse struct {
	Events  []Event `json:"events"`
	Dropped uint64  `json:"dropped"`
}

// healthResponse is the JSON body for GET /_proxy/health.
type healthResponse struct {
	Status  string  `json:"status"`
	UptimeS float64 `json:"uptime_s"`
}

// errorResponse is the JSON body for every non-2xx response this package
// produces, so an agent parsing the output always finds the same shape.
type errorResponse struct {
	Error string `json:"error"`
}

// Handler serves the local /_proxy/* debugging endpoints. These are never
// forwarded upstream; they exist so an agent (or a human) can ask "did my
// request even get made, and did it get authenticated" without ever being
// handed the credential that answers it.
func Handler(ins Inspector) http.Handler {
	started := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/_proxy/health", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{
			Status:  "ok",
			UptimeS: time.Since(started).Seconds(),
		})
	})

	mux.HandleFunc("/_proxy/routes", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, ins.Routes())
	})

	mux.HandleFunc("/_proxy/requests", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethod(w, r, http.MethodGet) {
			return
		}

		n := 20 // default: enough to see a recent test run without flooding the output
		if raw := r.URL.Query().Get("n"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "n must be an integer"})
				return
			}
			n = parsed
		}
		if n <= 0 || n > maxRequestsN {
			n = maxRequestsN
		}

		writeJSON(w, http.StatusOK, requestsResponse{
			Events:  ins.Recent(n),
			Dropped: ins.Dropped(),
		})
	})

	mux.HandleFunc("/_proxy/", func(w http.ResponseWriter, r *http.Request) {
		// Anything under /_proxy/ that isn't one of the routes above.
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no such endpoint: " + r.URL.Path})
	})

	return mux
}

// allowMethod writes a 405 with an Allow header and returns false if the
// request method isn't GET. All /_proxy endpoints are read-only, so GET is
// the only method any of them accept.
func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
	return false
}

// writeJSON writes an indented JSON body — this output is meant to be read
// directly by a human or an agent, not minified — with headers set so
// nothing caches a response that reflects live, fast-changing state.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// GuardLocalhost rejects requests whose Host header doesn't name localhost.
//
// The listener itself is already loopback-only, so this looks redundant —
// but a browser can be tricked into resolving an attacker-controlled
// hostname to 127.0.0.1 (DNS rebinding) and then send that Host header to a
// server that's listening there. Checking Host costs nothing and closes
// that gap; it's a second boundary, not the only one.
func GuardLocalhost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalHost(r.Host) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid host"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalHost reports whether host (as found in an http.Request.Host,
// possibly with a port) names localhost. An empty Host is allowed: some
// HTTP/1.0 clients and direct socket tools omit it, and there's no DNS
// involved for those to rebind.
func isLocalHost(host string) bool {
	if host == "" {
		return true
	}

	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	// SplitHostPort errors on a bare host with no port (e.g. "localhost" or
	// "::1" without brackets+port) — in that case hostname is already
	// correct as the original string.

	hostname = strings.ToLower(hostname)
	// Strip IPv6 brackets if SplitHostPort didn't already (e.g. bare "[::1]").
	hostname = strings.TrimPrefix(hostname, "[")
	hostname = strings.TrimSuffix(hostname, "]")

	switch hostname {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
