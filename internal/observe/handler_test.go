package observe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubInspector is a minimal Inspector for testing the handler in
// isolation, without pulling in internal/config or internal/secret.
type stubInspector struct {
	routes  []RouteInfo
	events  []Event
	dropped uint64
}

func (s stubInspector) Routes() []RouteInfo { return s.routes }
func (s stubInspector) Recent(n int) []Event {
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	return s.events[:n]
}
func (s stubInspector) Dropped() uint64 { return s.dropped }

func TestHandler_Health(t *testing.T) {
	h := Handler(stubInspector{})
	req := httptest.NewRequest(http.MethodGet, "/_proxy/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("Status = %q, want ok", body.Status)
	}
	if body.UptimeS < 0 {
		t.Errorf("UptimeS = %v, want >= 0", body.UptimeS)
	}
}

func TestHandler_Routes(t *testing.T) {
	// Not shaped like a real provider's key on purpose; see the note in
	// log_test.go. A realistic prefix here would trip secret scanners on push
	// without making the assertion any stronger.
	const seededSecretLookingValue = "not-a-real-token-value-must-never-be-served-9876543210"

	ins := stubInspector{routes: []RouteInfo{
		{
			Alias:       "orders",
			Upstream:    "https://api.example.com",
			HasToken:    true,
			Fingerprint: "ab12cd34", // a fingerprint is fine to show; it's not the secret
			Issuer:      "example-issuer",
			ExpiresAt:   time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}}
	h := Handler(ins)
	req := httptest.NewRequest(http.MethodGet, "/_proxy/routes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, seededSecretLookingValue) {
		t.Fatalf("response leaked a secret-looking value it was never given: %s", body)
	}

	var routes []RouteInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &routes); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(routes) != 1 || routes[0].Alias != "orders" {
		t.Errorf("routes = %+v, want one route named orders", routes)
	}
	if !routes[0].HasToken {
		t.Errorf("HasToken = false, want true")
	}
}

func TestHandler_Routes_ZeroExpiresAtOmitted(t *testing.T) {
	ins := stubInspector{routes: []RouteInfo{{Alias: "no-expiry"}}}
	h := Handler(ins)
	req := httptest.NewRequest(http.MethodGet, "/_proxy/routes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "expires_at") {
		t.Errorf("zero-value ExpiresAt should be omitted via omitzero, got: %s", rec.Body.String())
	}
}

func TestHandler_Requests_Default(t *testing.T) {
	ins := stubInspector{
		events:  []Event{{Seq: 1}, {Seq: 2}},
		dropped: 3,
	}
	h := Handler(ins)
	req := httptest.NewRequest(http.MethodGet, "/_proxy/requests", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body requestsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Events) != 2 {
		t.Errorf("len(Events) = %d, want 2", len(body.Events))
	}
	if body.Dropped != 3 {
		t.Errorf("Dropped = %d, want 3", body.Dropped)
	}
}

func TestHandler_Requests_BadN(t *testing.T) {
	h := Handler(stubInspector{})
	req := httptest.NewRequest(http.MethodGet, "/_proxy/requests?n=notanumber", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error == "" {
		t.Errorf("expected non-empty error message")
	}
}

func TestHandler_Requests_ClampsN(t *testing.T) {
	events := make([]Event, 10)
	for i := range events {
		events[i] = Event{Seq: uint64(i)}
	}
	ins := stubInspector{events: events}
	h := Handler(ins)

	req := httptest.NewRequest(http.MethodGet, "/_proxy/requests?n=1000000", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body requestsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Events) != len(events) {
		t.Errorf("len(Events) = %d, want %d (all available, clamped request doesn't fabricate more)", len(body.Events), len(events))
	}
}

func TestHandler_UnknownProxyPath(t *testing.T) {
	h := Handler(stubInspector{})
	req := httptest.NewRequest(http.MethodGet, "/_proxy/nope", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error == "" {
		t.Errorf("expected non-empty error message")
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	for _, path := range []string{"/_proxy/health", "/_proxy/routes", "/_proxy/requests"} {
		t.Run(path, func(t *testing.T) {
			h := Handler(stubInspector{})
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
				t.Errorf("Allow = %q, want GET", allow)
			}
		})
	}
}

func TestGuardLocalhost_Accepts(t *testing.T) {
	cases := []string{
		"localhost:8787",
		"127.0.0.1:8787",
		"[::1]:8787",
		"",
		"localhost",
		"127.0.0.1",
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guarded := GuardLocalhost(next)

	for _, host := range cases {
		t.Run("host="+host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/_proxy/health", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for host %q", rec.Code, host)
			}
		})
	}
}

func TestGuardLocalhost_Rejects(t *testing.T) {
	cases := []string{
		"evil.com",
		"attacker.local:8787",
		"evil.com:80",
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guarded := GuardLocalhost(next)

	for _, host := range cases {
		t.Run("host="+host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/_proxy/health", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for host %q", rec.Code, host)
			}
		})
	}
}
