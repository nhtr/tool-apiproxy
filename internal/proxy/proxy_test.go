package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"apiproxy/internal/config"
	"apiproxy/internal/observe"
)

// testRecorder captures Events for assertions, safe for concurrent use even
// though these tests are sequential.
type testRecorder struct {
	mu     sync.Mutex
	events []observe.Event
}

func (r *testRecorder) Record(e observe.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *testRecorder) last() observe.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return observe.Event{}
	}
	return r.events[len(r.events)-1]
}

// mustRoute builds a single validated config.Route pointing at upstream.
func mustRoute(t *testing.T, alias, upstream, profile, header, scheme string) config.Route {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream %q: %v", upstream, err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if header == "" {
		header = "Authorization"
	}
	return config.Route{
		Alias:       alias,
		Upstream:    upstream,
		Profile:     profile,
		Header:      header,
		Scheme:      scheme,
		UpstreamURL: u,
	}
}

func TestHappyPath_InjectsCredentialAndJoinsPath(t *testing.T) {
	var gotAuth, gotPath, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders/v2", "corp-sso", "", "Bearer")
	h, err := New(Options{
		Routes: []config.Route{route},
		Tokens: MapTokenSource{"corp-sso": "secret-token"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/v1/items?foo=bar")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, "Bearer secret-token")
	}
	if gotPath != "/orders/v2/v1/items" {
		t.Errorf("upstream path = %q, want %q", gotPath, "/orders/v2/v1/items")
	}
	if gotQuery != "foo=bar" {
		t.Errorf("upstream query = %q, want %q", gotQuery, "foo=bar")
	}
}

func TestBareAliasWithNoTrailingPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders/v2", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// httputil.ReverseProxy's own path join (singleJoiningSlash) appends a
	// "/" when exactly one side already has one, which is the case for
	// "/orders/v2" + "/": it becomes "/orders/v2/". This is standard-library
	// behavior this package intentionally does not second-guess.
	if gotPath != "/orders/v2/" {
		t.Errorf("upstream path = %q, want %q", gotPath, "/orders/v2/")
	}
}

func TestHeaderSmuggling_ClientHeadersAreDropped(t *testing.T) {
	var gotAuth, gotXFF string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "corp-sso", "", "Bearer")
	h, err := New(Options{
		Routes: []config.Route{route},
		Tokens: MapTokenSource{"corp-sso": "real-token"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orders/items", nil)
	req.Header.Set("Authorization", "Bearer evil")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want injected %q", gotAuth, "Bearer real-token")
	}
	if gotXFF != "" {
		t.Errorf("upstream X-Forwarded-For = %q, want stripped (empty)", gotXFF)
	}
}

func TestOpenRelay_HostHeaderSpoofDoesNotRedirectOrigin(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Spoofed Host header: must have zero effect on where the request goes.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/orders/items", nil)
	req.Host = "evil.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (upstream should still be reached via fixed route)", resp.StatusCode)
	}
	if !upstreamHit {
		t.Fatalf("expected upstream to be hit via the fixed route despite spoofed Host")
	}
}

func TestOpenRelay_AbsoluteFormURIRejected(t *testing.T) {
	route := mustRoute(t, "orders", "http://127.0.0.1:1/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Build a request with an absolute-form request URI naming a different
	// host, as a misbehaving/malicious client might send to a proxy.
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv.URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", target.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	raw := "GET http://attacker.example.com/orders/items HTTP/1.1\r\nHost: " + target.Host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for absolute-form URI naming a different host", resp.StatusCode)
	}
}

func TestPathTraversal_Rejected(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []struct {
		name string
		path string
	}{
		{"literal dot-dot", "/orders/../admin"},
		{"percent-encoded dot-dot", "/orders/%2e%2e/admin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamHit = false
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if upstreamHit {
				t.Errorf("upstream was called, want never called on traversal attempt")
			}
		})
	}
}

func TestUnknownAliasAndReservedPrefix404(t *testing.T) {
	route := mustRoute(t, "orders", "http://127.0.0.1:1/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []struct {
		name string
		path string
	}{
		{"unknown alias", "/billing/v1/items"},
		{"reserved prefix", "/" + config.ReservedPrefix + "/history"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
		})
	}
}

func TestPassThrough_UpstreamErrorBodyAndStatusUntouched(t *testing.T) {
	const wantBody = `{"error":"insufficient_funds","code":42}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(wantBody))
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/fail")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (passed through from upstream)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != wantBody {
		t.Errorf("body = %q, want %q", string(body), wantBody)
	}
}

func TestNoProfileRoute_ForwardsWithoutAnyCredentialHeader(t *testing.T) {
	var sawAuth bool
	var authVal string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authVal = r.Header.Get("Authorization")
		sawAuth = authVal != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "public", upstream.URL+"/public", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/public/ping")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawAuth {
		t.Errorf("upstream saw Authorization = %q, want none for a no-profile route", authVal)
	}
}

func TestTokenError_503AndUpstreamNeverCalledAndTokenAbsent(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "missing-profile", "", "Bearer")
	h, err := New(Options{
		Routes: []config.Route{route},
		Tokens: MapTokenSource{"other-profile": "some-token"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/items")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if upstreamHit {
		t.Errorf("upstream was called, want never called when token resolution fails")
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "some-token") {
		t.Errorf("response body leaked a token value: %q", string(body))
	}
	if !strings.Contains(string(body), "missing-profile") {
		t.Errorf("response body = %q, want it to name the failing profile", string(body))
	}
}

func TestRecordedEvent_InjectedStatusAliasAndNoQueryInOutURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "corp-sso", "", "Bearer")
	rec := &testRecorder{}
	h, err := New(Options{
		Routes:   []config.Route{route},
		Tokens:   MapTokenSource{"corp-sso": "tok-with-secret-query-value"},
		Recorder: rec,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/items?access_token=tok-with-secret-query-value")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	ev := rec.last()
	if ev.Alias != "orders" {
		t.Errorf("Alias = %q, want %q", ev.Alias, "orders")
	}
	if !ev.Injected {
		t.Errorf("Injected = false, want true")
	}
	if ev.Status != http.StatusCreated {
		t.Errorf("Status = %d, want %d", ev.Status, http.StatusCreated)
	}
	if strings.Contains(ev.OutURL, "?") || strings.Contains(ev.OutURL, "access_token") {
		t.Errorf("OutURL = %q, must not carry a query string", ev.OutURL)
	}
}

func TestQueryStringPreservedThroughToUpstream(t *testing.T) {
	var gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/items?a=1&b=two&c=x%20y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	want := "a=1&b=two&c=x%20y"
	if gotQuery != want {
		t.Errorf("upstream query = %q, want %q", gotQuery, want)
	}
}

func TestResponseLeakHeadersStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.2.3")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/items")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("X-Powered-By"); v != "" {
		t.Errorf("X-Powered-By leaked: %q", v)
	}
	// resp.Header.Get("Server") can't be fully trusted since Go's HTTP
	// client/server machinery may set its own Server header value, but the
	// upstream-supplied "nginx/1.2.3" specifically must not appear.
	if v := resp.Header.Get("Server"); v == "nginx/1.2.3" {
		t.Errorf("Server header leaked upstream value: %q", v)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/orders/items")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 passed through", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/elsewhere" {
		t.Errorf("Location = %q, want pass-through", resp.Header.Get("Location"))
	}
}

func TestTransportFailure_502GenericBodyNoUpstreamDetails(t *testing.T) {
	// Point at a port nothing listens on, so the dial fails fast.
	route := mustRoute(t, "orders", "http://127.0.0.1:1/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/items")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "127.0.0.1") {
		t.Errorf("response body leaked upstream address: %q", string(body))
	}
}

// --- regression: tokenGateTransport must not truncate response bodies ---
//
// This is the C1 fix. The old timeoutTransport wrapped every request in a
// context.WithTimeout and deferred cancel() in RoundTrip. RoundTrip returns
// as soon as response headers arrive; httputil.ReverseProxy streams the
// body afterward using that same (by-then-cancelled) context, so any
// response that didn't fit in the first read came back truncated. These
// tests fail against that old code and must pass against the fix.

// TestLargeBody_NotTruncated reproduces the reviewer's repro: a multi-
// megabyte response must arrive at the client byte-for-byte intact, not
// cut off after the first read.
func TestLargeBody_NotTruncated(t *testing.T) {
	const size = 2 * 1024 * 1024 // 2 MiB, comfortably larger than any single socket read.
	want := deterministicBytes(size)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconvItoa(len(want)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(want)
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	rec := &testRecorder{}
	h, err := New(Options{Routes: []config.Route{route}, Recorder: rec})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v (this is exactly the 'unexpected EOF' regression if non-nil)", err)
	}

	if len(got) != len(want) {
		t.Fatalf("body length = %d, want %d", len(got), len(want))
	}
	if !bytesEqual(got, want) {
		t.Fatalf("body content mismatch (length matched but bytes differ)")
	}

	// RespBytes in the recorded Event must reflect the full transfer, not
	// a truncated prefix.
	ev := rec.last()
	if ev.RespBytes != int64(len(want)) {
		t.Errorf("recorded RespBytes = %d, want %d", ev.RespBytes, len(want))
	}
}

// TestStreamingChunks_AllArriveNoUnexpectedEOF covers a slow, flushed,
// multi-chunk response -- the other shape the old context-cancel bug broke,
// distinct from "one big body": here the upstream deliberately pauses
// between writes so RoundTrip's header-arrival point is nowhere near the
// end of the body.
func TestStreamingChunks_AllArriveNoUnexpectedEOF(t *testing.T) {
	chunks := []string{"first-chunk-", "second-chunk-", "third-chunk-", "fourth-chunk"}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Fatalf("test upstream ResponseWriter does not support Flusher")
		}
		w.WriteHeader(http.StatusOK)
		for _, c := range chunks {
			_, _ = w.Write([]byte(c))
			fl.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
	h, err := New(Options{Routes: []config.Route{route}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/orders/stream")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v (unexpected EOF here is the regression)", err)
	}

	want := strings.Join(chunks, "")
	if string(got) != want {
		t.Fatalf("body = %q, want %q", string(got), want)
	}
}

// TestStatusWriterFlush_ReachesBaseWriter confirms statusWriter.Flush
// actually calls through to the underlying ResponseWriter's Flush, which
// is what lets a streaming/chunked response reach the client incrementally
// instead of buffering until the handler returns.
func TestStatusWriterFlush_ReachesBaseWriter(t *testing.T) {
	base := &flushRecorder{ResponseWriter: httptest.NewRecorder()}
	sw := &statusWriter{ResponseWriter: base}

	sw.WriteHeader(http.StatusOK)
	_, _ = sw.Write([]byte("chunk"))
	sw.Flush()

	if !base.flushed {
		t.Errorf("statusWriter.Flush did not reach the base ResponseWriter's Flush")
	}
}

// flushRecorder wraps httptest.NewRecorder (which does not itself implement
// http.Flusher) to observe whether Flush was called through statusWriter.
type flushRecorder struct {
	http.ResponseWriter
	flushed bool
}

func (f *flushRecorder) Flush() {
	f.flushed = true
}

// TestStatusWriterUnwrap confirms the Unwrap method required for
// http.ResponseController to see past this wrapper is present and returns
// the real underlying writer.
func TestStatusWriterUnwrap(t *testing.T) {
	base := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: base}

	unwrapped, ok := any(sw).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatalf("statusWriter does not implement Unwrap() http.ResponseWriter")
	}
	if unwrapped.Unwrap() != base {
		t.Errorf("Unwrap() returned a different writer than the one statusWriter wraps")
	}
}

// --- Options.Timeout semantics: ResponseHeaderTimeout, not a body deadline ---

// TestTimeout_BoundsHeadersNotBody pins down the new, documented meaning of
// Options.Timeout: it must cut off an upstream that never sends response
// headers, but once headers have arrived it must not interrupt a slow body
// stream, even one slower than Timeout itself.
func TestTimeout_BoundsHeadersNotBody(t *testing.T) {
	t.Run("headers never arrive -> 502 within Timeout", func(t *testing.T) {
		// A listener that accepts but never writes anything back: headers
		// never arrive, so ResponseHeaderTimeout must fire.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// Accept and hold the connection open, writing nothing.
				go func() { <-make(chan struct{}) }() //nolint: this goroutine leaks for the test's short lifetime only
				_ = c
			}
		}()

		route := mustRoute(t, "orders", "http://"+ln.Addr().String()+"/orders", "", "", "")
		h, err := New(Options{Routes: []config.Route{route}, Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		srv := httptest.NewServer(h)
		defer srv.Close()

		start := time.Now()
		resp, err := http.Get(srv.URL + "/orders/slow")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		elapsed := time.Since(start)

		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status = %d, want 502 (ResponseHeaderTimeout should fire)", resp.StatusCode)
		}
		// Generous upper bound: the timeout is 300ms, this must not take
		// anywhere near the old 30s default.
		if elapsed > 5*time.Second {
			t.Errorf("took %v to fail, want roughly the configured Timeout (300ms), not a much longer default", elapsed)
		}
	})

	t.Run("headers arrive promptly, body streams slower than Timeout -> full body delivered", func(t *testing.T) {
		// Upstream answers headers immediately, then streams a body slower
		// (in total) than the configured Timeout. With Timeout applied
		// correctly as ResponseHeaderTimeout, this must still succeed in
		// full: the old whole-request-deadline bug would have cut this off.
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fl := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			fl.Flush()
			for i := 0; i < 5; i++ {
				_, _ = w.Write([]byte("x"))
				fl.Flush()
				time.Sleep(80 * time.Millisecond)
			}
		}))
		defer upstream.Close()

		route := mustRoute(t, "orders", upstream.URL+"/orders", "", "", "")
		// Timeout shorter than the total streaming time (5 * 80ms = 400ms),
		// but headers arrive almost instantly, so it must not matter.
		h, err := New(Options{Routes: []config.Route{route}, Timeout: 150 * time.Millisecond})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		srv := httptest.NewServer(h)
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/orders/slow-body")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v (a short Options.Timeout must not cut off an already-started body stream)", err)
		}
		if got, want := string(got), "xxxxx"; got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})
}

// --- small helpers for the regression tests above ---

// deterministicBytes returns a reproducible, non-trivial byte sequence of
// length n so a truncation bug shows up as both a length mismatch and a
// content mismatch, never as a false positive from all-zero bytes.
func deterministicBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251) // 251 is prime and < 256: avoids a short repeating pattern aligning with common buffer sizes.
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// strconvItoa avoids importing strconv solely for one Content-Length
// header in a test; kept trivial on purpose.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
