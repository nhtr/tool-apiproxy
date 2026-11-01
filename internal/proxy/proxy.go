// Package proxy implements the reverse-proxy core: it matches an inbound
// request to a fixed upstream route, injects a credential the client never
// sees, and forwards the request untouched otherwise.
//
// The central security property is that nothing in an inbound request may
// influence where it is sent. The upstream for each alias is fixed at
// New() time from config.Route.UpstreamURL. Host headers, absolute-form
// request URIs, query params, and other headers are never consulted for
// routing. See ServeHTTP and the Rewrite func below for where that is
// enforced.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"apiproxy/internal/config"
	"apiproxy/internal/observe"
)

// TokenSource resolves a profile name to a credential value. Implementations
// must not log the returned token; callers of Token are equally responsible
// for never writing it anywhere but the one outbound header.
type TokenSource interface {
	Token(profile string) (string, error)
}

// MapTokenSource is a simple in-memory TokenSource for tests and for the
// serve command once secrets are decrypted into memory.
type MapTokenSource map[string]string

// Token implements TokenSource. A missing profile is an error rather than an
// empty string so that a typo'd profile name fails loudly instead of
// forwarding a request with no credential.
func (m MapTokenSource) Token(profile string) (string, error) {
	v, ok := m[profile]
	if !ok {
		return "", fmt.Errorf("proxy: no token for profile %q", profile)
	}
	return v, nil
}

// Options configures a proxy Handler.
type Options struct {
	// Routes is the fixed alias -> upstream table. Required, non-empty.
	Routes []config.Route

	// Tokens resolves Route.Profile to a credential. May be nil only if no
	// route in Routes has a non-empty Profile.
	Tokens TokenSource

	// Recorder receives one Event per completed request. Defaults to
	// observe.NopRecorder.
	Recorder observe.Recorder

	// Transport is the RoundTripper used to reach upstreams. Defaults to a
	// pooling transport bounded by Timeout (see defaultTransport). Ignored
	// if non-nil: Timeout is then the caller's responsibility to apply.
	Transport http.RoundTripper

	// Timeout bounds how long the proxy waits for an upstream to start
	// responding: it is applied as the default transport's
	// ResponseHeaderTimeout (time from request sent to response headers
	// received). Defaults to 30s.
	//
	// It does NOT bound the time spent streaming the response body back to
	// the client. A context deadline covering the whole request would
	// cancel mid-copy on any response that doesn't fit in one read --
	// exactly wrong for a proxy whose job is to hand back real upstream
	// responses, including large or slowly-streamed ones. If you need a
	// hard ceiling on total request time, enforce it at the Transport you
	// pass in instead.
	Timeout time.Duration
}

// hopHeaders are deleted from the outbound request before any credential is
// injected. Every one of these is either spoofable by the client or would
// leak information about the proxy's own network position (client IP,
// original host, etc.) to the upstream. X-Forwarded-* has no wildcard form in
// net/http, so each member this proxy cares about is named individually.
var hopHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
}

// leakHeaders are stripped from the upstream response before it reaches the
// client. They describe the upstream's own server stack and are not this
// proxy's business to forward.
var leakHeaders = []string{
	"X-Powered-By",
	"Server",
	"X-AspNet-Version",
}

// handler is the proxy's http.Handler. It owns one httputil.ReverseProxy per
// route, built once at New() time so each proxy closes over a fixed,
// immutable target.
type handler struct {
	routes   map[string]*routeProxy
	recorder observe.Recorder
}

// routeProxy pairs a config.Route with the ReverseProxy configured to serve
// it.
type routeProxy struct {
	route config.Route
	rp    *httputil.ReverseProxy
}

// New builds the proxy handler described by opts.
func New(opts Options) (http.Handler, error) {
	if len(opts.Routes) == 0 {
		return nil, errors.New("proxy: no routes configured")
	}

	rec := opts.Recorder
	if rec == nil {
		rec = observe.NopRecorder{}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	transport := opts.Transport
	if transport == nil {
		transport = defaultTransport(timeout)
	}

	h := &handler{
		routes:   make(map[string]*routeProxy, len(opts.Routes)),
		recorder: rec,
	}

	for _, r := range opts.Routes {
		if r.Alias == config.ReservedPrefix {
			// config.Validate already rejects this, but defense in depth
			// costs nothing and keeps this package safe if ever used
			// without going through config loading.
			return nil, fmt.Errorf("proxy: route alias %q collides with the reserved proxy namespace", r.Alias)
		}
		if r.UpstreamURL == nil {
			return nil, fmt.Errorf("proxy: route %q has no parsed upstream URL (call config.Validate first)", r.Alias)
		}
		if r.Profile != "" && opts.Tokens == nil {
			return nil, fmt.Errorf("proxy: route %q requires profile %q but no TokenSource was supplied", r.Alias, r.Profile)
		}

		rp := newReverseProxy(r, opts.Tokens, transport)
		h.routes[r.Alias] = &routeProxy{route: r, rp: rp}
	}

	return h, nil
}

// reqState carries per-request facts from Rewrite/ErrorHandler (which have
// no return value usable by ServeHTTP) back to ServeHTTP, where the Event is
// built. It is allocated once per request in ServeHTTP and threaded through
// via context, then read back after rp.ServeHTTP returns.
type reqState struct {
	injected     bool
	tokenErr     error
	transportErr string
}

type reqStateKey struct{}

// ServeHTTP matches the first path segment to a route and forwards to it.
//
// All routing decisions happen here, before httputil.ReverseProxy is ever
// invoked. This is deliberate: path traversal, alias matching, and the
// reserved-prefix check are security-relevant and easier to reason about as
// one linear sequence than scattered across Director/Rewrite hooks.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Reject absolute-form request targets and any inbound Host spoofing
	// attempt up front. A client-controlled Host header or request-URI must
	// never be allowed to influence routing; the upstream is fixed by
	// config alone. r.URL.Host is only non-empty for proxy-style
	// (absolute-form) requests, which a normal reverse-proxy client never
	// sends; treat it as suspicious and refuse it outright rather than
	// silently ignoring it.
	if r.URL.IsAbs() || r.URL.Host != "" {
		writePlain(w, http.StatusBadRequest, "bad request")
		return
	}

	cleanPath, ok := normalizePath(r.URL.Path)
	if !ok {
		writePlain(w, http.StatusBadRequest, "invalid path")
		return
	}

	alias, rest := splitAlias(cleanPath)

	if alias == config.ReservedPrefix {
		// The top-level mux is expected to own this prefix. If a request
		// reaches this handler anyway, refuse it rather than forward it
		// upstream with a credential attached.
		writePlain(w, http.StatusNotFound, "not found")
		return
	}

	rt, found := h.routes[alias]
	if !found {
		// Deliberately generic: do not echo the attempted alias or list
		// configured aliases, since that would hand a probing client a map
		// of internal integrations.
		writePlain(w, http.StatusNotFound, "not found")
		return
	}

	// Rewrite the request path to "rest" (the part after the alias) so the
	// ReverseProxy's Rewrite func only has to join it with the fixed
	// upstream prefix.
	r.URL.Path = rest
	r.URL.RawPath = "" // force re-encoding from the cleaned Path.

	state := &reqState{}
	r = r.WithContext(context.WithValue(r.Context(), reqStateKey{}, state))

	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	rt.rp.ServeHTTP(sw, r)

	h.recorder.Record(observe.Event{
		Seq:        0, // assigned by the Recorder implementation, not here.
		At:         start,
		Alias:      alias,
		Method:     r.Method,
		InPath:     cleanPath,
		OutURL:     outURLNoQuery(rt.route.UpstreamURL, rest),
		Status:     sw.status,
		DurationMS: time.Since(start).Milliseconds(),
		RespBytes:  sw.bytes,
		Injected:   state.injected,
		Error:      state.transportErr,
	})
}

// newReverseProxy builds the ReverseProxy for one route. Each route gets its
// own instance so Rewrite and ModifyResponse can close over route-specific,
// immutable state instead of doing a map lookup per request.
func newReverseProxy(r config.Route, tokens TokenSource, transport http.RoundTripper) *httputil.ReverseProxy {
	target := r.UpstreamURL

	rp := &httputil.ReverseProxy{
		Transport: &tokenGateTransport{base: transport},

		Rewrite: func(pr *httputil.ProxyRequest) {
			// SetURL points Out at the fixed upstream and merges the
			// upstream's path prefix with whatever path remains after
			// alias-stripping (ServeHTTP already set it on the inbound
			// URL). SetXForwarded then adds X-Forwarded-For/Host/Proto
			// describing the real inbound connection; we delete those
			// right after, since this route's config may not want them
			// passed on, and in any case they must never be a vector for
			// the *client* to have supplied false values -- SetXForwarded
			// only ever writes values derived from pr.In, never from
			// pre-existing client headers, so this ordering is about
			// policy (strip them entirely) rather than spoofing.
			pr.SetURL(target)
			pr.SetXForwarded()

			state, _ := pr.Out.Context().Value(reqStateKey{}).(*reqState)

			// Strip headers the client could use to smuggle identity or
			// spoof origin info before any credential is added. This
			// includes the X-Forwarded-* trio SetXForwarded just set,
			// because this proxy's policy is to not reveal the client's
			// network position to the upstream at all.
			for _, hn := range hopHeaders {
				pr.Out.Header.Del(hn)
			}
			// Also remove whatever header this route injects into, so a
			// caller can't pre-seed it and have it survive if injection
			// is skipped (no profile) or ever changed from Set to Add.
			if r.Header != "" {
				pr.Out.Header.Del(r.Header)
			}

			if r.Profile == "" || tokens == nil {
				return
			}

			tok, err := tokens.Token(r.Profile)
			if err != nil {
				// Rewrite has no ResponseWriter and no way to abort the
				// request directly. Recording the error in reqState and
				// clearing the target host (see timeoutTransport) is what
				// stops this request from ever reaching the network;
				// ErrorHandler then turns it into a 503.
				if state != nil {
					state.tokenErr = err
				}
				return
			}

			val := tok
			if r.Scheme != "" {
				val = r.Scheme + " " + tok
			}
			pr.Out.Header.Set(r.Header, val)
			if state != nil {
				state.injected = true
			}
		},

		ModifyResponse: func(resp *http.Response) error {
			for _, hn := range leakHeaders {
				resp.Header.Del(hn)
			}
			return nil
		},

		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			// This fires only for transport-level failures (dial, TLS,
			// timeout) or for the token-error short-circuit below -- never
			// for a successful round trip, so upstream 4xx/5xx always
			// reach ModifyResponse and the client untouched.
			state, _ := req.Context().Value(reqStateKey{}).(*reqState)

			if state != nil && state.tokenErr != nil {
				// Never name the token value, only the profile, so an
				// operator can fix config without this response becoming
				// a secret-disclosure path itself.
				writePlain(w, http.StatusServiceUnavailable,
					fmt.Sprintf("proxy: could not obtain token for profile %q", r.Profile))
				if sw, ok := w.(*statusWriter); ok {
					_ = sw // status already recorded by writePlain via WriteHeader
				}
				return
			}

			if state != nil {
				state.transportErr = safeErrText(err)
			}

			// Generic body: never echo err.Error() to the client. It can
			// contain upstream hostnames, IPs, or TLS details that this
			// proxy exists partly to hide.
			writePlain(w, http.StatusBadGateway, "upstream unavailable")
		},
	}

	return rp
}

// errTokenUnavailable is returned by tokenGateTransport.RoundTrip when
// Rewrite recorded a token error, so the request never reaches the network.
var errTokenUnavailable = errors.New("proxy: token unavailable")

// tokenGateTransport short-circuits before any network I/O when Rewrite
// recorded a token error. This is what guarantees "Tokens.Token() failed"
// means the upstream is never called.
//
// This type used to also wrap every request in a context.WithTimeout and
// defer cancel() right here. That was a bug, not a feature: RoundTrip
// returns as soon as response headers arrive, but httputil.ReverseProxy
// streams the body afterward using the *same* request context. The
// deferred cancel fired the instant RoundTrip returned, so the body read
// was already bound to a cancelled context -- any response that didn't fit
// in the first read came back truncated with "unexpected EOF". Time-to-
// first-byte is bounded by the transport's ResponseHeaderTimeout instead
// (see defaultTransport), which cancels nothing once headers are in and so
// never touches the body stream.
type tokenGateTransport struct {
	base http.RoundTripper
}

func (t *tokenGateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if state, ok := req.Context().Value(reqStateKey{}).(*reqState); ok && state != nil && state.tokenErr != nil {
		return nil, errTokenUnavailable
	}
	return t.base.RoundTrip(req)
}

// defaultTransport returns a pooling transport with conservative timeouts.
// It mirrors http.DefaultTransport's shape but makes every timeout explicit
// instead of relying on library defaults that might change. headerTimeout
// becomes ResponseHeaderTimeout: the only phase of the round trip this
// package bounds beyond dial/handshake, since anything stricter would have
// to apply to the body stream too and that's exactly the bug this file's
// history exists to document.
func defaultTransport(headerTimeout time.Duration) http.RoundTripper {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		Proxy:                 nil, // never honor env proxy vars: the destination is fixed by config, not by the network.
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
	}
}

// normalizePath cleans p and reports whether it is safe to route.
//
// httputil.ReverseProxy does not clean or validate the inbound path, so
// "/orders/../admin" or its percent-encoded form would otherwise be joined
// onto the upstream path verbatim. Cleaning here, before alias matching, is
// what makes traversal attempts visible as a rejected request instead of a
// silently escaped one.
func normalizePath(raw string) (string, bool) {
	// Decode first so an encoded ".." (%2e%2e) is caught by the same check
	// as a literal one. net/http has already rejected most invalid percent
	// escapes by the time we see r.URL.Path, but PathUnescape is cheap
	// insurance.
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}

	if decoded == "" {
		decoded = "/"
	}
	if !strings.HasPrefix(decoded, "/") {
		decoded = "/" + decoded
	}

	// Reject any literal ".." segment outright rather than relying on
	// path.Clean's output. Clean would silently absorb a traversal that
	// tries to walk above the root (e.g. "/orders/../../etc" cleans to
	// "/etc" with no trace it ever went out of bounds), so the only
	// reliable place to catch the attempt is before cleaning erases the
	// evidence. Legitimate paths never need a literal ".." segment.
	for _, seg := range strings.Split(decoded, "/") {
		if seg == ".." {
			return "", false
		}
	}

	// Reject control bytes (including NUL). url.PathUnescape happily turns
	// "%00" into a literal NUL with no error, and path.Clean does not
	// strip it either. This isn't a route to a different destination (the
	// upstream is fixed regardless), but a NUL or other control byte in a
	// path has no legitimate use here and is cleaner to refuse outright
	// than to forward.
	for i := 0; i < len(decoded); i++ {
		if decoded[i] < 0x20 || decoded[i] == 0x7f {
			return "", false
		}
	}

	cleaned := path.Clean(decoded)

	// Preserve a trailing slash the client sent, since it can be
	// semantically significant to the upstream (e.g. collection vs. item
	// routes). Clean strips it except for the root.
	if strings.HasSuffix(decoded, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	return cleaned, true
}

// splitAlias extracts the first path segment (the alias) and returns the
// remainder as an absolute path suitable for joining onto an upstream
// prefix. For "/orders/v1/items" it returns ("orders", "/v1/items"). For
// "/orders" it returns ("orders", "/").
func splitAlias(cleanPath string) (alias, rest string) {
	trimmed := strings.TrimPrefix(cleanPath, "/")
	i := strings.IndexByte(trimmed, '/')
	if i < 0 {
		return trimmed, "/"
	}
	return trimmed[:i], trimmed[i:]
}

// outURLNoQuery renders the final upstream URL for recording purposes only,
// with the query string stripped since it can carry tokens or PII that must
// never land in the event history.
func outURLNoQuery(base *url.URL, rest string) string {
	u := *base
	u.Path = joinPath(base.Path, rest)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// joinPath mirrors net/http/httputil's singleJoiningSlash, the unexported
// function SetURL uses to join a route's upstream prefix with the client's
// remaining path. Kept local (and matched byte-for-byte in behavior) so
// outURLNoQuery can render the same path the request actually went to,
// without reaching into the live request after the round trip has mutated
// it.
func joinPath(prefix, rest string) string {
	aslash := strings.HasSuffix(prefix, "/")
	bslash := strings.HasPrefix(rest, "/")
	switch {
	case aslash && bslash:
		return prefix + rest[1:]
	case !aslash && !bslash:
		return prefix + "/" + rest
	}
	return prefix + rest
}

// safeErrText reduces a transport error to a short, non-sensitive string for
// the Event.Error field. It never includes the error's own message, which
// for net errors commonly embeds the upstream host or IP.
func safeErrText(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errTokenUnavailable) {
		return "token unavailable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "upstream timeout"
	}
	return "upstream transport error"
}

// writePlain writes a short, fixed, plain-text body. Centralizing this
// keeps every error path from this package free of anything that could leak
// internals: no stack traces, no echoed input, no upstream error text.
func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// statusWriter wraps http.ResponseWriter to capture the status code and
// byte count written, for the Event recorded after ServeHTTP returns.
//
// It implements http.Flusher and http.Hijacker by delegating to the
// underlying writer when those interfaces are present, so streaming
// responses and (if ever needed) connection hijacking both keep working
// through the wrapper. It also implements Unwrap so http.ResponseController
// (which net/http/httputil's ReverseProxy uses internally for things like
// SetReadDeadline/SetWriteDeadline) can walk past this wrapper to the real
// ResponseWriter instead of silently finding nothing and no-oping.
type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("proxy: underlying ResponseWriter does not support Hijack")
	}
	return hj.Hijack()
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController,
// so deadline/wrapper-aware features of net/http (and of httputil's
// ReverseProxy) can reach past this wrapper instead of degrading silently.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
