package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"apiproxy/internal/config"
	"apiproxy/internal/observe"
	"apiproxy/internal/secret"
)

// --- envVarForProfile ---

func TestEnvVarForProfile(t *testing.T) {
	cases := []struct {
		profile string
		want    string
	}{
		{"corp-sso", "APIPROXY_TOKEN_CORP_SSO"},
		{"orders.v2", "APIPROXY_TOKEN_ORDERS_V2"},
		{"simple", "APIPROXY_TOKEN_SIMPLE"},
		{"a-b.c-d", "APIPROXY_TOKEN_A_B_C_D"},
		{"UPPER", "APIPROXY_TOKEN_UPPER"},
	}
	for _, tc := range cases {
		t.Run(tc.profile, func(t *testing.T) {
			got := envVarForProfile(tc.profile)
			if got != tc.want {
				t.Errorf("envVarForProfile(%q) = %q, want %q", tc.profile, got, tc.want)
			}
		})
	}
}

// --- inspector adapter ---

func TestRouteInfo_HasTokenAndFingerprintAndExpired(t *testing.T) {
	store := secret.NewMemStore()

	// Profile "present" has a token stored; "absent" never gets one.
	if err := store.Put("present", "shh-token-value", ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	routes := []config.Route{
		{Alias: "a", Upstream: "https://a.example", Profile: "present", Header: "Authorization"},
		{Alias: "b", Upstream: "https://b.example", Profile: "absent", Header: "Authorization"},
		{Alias: "c", Upstream: "https://c.example"}, // no profile at all
	}

	infos := make([]observe.RouteInfo, 0, len(routes))
	for _, r := range routes {
		infos = append(infos, routeInfo(r, store))
	}

	if len(infos) != 3 {
		t.Fatalf("len(infos) = %d, want 3", len(infos))
	}

	wantFP := secret.Fingerprint("shh-token-value")
	a := infos[0]
	if !a.HasToken {
		t.Errorf("route a: HasToken = false, want true")
	}
	if a.Fingerprint != wantFP {
		t.Errorf("route a: Fingerprint = %q, want %q", a.Fingerprint, wantFP)
	}
	if a.Expired {
		t.Errorf("route a: Expired = true, want false (no exp claim)")
	}

	b := infos[1]
	if b.HasToken {
		t.Errorf("route b: HasToken = true, want false (profile never stored)")
	}
	if b.Fingerprint != "" {
		t.Errorf("route b: Fingerprint = %q, want empty", b.Fingerprint)
	}

	c := infos[2]
	if c.HasToken {
		t.Errorf("route c: HasToken = true, want false (no profile configured)")
	}
}

func TestRouteInfo_NilStoreIsSafe(t *testing.T) {
	r := config.Route{Alias: "a", Upstream: "https://a.example", Profile: "x"}
	info := routeInfo(r, nil)
	if info.HasToken {
		t.Errorf("HasToken = true with nil store, want false")
	}
}

// TestInspectorRoutes_DevModeLoadedProfiles covers the nil-store fallback
// path: with no secret.Store at all (as on non-Windows platforms),
// newInspector still has to report HasToken correctly using only the list
// of profiles that were actually resolved into the running TokenSource.
func TestInspectorRoutes_DevModeLoadedProfiles(t *testing.T) {
	cfg := &config.Config{
		Listen: config.DefaultListen,
		Routes: []config.Route{
			{Alias: "orders", Upstream: "https://api.example/orders", Profile: "corp-sso"},
			{Alias: "billing", Upstream: "https://api.example/billing", Profile: "billing-sso"},
			{Alias: "public", Upstream: "https://api.example/public"},
		},
	}

	ring := observe.NewRing(10)
	ins := newInspector(cfg, nil, []string{"corp-sso"}, ring)

	routes := ins.Routes()
	byAlias := make(map[string]observe.RouteInfo, len(routes))
	for _, r := range routes {
		byAlias[r.Alias] = r
	}

	if !byAlias["orders"].HasToken {
		t.Errorf("orders: HasToken = false, want true (profile was loaded)")
	}
	if byAlias["billing"].HasToken {
		t.Errorf("billing: HasToken = true, want false (profile was not loaded)")
	}
	if byAlias["public"].HasToken {
		t.Errorf("public: HasToken = true, want false (no profile at all)")
	}
}

// TestRouteInfoJSON_NeverLeaksTokenOrPassphrase guards the actual security
// property the inspector exists for: whatever gets marshaled to JSON for
// /_proxy/routes must not contain the token value or the passphrase used
// to store it, no matter how RouteInfo's field set evolves.
func TestRouteInfoJSON_NeverLeaksTokenOrPassphrase(t *testing.T) {
	const secretToken = "super-secret-token-xyz"
	const secretPassphrase = "correct-horse-battery-staple"

	store := secret.NewMemStore()
	if err := store.Put("corp-sso", secretToken, secretPassphrase); err != nil {
		t.Fatalf("Put: %v", err)
	}

	r := config.Route{Alias: "orders", Upstream: "https://api.example", Profile: "corp-sso", Header: "Authorization"}
	info := routeInfo(r, store)

	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := string(b)

	if strings.Contains(out, secretToken) {
		t.Errorf("marshaled RouteInfo leaked the token: %s", out)
	}
	if strings.Contains(out, secretPassphrase) {
		t.Errorf("marshaled RouteInfo leaked the passphrase: %s", out)
	}
	if !strings.Contains(out, `"has_token":true`) {
		t.Errorf("expected has_token:true in %s", out)
	}
}

// --- inspector.Routes end-to-end against config.Config ---

func TestInspectorRoutes(t *testing.T) {
	store := secret.NewMemStore()
	if err := store.Put("corp-sso", "tok-1", ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	cfg := &config.Config{
		Listen: config.DefaultListen,
		Routes: []config.Route{
			{Alias: "orders", Upstream: "https://api.example/orders", Profile: "corp-sso", Header: "Authorization"},
			{Alias: "public", Upstream: "https://api.example/public"},
		},
	}

	ring := observe.NewRing(10)
	ins := newInspector(cfg, store, nil, ring)

	routes := ins.Routes()
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if !routes[0].HasToken {
		t.Errorf("orders route: HasToken = false, want true")
	}
	if routes[1].HasToken {
		t.Errorf("public route: HasToken = true, want false")
	}

	if ins.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0 on a fresh ring", ins.Dropped())
	}
	if len(ins.Recent(10)) != 0 {
		t.Errorf("Recent(10) = %v, want empty on a fresh ring", ins.Recent(10))
	}
}

// --- validateListen ---

func TestValidateListen(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"loopback v4", "127.0.0.1:9000", false},
		{"loopback name", "localhost:9000", false},
		{"all interfaces", "0.0.0.0:9000", true},
		{"no port", "127.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateListen(tc.addr)
			if tc.wantErr && err == nil {
				t.Errorf("validateListen(%q) = nil error, want an error", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateListen(%q) = %v, want no error", tc.addr, err)
			}
		})
	}
}

// --- loadTokensFromEnv ---

func TestLoadTokensFromEnv(t *testing.T) {
	t.Setenv("APIPROXY_TOKEN_CORP_SSO", "tok-value")

	tokens, err := loadTokensFromEnv([]string{"corp-sso"}, &discardWriter{})
	if err != nil {
		t.Fatalf("loadTokensFromEnv: %v", err)
	}

	got, err := tokens.Token("corp-sso")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "tok-value" {
		t.Errorf("Token = %q, want %q", got, "tok-value")
	}
}

func TestLoadTokensFromEnv_MissingVarIsAnError(t *testing.T) {
	_, err := loadTokensFromEnv([]string{"never-set-profile"}, &discardWriter{})
	if err == nil {
		t.Fatalf("expected an error for a missing env var")
	}
	if !strings.Contains(err.Error(), "APIPROXY_TOKEN_NEVER_SET_PROFILE") {
		t.Errorf("error = %v, want it to name the expected env var", err)
	}
}

// discardWriter satisfies io.Writer for tests that need an output sink
// without pulling in io/ioutil or os.DevNull.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// sanity: Meta.Expired via a JWT-shaped token round-tripped through the
// mem store, confirming the inspector surfaces Expired correctly end to
// end (not just that routeInfo copies the field).
func TestRouteInfo_ExpiredJWT(t *testing.T) {
	store := secret.NewMemStore()
	expired := makeExpiredJWT(t)
	if err := store.Put("expiring", expired, ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	r := config.Route{Alias: "a", Upstream: "https://a.example", Profile: "expiring"}
	info := routeInfo(r, store)

	if !info.Expired {
		t.Errorf("Expired = false, want true for a token with exp in the past")
	}
}

// makeExpiredJWT builds a minimal JWT-shaped string (header.payload.sig)
// with an exp claim one hour in the past, using the same base64url
// encoding internal/secret's inspectJWT expects.
func makeExpiredJWT(t *testing.T) string {
	t.Helper()
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	header := enc(`{"alg":"none"}`)
	exp := time.Now().Add(-time.Hour).Unix()
	payload := enc(fmt.Sprintf(`{"iss":"https://issuer.example","exp":%d}`, exp))
	sig := enc("sig")
	return header + "." + payload + "." + sig
}
