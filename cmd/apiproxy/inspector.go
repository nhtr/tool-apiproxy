// Command apiproxy's inspector.go is the one file in this program that is
// allowed to see both internal/config (routes, profiles) and internal/secret
// (token metadata). internal/observe deliberately does not import either
// package — see RouteInfo's doc comment — so this is the single seam where
// the two meet on their way into the observability layer.
//
// The rule enforced here by hand, because the type system can't do it for
// us: only Meta fields that are already documented as safe to display may
// be copied into a RouteInfo. Meta.Fingerprint, not the token. Never add a
// field here without checking it can't carry a credential.
package main

import (
	"apiproxy/internal/config"
	"apiproxy/internal/observe"
	"apiproxy/internal/secret"
)

// inspector implements observe.Inspector by joining the route table with
// whatever token metadata the secret store can report without a passphrase.
type inspector struct {
	cfg   *config.Config
	store secret.Store // nil in dev mode (see loadTokens); tokens arrive via loaded instead.
	ring  *observe.Ring

	// loaded is the resolved set of profiles that currently have a token in
	// memory. It only ever contributes the boolean "is this profile
	// loaded" fact to a RouteInfo -- never a value from it -- which is why
	// routeInfo takes a plain profile-name set rather than the
	// proxy.TokenSource itself. In the normal (Windows, real Store) path
	// this is nil and HasToken instead comes from store.Meta.
	loaded map[string]bool
}

// newInspector builds the Inspector used by the /_proxy endpoints.
//
// store may be nil (dev-mode fallback on non-Windows platforms has no
// persisted metadata to query). In that case loadedProfiles names the
// profiles that were actually resolved into the running proxy's
// TokenSource, so /_proxy/routes can still report HasToken accurately
// instead of always showing false. loadedProfiles is ignored when store is
// non-nil, since Store.Meta is the more complete and authoritative source
// there.
func newInspector(cfg *config.Config, store secret.Store, loadedProfiles []string, ring *observe.Ring) *inspector {
	ins := &inspector{cfg: cfg, store: store, ring: ring}
	if store == nil && len(loadedProfiles) > 0 {
		ins.loaded = make(map[string]bool, len(loadedProfiles))
		for _, p := range loadedProfiles {
			ins.loaded[p] = true
		}
	}
	return ins
}

// Routes implements observe.Inspector.
func (ins *inspector) Routes() []observe.RouteInfo {
	out := make([]observe.RouteInfo, 0, len(ins.cfg.Routes))
	for _, r := range ins.cfg.Routes {
		info := routeInfo(r, ins.store)
		if ins.store == nil && r.Profile != "" && ins.loaded[r.Profile] {
			// Dev-mode fallback: no Meta to report, but we can at least
			// confirm a token is loaded for this profile, which is the one
			// fact /_proxy/routes exists to answer.
			info.HasToken = true
		}
		out = append(out, info)
	}
	return out
}

// Recent implements observe.Inspector.
func (ins *inspector) Recent(n int) []observe.Event {
	return ins.ring.Recent(n)
}

// Dropped implements observe.Inspector.
func (ins *inspector) Dropped() uint64 {
	return ins.ring.Dropped()
}

// routeInfo projects one config.Route, plus whatever Store.Meta knows about
// its profile, into the redacted view observe.Handler serves.
//
// Meta() never requires a passphrase (see internal/secret's doc comment on
// the Store interface), so this works before the operator has unlocked
// anything, and a missing profile is reported as HasToken: false rather than
// surfaced as an error -- "no token stored yet" is a normal, expected state,
// not a failure.
func routeInfo(r config.Route, store secret.Store) observe.RouteInfo {
	info := observe.RouteInfo{
		Alias:    r.Alias,
		Upstream: r.Upstream,
		Profile:  r.Profile,
		Header:   r.Header,
	}

	if r.Profile == "" || store == nil {
		return info
	}

	meta, err := store.Meta(r.Profile)
	if err != nil {
		// Most commonly secret.ErrNotFound: the route names a profile that
		// hasn't been `apiproxy login`-ed yet. Any other error is treated
		// the same way here -- the /_proxy/routes endpoint's job is to show
		// what's loaded, not to diagnose store corruption.
		return info
	}

	info.HasToken = true
	info.Fingerprint = meta.Fingerprint
	info.Issuer = meta.Issuer
	info.ExpiresAt = meta.ExpiresAt
	info.Expired = meta.Expired()
	return info
}
