// Package config loads and validates the apiproxy route table.
//
// The config file never contains secrets. It is safe to commit and share
// across a team. Tokens live only in the secret store (see internal/secret).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// ReservedPrefix is the URL path namespace owned by the proxy itself.
// Requests under this prefix are answered locally and are NEVER forwarded
// upstream, so they can never carry the injected credential.
const ReservedPrefix = "_proxy"

// DefaultListen binds the IPv4 loopback explicitly. Binding by IP rather than
// by the name "localhost" avoids any dependence on name resolution.
const DefaultListen = "127.0.0.1:8787"

// aliasRe keeps aliases to a conservative, URL-safe shape. This matters because
// an alias becomes the first path segment of every proxied request.
var aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Config is the whole tool configuration.
type Config struct {
	// Listen is a host:port for the local listener. Must be a loopback host.
	Listen string `toml:"listen"`

	// Routes maps alias -> upstream. Declared in TOML as repeated [[route]].
	Routes []Route `toml:"route"`
}

// Route binds one local alias to exactly one fixed upstream origin.
//
// The upstream is fixed at config time on purpose. Nothing in an incoming
// request may influence where the request is sent; otherwise the proxy would
// become an open relay and leak the stored token to an arbitrary host.
type Route struct {
	// Alias is the first path segment clients use, e.g. "orders" for
	// http://127.0.0.1:8787/orders/v1/items.
	Alias string `toml:"alias"`

	// Upstream is the absolute base URL requests are forwarded to. Any path
	// component here is used as a prefix for the forwarded path.
	Upstream string `toml:"upstream"`

	// Profile names the secret-store entry holding this route's token.
	// Empty means this route forwards without injecting a credential.
	Profile string `toml:"profile"`

	// Header is the request header the credential is written to.
	// Defaults to "Authorization".
	Header string `toml:"header"`

	// Scheme is the credential prefix, e.g. "Bearer" produces
	// "Authorization: Bearer <token>". Empty sends the raw token value.
	Scheme string `toml:"scheme"`

	// UpstreamURL is the parsed form of Upstream, filled in by Validate.
	UpstreamURL *url.URL `toml:"-"`
}

// ErrNoConfig reports that no config file exists yet.
var ErrNoConfig = errors.New("config: no config file found")

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNoConfig, path)
	}
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var c Config
	if err := toml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate applies defaults and rejects configurations that would be unsafe or
// ambiguous. It mutates c in place, so callers get normalized values.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if err := checkLoopback(c.Listen); err != nil {
		return err
	}
	if len(c.Routes) == 0 {
		return errors.New("config: no [[route]] defined")
	}

	seen := make(map[string]bool, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]

		if !aliasRe.MatchString(r.Alias) {
			return fmt.Errorf("config: route %d: invalid alias %q "+
				"(allowed: lowercase letters, digits, '-', '_'; must start alphanumeric)", i, r.Alias)
		}
		if r.Alias == ReservedPrefix {
			return fmt.Errorf("config: alias %q is reserved for the proxy's own endpoints", r.Alias)
		}
		if seen[r.Alias] {
			return fmt.Errorf("config: duplicate alias %q", r.Alias)
		}
		seen[r.Alias] = true

		u, err := url.Parse(r.Upstream)
		if err != nil {
			return fmt.Errorf("config: route %q: invalid upstream %q: %w", r.Alias, r.Upstream, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("config: route %q: upstream scheme must be http or https, got %q", r.Alias, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("config: route %q: upstream %q has no host", r.Alias, r.Upstream)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("config: route %q: upstream must not contain a query or fragment", r.Alias)
		}
		// Normalize: drop any trailing slash so path joining is predictable.
		u.Path = strings.TrimSuffix(u.Path, "/")
		r.UpstreamURL = u

		if r.Header == "" {
			r.Header = "Authorization"
		}
		if r.Profile == "" && r.Scheme != "" {
			return fmt.Errorf("config: route %q: scheme set but no profile to read a token from", r.Alias)
		}
	}
	return nil
}

// Route returns the route for an alias.
func (c *Config) Route(alias string) (*Route, bool) {
	for i := range c.Routes {
		if c.Routes[i].Alias == alias {
			return &c.Routes[i], true
		}
	}
	return nil, false
}

// Profiles lists the distinct non-empty profile names referenced by routes.
func (c *Config) Profiles() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if r.Profile != "" && !seen[r.Profile] {
			seen[r.Profile] = true
			out = append(out, r.Profile)
		}
	}
	return out
}

// checkLoopback rejects any listen address that would expose the proxy beyond
// this machine. The proxy holds a live credential, so a non-loopback bind would
// hand it to anyone who can reach the port.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: invalid listen %q (want host:port): %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("config: listen %q must include a port", addr)
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	}
	return fmt.Errorf("config: listen host %q is not loopback; "+
		"apiproxy holds a live credential and must not be reachable off-machine", host)
}

// ConfigPath returns the path to the route table.
// Windows: %AppData%\apiproxy\config.toml
func ConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: locate user config dir: %w", err)
	}
	return filepath.Join(dir, "apiproxy", "config.toml"), nil
}

// SecretDir returns the directory holding encrypted token blobs. It is
// deliberately separate from the config directory: config is shareable,
// this is not, and on Windows this maps to the non-roaming profile so blobs
// are never synced to a server.
// Windows: %LocalAppData%\apiproxy
func SecretDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("config: locate user cache dir: %w", err)
	}
	return filepath.Join(dir, "apiproxy"), nil
}

// Sample is the starter config written by `apiproxy init`.
const Sample = `# apiproxy route table.
# This file holds NO secrets and is safe to commit.
# Tokens are stored encrypted; add one with: apiproxy login <profile>

listen = "127.0.0.1:8787"

# Requests to http://127.0.0.1:8787/orders/... are forwarded to the upstream
# below with an "Authorization: Bearer <token>" header injected.
[[route]]
alias    = "orders"
upstream = "https://api.corp.internal/orders/v2"
profile  = "corp-sso"
scheme   = "Bearer"
`
