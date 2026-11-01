// Command apiproxy is a local reverse proxy that holds an API token so an
// AI agent (or anything else) can run integration tests against a real
// upstream without ever being handed the credential. See the subcommand
// help text below for usage; this file is just dispatch plus the pieces
// that are either genuinely global (version, token-env lookup, listen
// validation) or awkward to place in cmd-specific files because multiple
// subcommands share them.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"apiproxy/internal/config"
	"apiproxy/internal/observe"
	"apiproxy/internal/proxy"
	"apiproxy/internal/secret"

	"golang.org/x/term"
)

// version is overwritten at build time via:
//
//	-ldflags "-X main.version=<value>"
//
// See the Makefile's windows/build targets. Defaults to "dev" for `go run`
// and any build that doesn't pass ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "apiproxy:", err)
		os.Exit(1)
	}
}

// run is main's logic, factored out so tests can exercise argument parsing
// and subcommand dispatch without calling os.Exit.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return errors.New("no subcommand given")
	}

	switch args[0] {
	case "-h", "-help", "--help", "help":
		printUsage(stdout)
		return nil
	case "-version", "--version", "version":
		fmt.Fprintln(stdout, "apiproxy", version)
		return nil
	case "init":
		return cmdInit(args[1:], stdout)
	case "login":
		return cmdLogin(args[1:], stdin, stdout, stderr)
	case "logout":
		return cmdLogout(args[1:], stdout)
	case "status":
		return cmdStatus(args[1:], stdout)
	case "serve":
		return cmdServe(args[1:], stdin, stdout, stderr)
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// printUsage lists every subcommand with a one-line description and a
// couple of realistic examples. This is what a developer sees running
// `apiproxy` with no args, and it's also what they'll paste into a chat
// with an AI agent asking "how do I use this tool", so it has to stand on
// its own.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `apiproxy: a local reverse proxy that holds your API token so an
AI agent can run integration tests without ever seeing the credential.

usage:
  apiproxy <command> [flags]

commands:
  init              write a starter config file
  login <profile>   store a token for a profile (prompts, never echoes it)
  logout <profile>  remove a stored token
  status            show configured routes and stored token metadata
  serve             run the proxy
  version           print the build version

global flags (accepted by most subcommands):
  -config <path>    path to config.toml (default: %s)
  -secrets <dir>    directory for encrypted token blobs (default: %s)

examples:
  apiproxy init
  apiproxy login corp-sso
  apiproxy serve
  apiproxy serve -listen 127.0.0.1:9000 -timeout 15s
  curl http://127.0.0.1:8787/orders/v1/items
`, defaultConfigPath(), defaultSecretDir())
}

// defaultConfigPath and defaultSecretDir resolve config.ConfigPath and
// config.SecretDir, falling back to an empty string (which just means the
// -config/-secrets flag becomes effectively required) if the OS refuses to
// name a user directory. That failure is rare enough (a broken HOME/
// AppData) that surfacing it only when the path is actually needed is
// friendlier than crashing at startup.
func defaultConfigPath() string {
	p, err := config.ConfigPath()
	if err != nil {
		return ""
	}
	return p
}

func defaultSecretDir() string {
	d, err := config.SecretDir()
	if err != nil {
		return ""
	}
	return d
}

// --- init ---

func cmdInit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to write config.toml")
	force := fs.Bool("force", false, "overwrite an existing config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("no config path: pass -config explicitly")
	}

	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to overwrite", *cfgPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", *cfgPath, err)
	}

	dir := filepath.Dir(*cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.WriteFile(*cfgPath, []byte(config.Sample), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *cfgPath, err)
	}

	fmt.Fprintf(stdout, "wrote %s\n", *cfgPath)
	fmt.Fprintf(stdout, "next: edit it to point at your upstream, then run:\n")
	fmt.Fprintf(stdout, "  apiproxy login <profile>\n")
	return nil
}

// --- login ---

func cmdLogin(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config.toml")
	secretsDir := fs.String("secrets", defaultSecretDir(), "directory for encrypted token blobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: apiproxy login <profile>")
	}
	profile := fs.Arg(0)

	store, err := openStore(*secretsDir)
	if err != nil {
		return err
	}

	stdinFd := int(os.Stdin.Fd())
	interactive := term.IsTerminal(stdinFd)

	token, err := readToken(stdin, stdinFd, interactive, stdout)
	if err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("empty token")
	}

	passphrase, err := readPassphrase(stdin, stdinFd, interactive, stdout, stderr)
	if err != nil {
		return err
	}

	if err := store.Put(profile, token, passphrase); err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	meta, err := store.Meta(profile)
	if err != nil {
		// Put just succeeded, so this would only happen on a concurrent
		// delete or a store bug; report it but don't treat the login as
		// having failed.
		fmt.Fprintf(stdout, "stored token for %q, but could not re-read its metadata: %v\n", profile, err)
		return nil
	}

	fmt.Fprintf(stdout, "stored token for profile %q (fingerprint %s)\n", profile, meta.Fingerprint)
	if !meta.ExpiresAt.IsZero() {
		fmt.Fprintf(stdout, "token expires: %s\n", meta.ExpiresAt.Format(time.RFC3339))
	}

	warnIfProfileUnused(stdout, *cfgPath, profile)
	return nil
}

// readToken reads the credential from the user. In an interactive terminal
// it's read hidden via term.ReadPassword so it never echoes and never
// lands in shell history; otherwise (piped stdin, as in CI: `echo $TOK |
// apiproxy login x`) it's read as a plain line.
func readToken(stdin io.Reader, fd int, interactive bool, stdout io.Writer) (string, error) {
	if interactive {
		fmt.Fprint(stdout, "token: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stdout)
		if err != nil {
			return "", fmt.Errorf("read token: %w", err)
		}
		return string(b), nil
	}

	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readPassphrase reads and confirms the passphrase in interactive mode, or
// takes it from APIPROXY_PASSPHRASE (or empty) when stdin isn't a terminal,
// since there's no second stream to prompt on standard input a second time
// after the token has already consumed it.
func readPassphrase(stdin io.Reader, fd int, interactive bool, stdout, stderr io.Writer) (string, error) {
	if !interactive {
		if p := os.Getenv("APIPROXY_PASSPHRASE"); p != "" {
			fmt.Fprintln(stderr, "warning: using APIPROXY_PASSPHRASE from the environment; "+
				"this puts the passphrase in the process environment block, which any other process "+
				"running as your user can read, defeating the at-rest protection against a same-user "+
				"attacker. Prefer the interactive prompt when you can.")
			return p, nil
		}
		return "", nil
	}

	fmt.Fprint(stdout, "passphrase (optional, hidden): ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(stdout)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}

	fmt.Fprint(stdout, "confirm passphrase: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(stdout)
	if err != nil {
		return "", fmt.Errorf("read passphrase confirmation: %w", err)
	}

	if string(p1) != string(p2) {
		return "", errors.New("passphrases did not match")
	}

	if len(p1) == 0 {
		fmt.Fprintln(stderr, "warning: no passphrase set; this token can be decrypted by any process running as your user")
	}

	return string(p1), nil
}

// warnIfProfileUnused prints a non-fatal warning when the config doesn't
// reference profile from any route -- a login with a typo'd profile name
// would otherwise silently store a token that nothing ever uses.
func warnIfProfileUnused(stdout io.Writer, cfgPath, profile string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// No config yet, or it doesn't parse: not login's job to fail over
		// that, just skip the cross-check silently.
		return
	}
	for _, p := range cfg.Profiles() {
		if p == profile {
			return
		}
	}
	fmt.Fprintf(stdout, "warning: no route in %s references profile %q\n", cfgPath, profile)
}

// --- logout ---

func cmdLogout(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	secretsDir := fs.String("secrets", defaultSecretDir(), "directory for encrypted token blobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: apiproxy logout <profile>")
	}
	profile := fs.Arg(0)

	store, err := openStore(*secretsDir)
	if err != nil {
		return err
	}

	if err := store.Delete(profile); err != nil {
		return fmt.Errorf("delete %q: %w", profile, err)
	}
	fmt.Fprintf(stdout, "removed token for profile %q (if it existed)\n", profile)
	return nil
}

// --- status ---

func cmdStatus(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config.toml")
	secretsDir := fs.String("secrets", defaultSecretDir(), "directory for encrypted token blobs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	store, err := openStore(*secretsDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "config: %s\n", *cfgPath)
	fmt.Fprintf(stdout, "listen: %s\n\n", cfg.Listen)

	fmt.Fprintln(stdout, "routes:")
	for _, r := range cfg.Routes {
		line := fmt.Sprintf("  %-16s -> %s", r.Alias, r.Upstream)
		if r.Profile == "" {
			fmt.Fprintln(stdout, line+"  (no credential)")
			continue
		}

		meta, err := store.Meta(r.Profile)
		if err != nil {
			fmt.Fprintln(stdout, line+fmt.Sprintf("  profile=%s (no token stored)", r.Profile))
			continue
		}

		status := fmt.Sprintf("profile=%s fingerprint=%s created=%s passphrase=%s",
			r.Profile, meta.Fingerprint, meta.CreatedAt.Format("2006-01-02"), yesNo(meta.HasPassphrase))
		if meta.Issuer != "" {
			status += " issuer=" + meta.Issuer
		}
		if !meta.ExpiresAt.IsZero() {
			status += " expires=" + meta.ExpiresAt.Format(time.RFC3339)
			if meta.Expired() {
				status += " EXPIRED"
			}
		}
		fmt.Fprintln(stdout, line+"  "+status)
	}

	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// --- serve ---

func cmdServe(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config.toml")
	secretsDir := fs.String("secrets", defaultSecretDir(), "directory for encrypted token blobs")
	listenOverride := fs.String("listen", "", "override the listen address from config (must be loopback)")
	historyN := fs.Int("history", 200, "number of recent requests to keep for /_proxy/requests")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request upstream timeout")
	quiet := fs.Bool("quiet", false, "suppress the per-request log line")
	noAuthPrompt := fs.Bool("no-auth-prompt", false, "skip the passphrase prompt (profiles with a passphrase will fail to decrypt)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if *listenOverride != "" {
		// Reuse config's own loopback validation instead of re-implementing
		// it, so "serve -listen" can never be looser than what a config
		// file is allowed to say.
		addr, err := validateListen(*listenOverride)
		if err != nil {
			return err
		}
		cfg.Listen = addr
	}

	tokens, store, loadedProfiles, devMode, err := loadTokens(cfg, *secretsDir, *noAuthPrompt, stdin, stdout, stderr)
	if err != nil {
		return err
	}

	ring := observe.NewRing(*historyN)
	var recorders []observe.Recorder
	recorders = append(recorders, ring)

	logger := observe.NewLogger(stdout)
	if !*quiet {
		recorders = append(recorders, logger)
	}

	h, err := proxy.New(proxy.Options{
		Routes:   cfg.Routes,
		Tokens:   tokens,
		Recorder: observe.Tee(recorders...),
		Timeout:  *timeout,
	})
	if err != nil {
		return fmt.Errorf("build proxy: %w", err)
	}

	ins := newInspector(cfg, store, loadedProfiles, ring)

	mux := http.NewServeMux()
	mux.Handle("/_proxy/", observe.Handler(ins))
	mux.Handle("/", h)

	guarded := observe.GuardLocalhost(mux)

	srv := &http.Server{
		Handler:           guarded,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout is deliberately unset. It would cap the entire
		// response including the body, which cuts off large or streaming
		// upstream responses -- exactly the truncation bug the proxy lane
		// is fixing in parallel. Don't "complete the set" by adding it
		// back; per-upstream-request timing is already handled by the
		// -timeout flag passed into proxy.Options.
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	printServeBanner(stdout, cfg, devMode)

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		fmt.Fprintln(stdout, "\nshutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

// printServeBanner prints the block a developer pastes to an AI agent: the
// listen address, each alias with its upstream and token status, the
// /_proxy URLs, and a ready-to-use API_BASE_URL line for the first route.
func printServeBanner(w io.Writer, cfg *config.Config, devMode bool) {
	if devMode {
		fmt.Fprintln(w, "*** DEV MODE: no encrypted token storage on this platform. ***")
		fmt.Fprintln(w, "*** Tokens were read from APIPROXY_TOKEN_<PROFILE> env vars. ***")
		fmt.Fprintln(w, "*** Do not use this mode to hold a real production credential. ***")
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "apiproxy listening on http://%s\n", cfg.Listen)
	fmt.Fprintln(w, "while running, tokens are held in memory and readable by any process under your user account.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "routes:")
	for _, r := range cfg.Routes {
		fmt.Fprintf(w, "  /%-16s -> %s\n", r.Alias, r.Upstream)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "debug endpoints:")
	fmt.Fprintf(w, "  http://%s/_proxy/health\n", cfg.Listen)
	fmt.Fprintf(w, "  http://%s/_proxy/routes\n", cfg.Listen)
	fmt.Fprintf(w, "  http://%s/_proxy/requests\n", cfg.Listen)

	if len(cfg.Routes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "API_BASE_URL=http://%s/%s\n", cfg.Listen, cfg.Routes[0].Alias)
	}
	fmt.Fprintln(w)
}

// validateListen reuses config.Config.Validate's loopback check by running
// a throwaway Config through it, instead of duplicating the host-allowlist
// logic here. A -listen flag that would be rejected in a config file must
// be rejected the same way on the command line.
func validateListen(addr string) (string, error) {
	c := &config.Config{
		Listen: addr,
		Routes: []config.Route{{Alias: "x", Upstream: "https://example.invalid"}},
	}
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("-listen %q: %w", addr, err)
	}
	return c.Listen, nil
}

// openStore opens the platform secret store, translating ErrUnsupported
// into a clear instruction rather than a raw "unsupported" error wherever
// a command needs a real (non-dev-mode) store: login, logout, and status
// all require one, since on non-Windows there is nothing else they could
// operate on.
func openStore(dir string) (secret.Store, error) {
	if dir == "" {
		return nil, errors.New("no secrets directory: pass -secrets explicitly")
	}
	store, err := secret.Open(dir)
	if errors.Is(err, secret.ErrUnsupported) {
		return nil, fmt.Errorf("%w (this subcommand needs encrypted storage, which only exists on Windows; "+
			"on other platforms use APIPROXY_TOKEN_<PROFILE> env vars with `apiproxy serve` instead)", err)
	}
	if err != nil {
		return nil, fmt.Errorf("open secret store at %s: %w", dir, err)
	}
	return store, nil
}

// loadTokens builds the TokenSource serve hands to the proxy.
//
// On Windows (or wherever secret.Open succeeds) it prompts once for the
// passphrase and decrypts every profile referenced by cfg.Profiles() into a
// MapTokenSource. On every other platform secret.Open returns
// secret.ErrUnsupported, and this falls back to reading each profile's
// token from an env var -- that's the one way this tool gets smoke-tested
// on macOS/Linux dev machines, since there is no DPAPI equivalent to build
// a real encrypted store on top of there.
//
// Returns the store too (nil in dev-mode fallback) and the list of profiles
// that were actually resolved, so the caller can hand both to the
// inspector for /_proxy/routes metadata.
func loadTokens(cfg *config.Config, secretsDir string, noAuthPrompt bool, stdin io.Reader, stdout, stderr io.Writer) (proxy.TokenSource, secret.Store, []string, bool, error) {
	profiles := cfg.Profiles()

	if secretsDir == "" {
		return nil, nil, nil, false, errors.New("no secrets directory: pass -secrets explicitly")
	}

	store, err := secret.Open(secretsDir)
	if errors.Is(err, secret.ErrUnsupported) {
		tokens, err := loadTokensFromEnv(profiles, stdout)
		if err != nil {
			return nil, nil, nil, true, err
		}
		return tokens, nil, profiles, true, nil
	}
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("open secret store at %s: %w", secretsDir, err)
	}

	if len(profiles) == 0 {
		return proxy.MapTokenSource{}, store, nil, false, nil
	}

	passphrase := os.Getenv("APIPROXY_PASSPHRASE")
	fromEnv := passphrase != ""
	if fromEnv {
		fmt.Fprintln(stderr, "warning: using APIPROXY_PASSPHRASE from the environment; "+
			"this puts the passphrase in the process environment block, which any other process "+
			"running as your user can read, defeating the at-rest protection against a same-user "+
			"attacker. Prefer the interactive prompt when you can.")
	}
	if !fromEnv && !noAuthPrompt {
		stdinFd := int(os.Stdin.Fd())
		if term.IsTerminal(stdinFd) {
			fmt.Fprint(stdout, "passphrase: ")
			b, err := term.ReadPassword(stdinFd)
			fmt.Fprintln(stdout)
			if err != nil {
				return nil, nil, nil, false, fmt.Errorf("read passphrase: %w", err)
			}
			passphrase = string(b)
		}
	}

	tokens := make(proxy.MapTokenSource, len(profiles))
	for _, p := range profiles {
		tok, err := store.Get(p, passphrase)
		switch {
		case errors.Is(err, secret.ErrBadPassphrase):
			return nil, nil, nil, false, fmt.Errorf("profile %q: passphrase looks wrong: %w", p, err)
		case errors.Is(err, secret.ErrNotFound):
			return nil, nil, nil, false, fmt.Errorf("profile %q has no stored token; run: apiproxy login %s", p, p)
		case err != nil:
			return nil, nil, nil, false, fmt.Errorf("profile %q: %w", p, err)
		}
		tokens[p] = tok
	}

	return tokens, store, profiles, false, nil
}

// loadTokensFromEnv is the non-Windows dev fallback: it reads each
// profile's token from APIPROXY_TOKEN_<PROFILE> (see envVarForProfile) so
// the team can smoke-test the proxy on macOS/Linux without DPAPI.
func loadTokensFromEnv(profiles []string, stdout io.Writer) (proxy.TokenSource, error) {
	tokens := make(proxy.MapTokenSource, len(profiles))
	for _, p := range profiles {
		envName := envVarForProfile(p)
		tok := os.Getenv(envName)
		if tok == "" {
			return nil, fmt.Errorf("dev mode (no encrypted storage): set %s to the token for profile %q", envName, p)
		}
		tokens[p] = tok
	}
	return tokens, nil
}

// envVarForProfile derives the env var name loadTokensFromEnv reads for a
// given profile: uppercase, with '-' and '.' turned into '_' since those
// characters are valid in a profile name (see secret.profileRe) but not in
// a shell-friendly env var name.
func envVarForProfile(profile string) string {
	upper := strings.ToUpper(profile)
	upper = strings.ReplaceAll(upper, "-", "_")
	upper = strings.ReplaceAll(upper, ".", "_")
	return "APIPROXY_TOKEN_" + upper
}
