// Package secret stores API tokens at rest.
//
// Threat model, stated plainly so nobody over-trusts this tool:
//
//   - Protects against: the token blob being copied off the machine, read by a
//     different Windows user, or leaking through a repo, backup, or roaming
//     profile sync. DPAPI CurrentUser scope plus the passphrase (mixed in as
//     DPAPI's optionalEntropy) cover this: without the passphrase, the blob
//     cannot be decrypted even by something that stole it.
//   - Does NOT protect against: a process already running as the same Windows
//     user while `apiproxy serve` is up. The passphrase only guards the
//     blob at rest; once serve decrypts a token, it sits as a plain string in
//     that process's memory for as long as serve runs, and any process
//     running as your user can read another process's memory (e.g.
//     OpenProcess+ReadProcessMemory, no special privilege required). DPAPI's
//     CurrentUser scope is a *user* boundary, not a process boundary, and
//     nothing in this package changes that while serve is live.
//
// If the agent must never be able to obtain the token at all, same-user
// isn't enough: run it under a separate OS user, a container, or a VM.
// Same-user is a convenience posture here, not a security boundary.
package secret

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound reports that no entry exists for a profile.
var ErrNotFound = errors.New("secret: profile not found")

// ErrUnsupported reports that the platform has no secure store available.
var ErrUnsupported = errors.New("secret: encrypted storage is only implemented on Windows")

// ErrBadPassphrase reports a failed decrypt, which in practice means the
// passphrase was wrong or the blob belongs to another user or machine.
var ErrBadPassphrase = errors.New("secret: cannot decrypt (wrong passphrase, or blob not created by this user on this machine)")

// profileRe keeps profile names safe to use as a filename.
var profileRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Store persists tokens encrypted at rest.
//
// Implementations are platform-specific: DPAPI on Windows, and a refusing stub
// elsewhere so the rest of the tool still compiles and tests on macOS/Linux.
type Store interface {
	// Put encrypts token for profile. passphrase may be empty, which means the
	// blob is protected by the OS user key alone.
	Put(profile, token, passphrase string) error

	// Get decrypts the token for profile.
	Get(profile, passphrase string) (string, error)

	// Delete removes the entry. Deleting a missing profile is not an error.
	Delete(profile string) error

	// List names the stored profiles. It must not require a passphrase, so it
	// reads only the unencrypted envelope.
	List() ([]string, error)

	// Meta returns non-sensitive facts about a stored entry without decrypting
	// the token.
	Meta(profile string) (Meta, error)
}

// Meta is the safe-to-display summary of a stored token. It deliberately has
// no field that could carry the token value.
type Meta struct {
	Profile string `json:"profile"`

	// Fingerprint is a short SHA-256 prefix of the token. It lets a human or an
	// agent confirm *which* token is loaded, and notice when it changes,
	// without ever seeing it. Not reversible to the token.
	Fingerprint string `json:"fingerprint"`

	// CreatedAt is when the entry was written.
	CreatedAt time.Time `json:"created_at"`

	// HasPassphrase records whether a passphrase is needed to decrypt.
	HasPassphrase bool `json:"has_passphrase"`

	// Issuer and ExpiresAt are parsed from the token when it looks like a JWT.
	// These are the two things that actually explain a surprise 401, which is
	// why they are worth surfacing. Zero when unknown.
	Issuer    string    `json:"issuer,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Expired reports whether the token's own exp claim is in the past.
func (m Meta) Expired() bool {
	return !m.ExpiresAt.IsZero() && time.Now().After(m.ExpiresAt)
}

// envelope is the on-disk format. Only Cipher is secret; the rest is metadata
// chosen so that `apiproxy status` and /_proxy/routes work without a
// passphrase. Nothing here is derived from the token except Fingerprint.
type envelope struct {
	Version       int       `json:"version"`
	Profile       string    `json:"profile"`
	Fingerprint   string    `json:"fingerprint"`
	CreatedAt     time.Time `json:"created_at"`
	HasPassphrase bool      `json:"has_passphrase"`
	Issuer        string    `json:"issuer,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`

	// Cipher is the platform-encrypted token, base64-encoded.
	Cipher []byte `json:"cipher"`
}

const envelopeVersion = 1

// Fingerprint returns a short, non-reversible identifier for a token value.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// validateProfile rejects names that would escape the secret directory or
// collide with path separators.
func validateProfile(profile string) error {
	if !profileRe.MatchString(profile) {
		return fmt.Errorf("secret: invalid profile name %q "+
			"(allowed: letters, digits, '.', '-', '_'; must start alphanumeric)", profile)
	}
	return nil
}

// blobPath returns the on-disk location for a profile's envelope.
func blobPath(dir, profile string) (string, error) {
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	return filepath.Join(dir, profile+".json"), nil
}

// writeEnvelope persists an envelope with owner-only permissions.
func writeEnvelope(dir, profile string, env envelope) error {
	path, err := blobPath(dir, profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secret: create %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("secret: encode envelope: %w", err)
	}
	// Write to a temp file then rename, so a crash mid-write cannot leave a
	// truncated blob that silently fails to decrypt later.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("secret: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secret: replace %s: %w", path, err)
	}
	return nil
}

// readEnvelope loads an envelope from disk.
func readEnvelope(dir, profile string) (envelope, error) {
	var env envelope
	path, err := blobPath(dir, profile)
	if err != nil {
		return env, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return env, fmt.Errorf("%w: %s", ErrNotFound, profile)
	}
	if err != nil {
		return env, fmt.Errorf("secret: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return env, fmt.Errorf("secret: parse %s: %w", path, err)
	}
	if env.Version != envelopeVersion {
		return env, fmt.Errorf("secret: %s has unsupported version %d", path, env.Version)
	}
	return env, nil
}

// listProfiles enumerates stored profiles by scanning the secret directory.
func listProfiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secret: read %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	return out, nil
}

// metaFromEnvelope projects the on-disk envelope to its safe public view.
func metaFromEnvelope(env envelope) Meta {
	return Meta{
		Profile:       env.Profile,
		Fingerprint:   env.Fingerprint,
		CreatedAt:     env.CreatedAt,
		HasPassphrase: env.HasPassphrase,
		Issuer:        env.Issuer,
		ExpiresAt:     env.ExpiresAt,
	}
}

// jwtClaims holds the only two claims worth exposing.
type jwtClaims struct {
	Issuer    string
	ExpiresAt time.Time
}

// inspectJWT best-effort reads iss and exp from a token that looks like a JWT.
//
// The signature is NOT verified, and must not be: this is a debugging aid for
// "why did I get a 401", not an authorization decision. Returns ok=false for
// anything that is not a readable JWT, which includes opaque tokens.
func inspectJWT(token string) (jwtClaims, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, false
	}
	var raw struct {
		Iss string  `json:"iss"`
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return jwtClaims{}, false
	}
	c := jwtClaims{Issuer: raw.Iss}
	if raw.Exp > 0 {
		c.ExpiresAt = time.Unix(int64(raw.Exp), 0).UTC()
	}
	if c.Issuer == "" && c.ExpiresAt.IsZero() {
		return jwtClaims{}, false
	}
	return c, true
}

// newEnvelope builds an envelope for a token, filling in all non-secret
// metadata. Encryption of cipher is the caller's (platform's) job.
func newEnvelope(profile, token string, hasPassphrase bool, cipher []byte) envelope {
	env := envelope{
		Version:       envelopeVersion,
		Profile:       profile,
		Fingerprint:   Fingerprint(token),
		CreatedAt:     time.Now().UTC(),
		HasPassphrase: hasPassphrase,
		Cipher:        cipher,
	}
	if c, ok := inspectJWT(token); ok {
		env.Issuer = c.Issuer
		env.ExpiresAt = c.ExpiresAt
	}
	return env
}
