package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// --- Fingerprint ---

func TestFingerprintStableAndDistinct(t *testing.T) {
	a1 := Fingerprint("token-a")
	a2 := Fingerprint("token-a")
	b := Fingerprint("token-b")

	if a1 != a2 {
		t.Fatalf("Fingerprint not stable: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("Fingerprint collided for different tokens: %q", a1)
	}
}

// --- inspectJWT ---

// makeJWT builds a minimal JWT-shaped string (header.payload.signature)
// with an arbitrary payload, using the same encoding inspectJWT expects.
// No JWT library: this is exactly what the function under test parses.
func makeJWT(t *testing.T, payload any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(pb)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return fmt.Sprintf("%s.%s.%s", header, body, sig)
}

func TestInspectJWT_RealShaped(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	tok := makeJWT(t, map[string]any{"iss": "https://issuer.example", "exp": exp})

	c, ok := inspectJWT(tok)
	if !ok {
		t.Fatalf("expected ok=true for well-formed JWT")
	}
	if c.Issuer != "https://issuer.example" {
		t.Errorf("Issuer = %q, want issuer.example", c.Issuer)
	}
	if c.ExpiresAt.Unix() != exp {
		t.Errorf("ExpiresAt = %v, want unix %d", c.ExpiresAt, exp)
	}
}

func TestInspectJWT_OpaqueToken(t *testing.T) {
	_, ok := inspectJWT("sk-abcdef0123456789")
	if ok {
		t.Fatalf("expected ok=false for opaque token")
	}
}

func TestInspectJWT_MalformedBase64(t *testing.T) {
	_, ok := inspectJWT("header.not!!valid!!base64.sig")
	if ok {
		t.Fatalf("expected ok=false for malformed base64 payload")
	}
}

func TestInspectJWT_NoUsefulClaims(t *testing.T) {
	tok := makeJWT(t, map[string]any{"sub": "user-123"})
	_, ok := inspectJWT(tok)
	if ok {
		t.Fatalf("expected ok=false when neither iss nor exp is present")
	}
}

// --- validateProfile ---

func TestValidateProfile(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"path traversal", "../x", true},
		{"path separator unix", "a/b", true},
		{"path separator with traversal", "foo/../bar", true},
		{"empty string", "", true},
		{"leading dot", ".hidden", true},
		{"normal name", "default", false},
		{"normal name with dash dot underscore", "my-profile_1.prod", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProfile(tc.profile)
			if tc.wantErr && err == nil {
				t.Errorf("validateProfile(%q): expected error, got nil", tc.profile)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateProfile(%q): unexpected error: %v", tc.profile, err)
			}
		})
	}
}

// --- Meta.Expired ---

func TestMetaExpired(t *testing.T) {
	cases := []struct {
		name string
		exp  time.Time
		want bool
	}{
		{"past", time.Now().Add(-time.Hour), true},
		{"future", time.Now().Add(time.Hour), false},
		{"zero", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Meta{ExpiresAt: tc.exp}
			if got := m.Expired(); got != tc.want {
				t.Errorf("Expired() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- envelope round trip ---

func TestEnvelopeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	env := newEnvelope("default", "sk-sometoken", true, []byte("cipherbytes"))

	if err := writeEnvelope(dir, "default", env); err != nil {
		t.Fatalf("writeEnvelope: %v", err)
	}

	got, err := readEnvelope(dir, "default")
	if err != nil {
		t.Fatalf("readEnvelope: %v", err)
	}
	if got.Profile != env.Profile || got.Fingerprint != env.Fingerprint || got.HasPassphrase != env.HasPassphrase {
		t.Errorf("round-tripped envelope mismatch: got %+v, want %+v", got, env)
	}
}

func TestEnvelopeMissingProfile(t *testing.T) {
	dir := t.TempDir()
	_, err := readEnvelope(dir, "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("readEnvelope on missing profile: got %v, want ErrNotFound", err)
	}
}

func TestEnvelopeVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	env := newEnvelope("default", "sk-sometoken", false, []byte("cipherbytes"))
	env.Version = envelopeVersion + 1

	if err := writeEnvelope(dir, "default", env); err != nil {
		t.Fatalf("writeEnvelope: %v", err)
	}

	_, err := readEnvelope(dir, "default")
	if err == nil {
		t.Fatalf("expected error for unsupported version, got nil")
	}
}

// --- Store contract, reusable across implementations ---

// testStoreContract exercises the full Store interface against impl. Any
// Store implementation (memStore today, dpapiStore on Windows) should pass
// this unchanged.
func testStoreContract(t *testing.T, s Store) {
	t.Helper()

	const profile = "work"
	const token = "sk-abc123"
	const passphrase = "correct-horse"

	t.Run("put then get round trip", func(t *testing.T) {
		if err := s.Put(profile, token, passphrase); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(profile, passphrase)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != token {
			t.Errorf("Get() = %q, want %q", got, token)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		_, err := s.Get(profile, "wrong-passphrase")
		if !errors.Is(err, ErrBadPassphrase) {
			t.Errorf("Get with wrong passphrase: got %v, want ErrBadPassphrase", err)
		}
	})

	t.Run("meta never carries token", func(t *testing.T) {
		meta, err := s.Meta(profile)
		if err != nil {
			t.Fatalf("Meta: %v", err)
		}
		if meta.Profile != profile {
			t.Errorf("Meta.Profile = %q, want %q", meta.Profile, profile)
		}
		if meta.Fingerprint != Fingerprint(token) {
			t.Errorf("Meta.Fingerprint = %q, want %q", meta.Fingerprint, Fingerprint(token))
		}
		if !meta.HasPassphrase {
			t.Errorf("Meta.HasPassphrase = false, want true")
		}
		// Reflect the whole struct through JSON and make sure the raw
		// token string never shows up anywhere in it.
		b, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("marshal meta: %v", err)
		}
		if containsToken(b, token) {
			t.Errorf("Meta JSON leaks the token value: %s", b)
		}
	})

	t.Run("list reflects puts", func(t *testing.T) {
		if err := s.Put("second", "sk-xyz", ""); err != nil {
			t.Fatalf("Put second: %v", err)
		}
		names, err := s.List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if !containsStr(names, profile) || !containsStr(names, "second") {
			t.Errorf("List() = %v, want to contain %q and %q", names, profile, "second")
		}
	})

	t.Run("get unknown profile", func(t *testing.T) {
		_, err := s.Get("nonexistent", "")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Get unknown profile: got %v, want ErrNotFound", err)
		}
	})

	t.Run("delete missing profile is not an error", func(t *testing.T) {
		if err := s.Delete("never-existed"); err != nil {
			t.Errorf("Delete missing profile: got %v, want nil", err)
		}
	})

	t.Run("delete removes entry", func(t *testing.T) {
		if err := s.Put("todelete", "sk-temp", ""); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete("todelete"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := s.Get("todelete", "")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after Delete: got %v, want ErrNotFound", err)
		}
	})
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsToken(haystack []byte, token string) bool {
	return len(token) > 0 && bytesContains(haystack, []byte(token))
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func TestMemStoreContract(t *testing.T) {
	testStoreContract(t, NewMemStore())
}
