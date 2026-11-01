//go:build windows

package secret

import (
	"errors"
	"testing"
)

// TestDPAPIStoreContract runs the shared Store contract against a real
// DPAPI-backed store. This only runs on Windows (DPAPI has no fallback),
// but must compile everywhere so `go vet`/`go build` stay clean cross
// platform.
func TestDPAPIStoreContract(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	testStoreContract(t, s)
}

// TestDPAPIStoreWrongPassphrase exercises the DPAPI-specific path: a blob
// encrypted with one passphrase must fail to decrypt with another, and the
// failure must be reported as ErrBadPassphrase rather than a raw syscall
// error, since that's what it actually means to the user.
func TestDPAPIStoreWrongPassphrase(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := s.Put("work", "sk-realtoken", "correct-passphrase"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err = s.Get("work", "wrong-passphrase")
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Get with wrong passphrase: got %v, want ErrBadPassphrase", err)
	}

	// Sanity check the correct passphrase still works, so a trivially
	// broken Put/encrypt path doesn't masquerade as "wrong passphrase
	// correctly rejected".
	got, err := s.Get("work", "correct-passphrase")
	if err != nil {
		t.Fatalf("Get with correct passphrase: %v", err)
	}
	if got != "sk-realtoken" {
		t.Fatalf("Get() = %q, want %q", got, "sk-realtoken")
	}
}
