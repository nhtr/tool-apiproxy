//go:build !windows

// Package secret's encrypted-at-rest store is a Windows feature of this
// tool, not an oversight here: it is built directly on DPAPI
// (CryptProtectData/CryptUnprotectData), which has no equivalent on
// macOS/Linux that this package tries to emulate. Rather than fake a
// weaker substitute that would quietly behave differently from the real
// thing, Open just refuses, so callers get a clear, early signal instead
// of a false sense of security. Use NewMemStore for local dev and tests on
// these platforms.
package secret

// Open always fails on non-Windows platforms. dir is accepted only so the
// signature matches the Windows build.
func Open(dir string) (Store, error) {
	return nil, ErrUnsupported
}
