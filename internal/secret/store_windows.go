//go:build windows

package secret

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CRYPTPROTECT_UI_FORBIDDEN tells DPAPI to fail instead of popping a UI
// prompt. apiproxy runs headless as a background server, so a blocking
// prompt would just hang the process forever.
const cryptProtectUIForbidden = 0x1

// dataBlob mirrors the Win32 DATA_BLOB / CRYPTOAPI_BLOB struct used by
// CryptProtectData and CryptUnprotectData: a length-prefixed byte buffer.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// toBlob builds a dataBlob pointing at b without copying. A zero-length
// slice must produce a null pbData (not a dangling pointer to an empty
// backing array), because CryptoAPI treats cbData==0 with a non-null
// pointer as still being a real, if empty, buffer, and some code paths are
// stricter about a genuinely absent entropy blob than others. Passing a
// clean null for "no entropy" matches what DPAPI expects when the caller
// supplied an empty passphrase.
func toBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

// dpapiEncrypt wraps plaintext with CryptProtectData, CurrentUser scope.
// entropy is the passphrase bytes (may be empty, meaning "OS user key
// only"). The returned ciphertext is a fresh Go-owned copy; the OS buffer
// backing it is freed before this function returns, on every path.
func dpapiEncrypt(plaintext, entropy []byte) ([]byte, error) {
	in := toBlob(plaintext)
	ent := toBlob(entropy)

	var out dataBlob
	ret, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // szDataDescr: no human-readable description needed
		uintptr(unsafe.Pointer(&ent)),
		0, // pvReserved
		0, // pPromptStruct: no UI
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	// Keep the input slices alive until after the syscall returns; the OS
	// only sees raw pointers and has no notion of Go's GC.
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(entropy)

	if ret == 0 {
		return nil, fmt.Errorf("secret: CryptProtectData failed: %w", callErr)
	}
	defer freeDPAPIBuffer(out)

	return copyBlob(out), nil
}

// dpapiDecrypt reverses dpapiEncrypt. Any failure here is reported as
// ErrBadPassphrase: in practice a CryptUnprotectData failure means the
// entropy (passphrase) was wrong, or the blob belongs to a different user
// or machine. There is no finer-grained error DPAPI gives us that would be
// more useful to a human than that.
func dpapiDecrypt(ciphertext, entropy []byte) ([]byte, error) {
	in := toBlob(ciphertext)
	ent := toBlob(entropy)

	var out dataBlob
	ret, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr: don't need it back
		uintptr(unsafe.Pointer(&ent)),
		0, // pvReserved
		0, // pPromptStruct: no UI
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(entropy)

	if ret == 0 {
		return nil, fmt.Errorf("%w: %v", ErrBadPassphrase, callErr)
	}
	defer freeDPAPIBuffer(out)

	return copyBlob(out), nil
}

// copyBlob copies a DPAPI output buffer into a Go-owned byte slice. The
// caller is still responsible for freeing out.pbData; this just makes sure
// the plaintext/ciphertext outlives that free.
func copyBlob(b dataBlob) []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

// freeDPAPIBuffer releases memory CryptoAPI allocated for us with
// LocalAlloc. Skipping this on any path, including errors, leaks decrypted
// plaintext (or ciphertext) into the process heap for the life of the
// process, which defeats the point of encrypting it in the first place.
func freeDPAPIBuffer(b dataBlob) {
	if b.pbData == nil {
		return
	}
	procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
}

// zero overwrites a byte slice in place. Used on plaintext we're done with
// so it doesn't linger in memory any longer than necessary. This is best
// effort, not a security guarantee: Go's GC can have already copied the
// slice's backing array during a prior move, and the compiler is free to
// optimize trivial writes away in some circumstances. It still meaningfully
// shrinks the window a plaintext token sits around in memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// dpapiStore is a Store backed by Windows DPAPI. Each profile is one
// envelope file in dir; the Cipher field holds the DPAPI-protected token.
type dpapiStore struct {
	mu  sync.Mutex
	dir string
}

// Open returns a DPAPI-backed Store rooted at dir. dir is created on first
// write; it is not required to exist yet.
func Open(dir string) (Store, error) {
	return &dpapiStore{dir: dir}, nil
}

func (s *dpapiStore) Put(profile, token, passphrase string) error {
	if err := validateProfile(profile); err != nil {
		return err
	}

	plaintext := []byte(token)
	entropy := []byte(passphrase)
	cipher, err := dpapiEncrypt(plaintext, entropy)
	zero(plaintext)
	zero(entropy)
	if err != nil {
		return fmt.Errorf("secret: encrypt %s: %w", profile, err)
	}

	env := newEnvelope(profile, token, passphrase != "", cipher)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeEnvelope(s.dir, profile, env); err != nil {
		return err
	}
	return nil
}

func (s *dpapiStore) Get(profile, passphrase string) (string, error) {
	s.mu.Lock()
	env, err := readEnvelope(s.dir, profile)
	s.mu.Unlock()
	if err != nil {
		return "", err
	}

	entropy := []byte(passphrase)
	plaintext, err := dpapiDecrypt(env.Cipher, entropy)
	zero(entropy)
	if err != nil {
		return "", fmt.Errorf("secret: decrypt %s: %w", profile, err)
	}
	defer zero(plaintext)

	token := string(plaintext)

	// Catch a corrupted or tampered blob: the decrypted bytes should hash
	// to the fingerprint recorded at Put time. DPAPI's own integrity check
	// already protects against bit-flips (it would fail to decrypt at
	// all), so a mismatch here means the envelope's Fingerprint field
	// itself was edited, or Cipher was swapped for another profile's.
	if got := Fingerprint(token); got != env.Fingerprint {
		return "", fmt.Errorf("secret: %s: decrypted token fingerprint %s does not match stored %s (corrupted or tampered envelope)",
			profile, got, env.Fingerprint)
	}

	return token, nil
}

func (s *dpapiStore) Delete(profile string) error {
	path, err := blobPath(s.dir, profile)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secret: delete %s: %w", profile, err)
	}
	return nil
}

func (s *dpapiStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listProfiles(s.dir)
}

func (s *dpapiStore) Meta(profile string) (Meta, error) {
	s.mu.Lock()
	env, err := readEnvelope(s.dir, profile)
	s.mu.Unlock()
	if err != nil {
		return Meta{}, err
	}
	return metaFromEnvelope(env), nil
}
