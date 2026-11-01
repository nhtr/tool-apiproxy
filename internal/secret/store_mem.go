package secret

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
)

// memStore is an in-memory Store for tests and for `go run` on a dev
// machine where DPAPI isn't available (i.e. every non-Windows box).
//
// It does NOT persist anything (entries vanish when the process exits) and
// it does NOT encrypt anything (the token sits in a plain Go map in this
// process's heap). It exists purely so the rest of the program and its
// tests have something satisfying the Store interface to run against
// without touching the filesystem or a real OS crypto API. Do not wire
// this up as a real store.
type memStore struct {
	mu      sync.RWMutex
	entries map[string]memEntry
}

// memEntry pairs an envelope (for metadata) with the plaintext token and a
// hash of the passphrase that guarded it, so Get can still enforce "wrong
// passphrase" the same way the real stores do.
type memEntry struct {
	env           envelope
	token         string
	passphraseSum [32]byte
	hasPassphrase bool
}

// NewMemStore returns a Store backed by an in-memory map. See the memStore
// doc comment: no persistence, no encryption, test/dev use only.
func NewMemStore() Store {
	return &memStore{entries: make(map[string]memEntry)}
}

func (m *memStore) Put(profile, token, passphrase string) error {
	if err := validateProfile(profile); err != nil {
		return err
	}

	// cipher is never read back for anything real here since Get keeps the
	// plaintext alongside it, but newEnvelope still wants something in
	// Cipher and the field has to round-trip like the real stores for
	// anyone snapshotting Meta/envelope behavior in tests.
	env := newEnvelope(profile, token, passphrase != "", []byte(token))

	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[profile] = memEntry{
		env:           env,
		token:         token,
		passphraseSum: sha256.Sum256([]byte(passphrase)),
		hasPassphrase: passphrase != "",
	}
	return nil
}

func (m *memStore) Get(profile, passphrase string) (string, error) {
	m.mu.RLock()
	e, ok := m.entries[profile]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, profile)
	}

	sum := sha256.Sum256([]byte(passphrase))
	if subtle.ConstantTimeCompare(sum[:], e.passphraseSum[:]) != 1 {
		return "", ErrBadPassphrase
	}
	return e.token, nil
}

func (m *memStore) Delete(profile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, profile)
	return nil
}

func (m *memStore) List() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.entries))
	for name := range m.entries {
		out = append(out, name)
	}
	return out, nil
}

func (m *memStore) Meta(profile string) (Meta, error) {
	m.mu.RLock()
	e, ok := m.entries[profile]
	m.mu.RUnlock()
	if !ok {
		return Meta{}, fmt.Errorf("%w: %s", ErrNotFound, profile)
	}
	return metaFromEnvelope(e.env), nil
}
