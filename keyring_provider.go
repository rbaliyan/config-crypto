package crypto

import (
	"context"
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
)

// KeyRingProvider is a mutable Provider that supports runtime key rotation.
// Keys can be added, removed, and the current key switched at any time.
// End users usually get a KeyRingProvider from a KMS package; this interface
// is exported so KMS packages can build on top of it.
//
// KeyRingProvider is safe for concurrent use.
type KeyRingProvider interface {
	Provider

	// AddKey adds a key that can be used for decryption or set as the current
	// key. The keyBytes must be 32 bytes for AES-256 and id must not be empty.
	// rank is the KV store version number for this key; it is used by
	// NeedsReencryption to establish ordering. Pass 0 when the backing store
	// does not provide version ordering. Returns ErrInvalidKeyID if the ID
	// already exists.
	AddKey(keyBytes []byte, id string, rank uint64) error

	// SetCurrentKey switches the active encryption key to the given ID.
	// The key must have been previously added via the constructor or AddKey.
	SetCurrentKey(id string) error

	// RemoveKey removes a key by ID. The current key cannot be removed.
	RemoveKey(id string) error

	// CurrentKeyID returns the ID of the key currently used for encryption.
	CurrentKeyID() string

	// NeedsReencryption reports whether ciphertext was encrypted with a key
	// that is older than the current key, based on the rank recorded when each
	// key was added. It returns true only when the current key has a strictly
	// higher rank than the key embedded in the ciphertext header.
	//
	// It returns false (not true) when the ciphertext key is unknown to this
	// provider, since ordering cannot be determined in that case.
	// It returns an error only if the ciphertext header cannot be parsed.
	NeedsReencryption(ciphertext []byte) (bool, error)
}

// keyEntry holds key material for one entry in a keyRingProvider.
// The 32-byte AES-256 KEK is stored inside a memguard Enclave:
//   - mlock prevents the OS from paging it to disk.
//   - XOR-at-rest makes the plaintext invisible to heap scans between uses.
//   - Destroy() zeroes and unlocks on removal or Close.
type keyEntry struct {
	enclave *memguard.Enclave
	rank    uint64 // monotonically increasing; higher means newer
}

// keyRingProvider is the concrete implementation of KeyRingProvider. Each
// key is stored exactly once in keys; currentID names the entry used for
// new encryptions. Single-copy storage keeps Close's zeroing trivially
// correct: no aliasing, no double-clear.
type keyRingProvider struct {
	mu        sync.RWMutex
	currentID string
	keys      map[string]keyEntry
	closed    bool
}

// Compile-time interface check.
var _ KeyRingProvider = (*keyRingProvider)(nil)

// NewKeyRingProvider creates a mutable Provider with the given initial key.
// The keyBytes must be 32 bytes for AES-256. The id identifies this key.
// rank is the KV store version number for this key (e.g. the Vault KV version
// integer cast to uint64); it is used by NeedsReencryption to determine
// whether a given ciphertext was encrypted with an older key. Use 0 when the
// backing store does not provide version ordering.
// Key bytes are copied into a memguard Enclave; the caller should zero the
// original slice after construction as a defence-in-depth measure.
func NewKeyRingProvider(initialBytes []byte, id string, rank uint64) (KeyRingProvider, error) {
	if len(initialBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(initialBytes))
	}
	if id == "" {
		return nil, fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	enc := sealKey(initialBytes)
	keys := make(map[string]keyEntry, 1)
	keys[id] = keyEntry{enclave: enc, rank: rank}

	return &keyRingProvider{
		currentID: id,
		keys:      keys,
	}, nil
}

// Name returns the ID of the current encryption key.
func (p *keyRingProvider) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentID
}

// Connect is a no-op for keyRingProvider.
func (p *keyRingProvider) Connect(_ context.Context) error { return nil }

// Encrypt encrypts plaintext using envelope encryption with the current key.
func (p *keyRingProvider) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	cur, ok := p.keys[p.currentID]
	if !ok {
		return nil, fmt.Errorf("%w: current %q", ErrKeyNotFound, p.currentID)
	}

	lb, err := cur.enclave.Open()
	if err != nil {
		return nil, fmt.Errorf("open key enclave %q: %w", p.currentID, err)
	}
	defer lb.Destroy()
	return encryptEnvelope(plaintext, p.currentID, lb.Bytes())
}

// Decrypt decrypts ciphertext using the key identified in the header.
func (p *keyRingProvider) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	return decryptEnvelope(ciphertext, p.keyByID)
}

// HealthCheck returns nil unless Close has been called.
func (p *keyRingProvider) HealthCheck(_ context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return ErrProviderClosed
	}
	return nil
}

// Close wipes all key enclaves and blocks further operations.
// Safe to call multiple times; subsequent calls are no-ops.
func (p *keyRingProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	for _, k := range p.keys {
		wipeEnclave(k.enclave)
	}
	p.keys = nil
	p.currentID = ""
	p.closed = true
	return nil
}

// AddKey adds a key that can be used for decryption or set as the current key.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
// rank is the KV store version number for this key; it is used by
// NeedsReencryption to establish ordering across restarts.
// Returns ErrDuplicateKeyID if the ID already exists.
// Key bytes are copied into a memguard Enclave; the caller should zero their
// slice after AddKey returns as a defence-in-depth measure.
func (p *keyRingProvider) AddKey(keyBytes []byte, id string, rank uint64) error {
	if len(keyBytes) != aesKeySize {
		return fmt.Errorf("%w: key %q has %d bytes", ErrInvalidKeySize, id, len(keyBytes))
	}
	if id == "" {
		return fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	enc := sealKey(keyBytes)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		wipeEnclave(enc)
		return ErrProviderClosed
	}
	if _, exists := p.keys[id]; exists {
		wipeEnclave(enc)
		return fmt.Errorf("%w: %q", ErrDuplicateKeyID, id)
	}
	p.keys[id] = keyEntry{enclave: enc, rank: rank}
	return nil
}

// SetCurrentKey switches the active encryption key to the given ID.
// The key must have been previously added via the constructor or AddKey.
func (p *keyRingProvider) SetCurrentKey(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}
	if _, ok := p.keys[id]; !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	p.currentID = id
	return nil
}

// RemoveKey removes a key by ID. The current key cannot be removed.
func (p *keyRingProvider) RemoveKey(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}
	if p.currentID == id {
		return fmt.Errorf("%w: %s", ErrRemoveCurrentKey, id)
	}
	k, ok := p.keys[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	wipeEnclave(k.enclave)
	delete(p.keys, id)
	return nil
}

// CurrentKeyID returns the ID of the key currently used for encryption.
func (p *keyRingProvider) CurrentKeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentID
}

// NeedsReencryption reports whether ciphertext was encrypted with a key that
// is older than the current key, based on the rank (KV store version) recorded
// when each key was added.
func (p *keyRingProvider) NeedsReencryption(ciphertext []byte) (bool, error) {
	h, _, err := readHeader(ciphertext)
	if err != nil {
		return false, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if h.keyID == p.currentID {
		return false, nil
	}

	stored, ok := p.keys[h.keyID]
	if !ok {
		return false, nil
	}
	current, ok := p.keys[p.currentID]
	if !ok {
		return false, nil
	}
	return stored.rank < current.rank, nil
}

// keyByID opens the enclave for the given key ID and returns a plaintext copy.
// The caller is responsible for zeroing the returned slice after use.
// Caller must hold at least a read lock.
func (p *keyRingProvider) keyByID(id string) ([]byte, error) {
	k, ok := p.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	lb, err := k.enclave.Open()
	if err != nil {
		return nil, fmt.Errorf("open key enclave %q: %w", id, err)
	}
	defer lb.Destroy()
	b := make([]byte, lb.Size())
	copy(b, lb.Bytes())
	return b, nil
}

// sealKey copies keyBytes into a mutable LockedBuffer and seals it into a
// memguard Enclave. The caller's slice is NOT modified; callers are responsible
// for zeroing their own copy of the key material.
func sealKey(keyBytes []byte) *memguard.Enclave {
	lb := memguard.NewBuffer(len(keyBytes))
	lb.Copy(keyBytes)
	return lb.Seal()
}

// wipeEnclave opens the enclave and destroys the resulting LockedBuffer,
// zeroing the plaintext key material in the mlock'd region.
// The encrypted blob in the Enclave struct is left in heap but is
// cryptographically opaque without the memguard session key.
func wipeEnclave(enc *memguard.Enclave) {
	if lb, err := enc.Open(); err == nil {
		lb.Destroy()
	}
}
