package crypto

import (
	"context"
	"fmt"
	"sync"
)

// RotatingProvider is a mutable Provider that supports runtime key rotation.
// Keys can be added, removed, and the current key switched at any time.
// End users usually get a Provider from a KMS sub-module; this type is
// exported so KMS modules can build on top of it.
//
// RotatingProvider is safe for concurrent use.
type RotatingProvider struct {
	mu      sync.RWMutex
	current keyEntry
	keys    map[string]keyEntry
	closed  bool
}

// Compile-time interface check.
var _ Provider = (*RotatingProvider)(nil)

// NewRotatingProvider creates a mutable Provider with the given initial key.
// The keyBytes must be 32 bytes for AES-256. The id identifies this key.
// rank is the KV store version number for this key (e.g. the Vault KV version
// integer cast to uint64); it is used by NeedsReencryption to determine
// whether a given ciphertext was encrypted with an older key. Use 0 when the
// backing store does not provide version ordering.
// Old keys can be added with WithOldKey; pass the KV version as rank.
// Key bytes are copied internally; the caller may safely zero the original after construction.
func NewRotatingProvider(initialBytes []byte, id string, rank uint64, opts ...Option) (*RotatingProvider, error) {
	if len(initialBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(initialBytes))
	}
	if id == "" {
		return nil, fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	o := &providerOptions{}
	for _, opt := range opts {
		opt(o)
	}
	if o.err != nil {
		return nil, o.err
	}

	keys := make(map[string]keyEntry, 1+len(o.oldKeys))
	for _, old := range o.oldKeys {
		if _, exists := keys[old.id]; exists {
			return nil, fmt.Errorf("%w: duplicate key ID %q", ErrInvalidKeyID, old.id)
		}
		keys[old.id] = keyEntry{id: old.id, bytes: old.bytes, generation: old.rank}
	}

	b := make([]byte, aesKeySize)
	copy(b, initialBytes)
	current := keyEntry{id: id, bytes: b, generation: rank}
	keys[id] = current

	return &RotatingProvider{
		current: current,
		keys:    keys,
	}, nil
}

// Encrypt encrypts plaintext using envelope encryption with the current key.
func (p *RotatingProvider) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	return encryptEnvelope(plaintext, p.current.id, p.current.bytes)
}

// Decrypt decrypts ciphertext using the key identified in the header.
func (p *RotatingProvider) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	return decryptEnvelope(ciphertext, p.keyByID)
}

// HealthCheck returns nil unless Close has been called.
func (p *RotatingProvider) HealthCheck(_ context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return ErrProviderClosed
	}
	return nil
}

// Close zeros all key material and blocks further operations.
// Safe to call multiple times; subsequent calls are no-ops.
func (p *RotatingProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	for _, k := range p.keys {
		clear(k.bytes)
	}
	clear(p.current.bytes)
	p.current = keyEntry{}
	p.keys = nil
	p.closed = true
	return nil
}

// AddKey adds a key that can be used for decryption or set as the current key.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
// rank is the KV store version number for this key; it is used by
// NeedsReencryption to establish ordering across restarts. Pass the same
// value that the backing store (e.g. Vault KV version) provides so that
// the ordering is stable even after a process restart.
// Key bytes are copied internally.
func (p *RotatingProvider) AddKey(keyBytes []byte, id string, rank uint64) error {
	if len(keyBytes) != aesKeySize {
		return fmt.Errorf("%w: key %q has %d bytes", ErrInvalidKeySize, id, len(keyBytes))
	}
	if id == "" {
		return fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	b := make([]byte, aesKeySize)
	copy(b, keyBytes)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}
	p.keys[id] = keyEntry{id: id, bytes: b, generation: rank}
	return nil
}

// SetCurrentKey switches the active encryption key to the given ID.
// The key must have been previously added via the constructor or AddKey.
func (p *RotatingProvider) SetCurrentKey(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}

	k, ok := p.keys[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	// Copy so current and keys[id] don't share backing array.
	cb := make([]byte, len(k.bytes))
	copy(cb, k.bytes)
	p.current = keyEntry{id: k.id, bytes: cb, generation: k.generation}
	return nil
}

// RemoveKey removes a key by ID. The current key cannot be removed.
func (p *RotatingProvider) RemoveKey(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}

	if p.current.id == id {
		return fmt.Errorf("%w: %s", ErrRemoveCurrentKey, id)
	}

	k, ok := p.keys[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	clear(k.bytes)
	delete(p.keys, id)
	return nil
}

// CurrentKeyID returns the ID of the key currently used for encryption.
func (p *RotatingProvider) CurrentKeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current.id
}

// NeedsReencryption reports whether ciphertext was encrypted with a key that
// is older than the current key, based on the rank (KV store version) recorded
// when each key was added. It returns true only when the current key has a
// strictly higher rank than the key embedded in the ciphertext header, so
// instances that have not yet rotated to a newer key will not re-encrypt
// backwards during a rolling restart.
//
// It returns false (not true) when the ciphertext key is unknown to this
// provider, since ordering cannot be determined in that case.
// It returns an error only if the ciphertext header cannot be parsed.
func (p *RotatingProvider) NeedsReencryption(ciphertext []byte) (bool, error) {
	h, _, err := readHeader(ciphertext)
	if err != nil {
		return false, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if h.keyID == p.current.id {
		return false, nil
	}

	k, ok := p.keys[h.keyID]
	if !ok {
		return false, nil
	}

	return k.generation < p.current.generation, nil
}

// keyByID returns a copy of key bytes for the given ID. Caller must hold at least a read lock.
func (p *RotatingProvider) keyByID(id string) ([]byte, error) {
	k, ok := p.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	b := make([]byte, len(k.bytes))
	copy(b, k.bytes)
	return b, nil
}
