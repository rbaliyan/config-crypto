package crypto

import (
	"context"
	"fmt"
	"sync"
)

// Provider encrypts and decrypts data using envelope encryption.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Encrypt encrypts plaintext using envelope encryption.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext that was produced by Encrypt.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// HealthCheck reports whether the provider is currently usable. It
	// returns nil for a healthy provider and an error otherwise.
	// Implementations backed by remote services may use ctx to bound the
	// check; static providers ignore ctx and return nil unless closed.
	HealthCheck(ctx context.Context) error

	// Close zeros all key material and releases resources.
	// After Close, Encrypt, Decrypt, and HealthCheck return ErrProviderClosed.
	Close() error
}

// Option configures provider construction.
type Option func(*providerOptions)

type providerOptions struct {
	oldKeys []oldKeyEntry
	err     error
}

type oldKeyEntry struct {
	bytes []byte
	id    string
}

// WithOldKey adds a previous key for decryption during key rotation.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
func WithOldKey(keyBytes []byte, id string) Option {
	return func(o *providerOptions) {
		if o.err != nil {
			return
		}
		if len(keyBytes) != aesKeySize {
			o.err = fmt.Errorf("%w: old key %q has %d bytes", ErrInvalidKeySize, id, len(keyBytes))
			return
		}
		if id == "" {
			o.err = fmt.Errorf("%w: old key ID must not be empty", ErrInvalidKeyID)
			return
		}
		b := make([]byte, aesKeySize)
		copy(b, keyBytes)
		o.oldKeys = append(o.oldKeys, oldKeyEntry{bytes: b, id: id})
	}
}

// NewProvider builds a static Provider from raw 32-byte AES-256 key bytes.
// Key bytes are copied internally; the caller may safely zero the original after construction.
func NewProvider(keyBytes []byte, id string, opts ...Option) (Provider, error) {
	if len(keyBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(keyBytes))
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

	b := make([]byte, aesKeySize)
	copy(b, keyBytes)
	current := keyEntry{id: id, bytes: b}

	keys := make(map[string]keyEntry, 1+len(o.oldKeys))
	keys[id] = current

	for _, old := range o.oldKeys {
		if _, exists := keys[old.id]; exists {
			return nil, fmt.Errorf("%w: duplicate key ID %q", ErrInvalidKeyID, old.id)
		}
		keys[old.id] = keyEntry{id: old.id, bytes: old.bytes}
	}

	return &staticProvider{
		current: current,
		keys:    keys,
	}, nil
}

// keyEntry holds key material for internal use.
type keyEntry struct {
	id    string
	bytes []byte
}

// staticProvider is an immutable Provider backed by in-memory keys.
type staticProvider struct {
	mu      sync.RWMutex
	current keyEntry
	keys    map[string]keyEntry
	closed  bool
}

// Compile-time interface check.
var _ Provider = (*staticProvider)(nil)

// Encrypt encrypts plaintext using envelope encryption with the current key.
func (p *staticProvider) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	return encryptEnvelope(plaintext, p.current.id, p.current.bytes)
}

// Decrypt decrypts ciphertext using the key identified in the header.
func (p *staticProvider) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	return decryptEnvelope(ciphertext, p.keyByID)
}

// HealthCheck reports liveness only. A static provider keeps its key
// material in process memory and does not retain a handle on any remote
// service, so "healthy" means "not yet closed" — it cannot probe whether
// the backend that originally supplied the keys is still reachable. KMS
// sub-modules that need remote readiness checks must override HealthCheck
// on their own wrapper type (see vault/provider.go for an example).
func (p *staticProvider) HealthCheck(_ context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return ErrProviderClosed
	}
	return nil
}

// Close zeros all key material.
func (p *staticProvider) Close() error {
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

// keyByID returns key bytes for the given ID. Caller must hold at least a read lock.
func (p *staticProvider) keyByID(id string) ([]byte, error) {
	k, ok := p.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	b := make([]byte, len(k.bytes))
	copy(b, k.bytes)
	return b, nil
}
