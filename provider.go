package crypto

import (
	"context"
	"fmt"
	"sync"
)

// Provider encrypts and decrypts data using envelope encryption.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Name returns a short human-readable identifier for this provider.
	// Used for logging and observability; need not be globally unique.
	Name() string

	// Connect initialises any remote connection the provider needs.
	// It is the caller's responsibility to call Connect before the first
	// Encrypt or Decrypt. Implementations backed by in-memory keys treat
	// this as a no-op; remote-key-wrapping implementations use it to
	// establish SDK sessions or verify credentials.
	Connect(ctx context.Context) error

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

// NewProvider builds a static Provider from raw 32-byte AES-256 key bytes.
// Key bytes are copied internally; the caller may safely zero the original after construction.
func NewProvider(keyBytes []byte, id string) (Provider, error) {
	if len(keyBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(keyBytes))
	}
	if id == "" {
		return nil, fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	b := make([]byte, aesKeySize)
	copy(b, keyBytes)
	current := keyEntry{id: id, bytes: b}

	// Make a separate copy for the lookup map so that Close() zeroing the map
	// entry and zeroing current.bytes do not alias the same backing array.
	kb := make([]byte, aesKeySize)
	copy(kb, b)
	keys := make(map[string]keyEntry, 1)
	keys[id] = keyEntry{id: id, bytes: kb}

	return &staticProvider{
		current: current,
		keys:    keys,
	}, nil
}

// keyEntry holds key material for internal use.
type keyEntry struct {
	id         string
	bytes      []byte
	generation uint64 // monotonically increasing; higher means newer
}

// staticProvider is an immutable Provider backed by a single in-memory key.
type staticProvider struct {
	mu      sync.RWMutex
	current keyEntry
	keys    map[string]keyEntry
	closed  bool
}

// Compile-time interface check.
var _ Provider = (*staticProvider)(nil)

// Name returns the key ID of this provider.
func (p *staticProvider) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current.id
}

// Connect is a no-op for static providers.
func (p *staticProvider) Connect(_ context.Context) error { return nil }

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
// packages that need remote readiness checks must wrap the Provider and
// override HealthCheck on their own type.
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
