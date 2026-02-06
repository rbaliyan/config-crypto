package crypto

import (
	"fmt"
	"sync"
)

// StaticKeyProvider is a KeyProvider backed by in-memory keys.
// It is safe for concurrent use.
type StaticKeyProvider struct {
	mu      sync.RWMutex
	current Key
	keys    map[string]Key
	err     error // deferred validation error from options
}

// StaticOption configures a StaticKeyProvider.
type StaticOption func(*StaticKeyProvider)

// WithOldKey adds a previous key for decryption during key rotation.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
func WithOldKey(keyBytes []byte, id string) StaticOption {
	return func(p *StaticKeyProvider) {
		if p.err != nil {
			return
		}
		if len(keyBytes) != aesKeySize {
			p.err = fmt.Errorf("%w: old key %q has %d bytes", ErrInvalidKeySize, id, len(keyBytes))
			return
		}
		if id == "" {
			p.err = fmt.Errorf("%w: old key ID must not be empty", ErrInvalidKeyID)
			return
		}
		b := make([]byte, aesKeySize)
		copy(b, keyBytes)
		p.keys[id] = Key{ID: id, Bytes: b}
	}
}

// NewStaticKeyProvider creates a KeyProvider with the given current key.
// The keyBytes must be 32 bytes for AES-256. The id identifies this key.
// Old keys can be added with WithOldKey for rotation support.
// Key bytes are copied internally; the caller may safely zero the original after construction.
func NewStaticKeyProvider(keyBytes []byte, id string, opts ...StaticOption) (*StaticKeyProvider, error) {
	if len(keyBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(keyBytes))
	}
	if id == "" {
		return nil, fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	b := make([]byte, aesKeySize)
	copy(b, keyBytes)
	current := Key{ID: id, Bytes: b}
	p := &StaticKeyProvider{
		current: current,
		keys:    map[string]Key{id: current},
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.err != nil {
		return nil, p.err
	}

	return p, nil
}

// CurrentKey returns the current key for new encryptions.
func (p *StaticKeyProvider) CurrentKey() (Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current, nil
}

// KeyByID returns the key with the given ID.
func (p *StaticKeyProvider) KeyByID(id string) (Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, ok := p.keys[id]
	if !ok {
		return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	return key, nil
}

// Compile-time interface check.
var _ KeyProvider = (*StaticKeyProvider)(nil)
