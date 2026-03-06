package crypto

import (
	"context"
	"fmt"
	"sync"

	"github.com/rbaliyan/config"
)

// DynamicKeyProvider is a mutable KeyProvider that supports runtime key rotation.
// Unlike StaticKeyProvider, the current key can be changed after construction
// via SetCurrentKeyID. It also supports watching a config store for automatic
// key rotation via WatchKeyRotation.
//
// DynamicKeyProvider is safe for concurrent use.
type DynamicKeyProvider struct {
	mu          sync.RWMutex
	current     Key
	keys        map[string]Key
	cancelWatch context.CancelFunc // cancel function from WatchKeyRotation
	err         error              // deferred validation error from options
	destroyed   bool
}

// DynamicOption configures a DynamicKeyProvider.
type DynamicOption func(*DynamicKeyProvider)

// WithDynamicOldKey adds a previous key for decryption during key rotation.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
func WithDynamicOldKey(keyBytes []byte, id string) DynamicOption {
	return func(p *DynamicKeyProvider) {
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
		if _, exists := p.keys[id]; exists {
			p.err = fmt.Errorf("%w: duplicate key ID %q", ErrInvalidKeyID, id)
			return
		}
		b := make([]byte, aesKeySize)
		copy(b, keyBytes)
		p.keys[id] = Key{ID: id, Bytes: b}
	}
}

// NewDynamicKeyProvider creates a mutable KeyProvider with the given current key.
// The keyBytes must be 32 bytes for AES-256. The id identifies this key.
// Old keys can be added with WithDynamicOldKey for rotation support.
// Key bytes are copied internally; the caller may safely zero the original after construction.
func NewDynamicKeyProvider(keyBytes []byte, id string, opts ...DynamicOption) (*DynamicKeyProvider, error) {
	if len(keyBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(keyBytes))
	}
	if id == "" {
		return nil, fmt.Errorf("%w: key ID must not be empty", ErrInvalidKeyID)
	}

	b := make([]byte, aesKeySize)
	copy(b, keyBytes)
	current := Key{ID: id, Bytes: b}
	p := &DynamicKeyProvider{
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
// The returned Key contains a copy of the internal bytes.
func (p *DynamicKeyProvider) CurrentKey() (Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.destroyed {
		return Key{}, ErrProviderDestroyed
	}
	return p.current.copy(), nil
}

// KeyByID returns the key with the given ID.
// The returned Key contains a copy of the internal bytes.
func (p *DynamicKeyProvider) KeyByID(id string) (Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.destroyed {
		return Key{}, ErrProviderDestroyed
	}

	key, ok := p.keys[id]
	if !ok {
		return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	return key.copy(), nil
}

// AddKey adds a key that can be used for decryption or set as the current key.
// The keyBytes must be 32 bytes for AES-256 and id must not be empty.
// Key bytes are copied internally.
func (p *DynamicKeyProvider) AddKey(keyBytes []byte, id string) error {
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
	if p.destroyed {
		return ErrProviderDestroyed
	}

	p.keys[id] = Key{ID: id, Bytes: b}
	return nil
}

// SetCurrentKeyID switches the active encryption key to the given ID.
// The key must have been previously added via the constructor or AddKey.
func (p *DynamicKeyProvider) SetCurrentKeyID(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return ErrProviderDestroyed
	}

	key, ok := p.keys[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	p.current = key
	return nil
}

// RemoveKey removes a key by ID. The current key cannot be removed.
func (p *DynamicKeyProvider) RemoveKey(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return ErrProviderDestroyed
	}

	if p.current.ID == id {
		return fmt.Errorf("%w: %s", ErrRemoveCurrentKey, id)
	}

	key, ok := p.keys[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	clear(key.Bytes)
	delete(p.keys, id)
	return nil
}

// WatchKeyRotation starts watching a config store for key rotation events.
// It watches the given namespace for changes, and when the specified key is
// updated, it calls SetCurrentKeyID with the new string value.
// The caller must ensure all referenced key IDs have been added via AddKey
// before the config value is changed.
// Returns a cancel function to stop watching.
func (p *DynamicKeyProvider) WatchKeyRotation(ctx context.Context, store config.Store, namespace, key string) (context.CancelFunc, error) {
	watchCtx, cancel := context.WithCancel(ctx)

	ch, err := store.Watch(watchCtx, config.WatchFilter{
		Namespaces: []string{namespace},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("crypto: failed to watch store: %w", err)
	}

	// Store cancel so Destroy can stop the goroutine.
	p.mu.Lock()
	p.cancelWatch = cancel
	p.mu.Unlock()

	go func() {
		for event := range ch {
			if event.Type != config.ChangeTypeSet {
				continue
			}
			if event.Key != key {
				continue
			}
			if event.Value == nil {
				continue
			}

			newKeyID, err := event.Value.String()
			if err != nil || newKeyID == "" {
				continue
			}

			_ = p.SetCurrentKeyID(newKeyID)
		}
	}()

	return cancel, nil
}

// Destroy zeros all key material held by this provider.
// After Destroy is called, all methods return ErrProviderDestroyed.
func (p *DynamicKeyProvider) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancelWatch != nil {
		p.cancelWatch()
		p.cancelWatch = nil
	}
	for _, k := range p.keys {
		clear(k.Bytes)
	}
	clear(p.current.Bytes)
	p.current = Key{}
	p.keys = nil
	p.destroyed = true
}

// Compile-time interface check.
var _ KeyProvider = (*DynamicKeyProvider)(nil)
