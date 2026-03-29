package crypto

import (
	"fmt"
	"sync"
)

// NamespaceKeySelector routes key operations to namespace-specific KeyProviders.
// It holds a map of namespace to KeyProvider plus an optional fallback provider.
// It is safe for concurrent use; providers can be added or removed at runtime.
//
// In multi-tenant scenarios, use ForNamespace to obtain a namespace-scoped
// KeyProvider rather than calling CurrentKey or KeyByID directly on the selector.
// The top-level KeyByID searches across all registered providers and is therefore
// not namespace-safe; a tenant could decrypt values belonging to another tenant
// if key IDs overlap.
type NamespaceKeySelector struct {
	mu        sync.RWMutex
	providers map[string]KeyProvider
	fallback  KeyProvider
}

// NamespaceOption configures a NamespaceKeySelector.
type NamespaceOption func(*namespaceOptions)

type namespaceOptions struct {
	providers map[string]KeyProvider
	fallback  KeyProvider
}

// WithNamespaceProvider registers a KeyProvider for the given namespace.
// Nil providers are ignored.
func WithNamespaceProvider(namespace string, provider KeyProvider) NamespaceOption {
	return func(o *namespaceOptions) {
		if provider != nil {
			o.providers[namespace] = provider
		}
	}
}

// WithFallbackProvider sets the fallback KeyProvider used when a namespace
// has no dedicated provider.
func WithFallbackProvider(provider KeyProvider) NamespaceOption {
	return func(o *namespaceOptions) {
		o.fallback = provider
	}
}

// NewNamespaceKeySelector creates a NamespaceKeySelector with the given options.
func NewNamespaceKeySelector(opts ...NamespaceOption) (*NamespaceKeySelector, error) {
	o := &namespaceOptions{
		providers: make(map[string]KeyProvider),
	}
	for _, opt := range opts {
		opt(o)
	}

	providers := make(map[string]KeyProvider, len(o.providers))
	for ns, p := range o.providers {
		providers[ns] = p
	}

	return &NamespaceKeySelector{
		providers: providers,
		fallback:  o.fallback,
	}, nil
}

// CurrentKey returns the current key from the fallback provider.
// If no fallback is set, it returns ErrNoProviderForNamespace.
// For namespace-scoped operations, use ForNamespace instead.
func (s *NamespaceKeySelector) CurrentKey() (Key, error) {
	s.mu.RLock()
	fb := s.fallback
	s.mu.RUnlock()

	if fb == nil {
		return Key{}, ErrNoProviderForNamespace
	}
	return fb.CurrentKey()
}

// KeyByID searches all providers for the given key ID.
// It checks the fallback first, then iterates namespace providers.
// Returns ErrKeyNotFound if no provider has the key.
//
// Warning: this method is not namespace-safe. It searches across all registered
// namespace providers and returns the first match. In multi-tenant deployments
// where key IDs may overlap, use ForNamespace to obtain a scoped provider instead.
func (s *NamespaceKeySelector) KeyByID(id string) (Key, error) {
	s.mu.RLock()
	fb := s.fallback
	providers := make(map[string]KeyProvider, len(s.providers))
	for ns, p := range s.providers {
		providers[ns] = p
	}
	s.mu.RUnlock()

	if fb != nil {
		key, err := fb.KeyByID(id)
		if err == nil {
			return key, nil
		}
	}

	for _, p := range providers {
		key, err := p.KeyByID(id)
		if err == nil {
			return key, nil
		}
	}

	return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
}

// ForNamespace returns a KeyProvider scoped to the given namespace.
// If the namespace has a registered provider, that provider is used.
// Otherwise the fallback provider is used. If neither exists, the returned
// provider will return ErrNoProviderForNamespace on all operations.
// The returned provider is safe for concurrent use and reflects runtime
// changes to the selector (providers added/removed after ForNamespace).
func (s *NamespaceKeySelector) ForNamespace(namespace string) KeyProvider {
	return &namespaceScopedProvider{
		selector:  s,
		namespace: namespace,
	}
}

// AddProvider registers a KeyProvider for the given namespace at runtime.
// It is a no-op if provider is nil.
func (s *NamespaceKeySelector) AddProvider(namespace string, provider KeyProvider) {
	if provider == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers[namespace] = provider
}

// RemoveProvider removes the KeyProvider for the given namespace.
func (s *NamespaceKeySelector) RemoveProvider(namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, namespace)
}

// resolve returns the provider for the given namespace, or the fallback, or nil.
func (s *NamespaceKeySelector) resolve(namespace string) KeyProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.providers[namespace]; ok {
		return p
	}
	return s.fallback
}

// namespaceScopedProvider is a lightweight KeyProvider that delegates
// to a NamespaceKeySelector for a specific namespace.
type namespaceScopedProvider struct {
	selector  *NamespaceKeySelector
	namespace string
}

func (p *namespaceScopedProvider) CurrentKey() (Key, error) {
	provider := p.selector.resolve(p.namespace)
	if provider == nil {
		return Key{}, fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.CurrentKey()
}

func (p *namespaceScopedProvider) KeyByID(id string) (Key, error) {
	provider := p.selector.resolve(p.namespace)
	if provider == nil {
		return Key{}, fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.KeyByID(id)
}

// Compile-time interface checks.
var (
	_ KeyProvider = (*NamespaceKeySelector)(nil)
	_ KeyProvider = (*namespaceScopedProvider)(nil)
)
