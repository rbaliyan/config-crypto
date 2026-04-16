package crypto

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
)

// NamespaceSelector routes Encrypt/Decrypt to namespace-specific Providers.
// It holds a map of namespace to Provider plus an optional fallback provider.
// It is safe for concurrent use; providers can be added or removed at runtime.
//
// In multi-tenant scenarios, use ForNamespace to obtain a namespace-scoped
// Provider; do not invoke Encrypt or Decrypt directly on the selector — those
// methods are not exposed because the selector itself does not know which
// namespace a payload belongs to.
type NamespaceSelector struct {
	mu        sync.RWMutex
	providers map[string]Provider
	fallback  Provider
	closed    bool
}

// NamespaceOption configures a NamespaceSelector.
type NamespaceOption func(*namespaceOptions)

type namespaceOptions struct {
	providers map[string]Provider
	fallback  Provider
}

// WithNamespaceProvider registers a Provider for the given namespace.
// Nil providers are ignored.
func WithNamespaceProvider(namespace string, provider Provider) NamespaceOption {
	return func(o *namespaceOptions) {
		if provider != nil {
			o.providers[namespace] = provider
		}
	}
}

// WithFallbackProvider sets the fallback Provider used when a namespace
// has no dedicated provider.
func WithFallbackProvider(provider Provider) NamespaceOption {
	return func(o *namespaceOptions) {
		o.fallback = provider
	}
}

// NewNamespaceSelector creates a NamespaceSelector with the given options.
func NewNamespaceSelector(opts ...NamespaceOption) (*NamespaceSelector, error) {
	o := &namespaceOptions{
		providers: make(map[string]Provider),
	}
	for _, opt := range opts {
		opt(o)
	}

	providers := make(map[string]Provider, len(o.providers))
	maps.Copy(providers, o.providers)

	return &NamespaceSelector{
		providers: providers,
		fallback:  o.fallback,
	}, nil
}

// ForNamespace returns a Provider scoped to the given namespace.
// If the namespace has a registered provider, that provider is used.
// Otherwise the fallback provider is used. If neither exists, the returned
// Provider returns ErrNoProviderForNamespace on Encrypt/Decrypt.
// The returned Provider is safe for concurrent use and reflects runtime
// changes to the selector (providers added/removed after ForNamespace).
//
// Close on the returned Provider is a no-op; close the underlying providers
// or the selector itself.
func (s *NamespaceSelector) ForNamespace(namespace string) Provider {
	return &scopedProvider{selector: s, namespace: namespace}
}

// AddProvider registers a Provider for the given namespace at runtime.
// Returns an error if provider is nil or the selector has been closed.
func (s *NamespaceSelector) AddProvider(namespace string, provider Provider) error {
	if provider == nil {
		return errors.New("crypto: AddProvider provider is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrProviderClosed
	}
	s.providers[namespace] = provider
	return nil
}

// RemoveProvider removes the Provider for the given namespace.
// The removed provider is not closed; the caller retains ownership and
// must call Close on it. Use RemoveAndClose if the selector should close
// the provider on the caller's behalf.
func (s *NamespaceSelector) RemoveProvider(namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, namespace)
}

// RemoveAndClose removes the Provider for the given namespace and calls
// Close on it. Returns the Close error (or nil if the namespace had no
// provider). Use this when the selector owns the provider's lifecycle.
func (s *NamespaceSelector) RemoveAndClose(namespace string) error {
	s.mu.Lock()
	p, ok := s.providers[namespace]
	if ok {
		delete(s.providers, namespace)
	}
	s.mu.Unlock()
	if !ok || p == nil {
		return nil
	}
	return p.Close()
}

// Close closes every Provider held by the selector (namespace-scoped and
// fallback). Errors from individual closes are joined via errors.Join.
// Safe to call multiple times; subsequent calls are no-ops.
func (s *NamespaceSelector) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error
	for ns, p := range s.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close namespace %q: %w", ns, err))
		}
	}
	if s.fallback != nil {
		if err := s.fallback.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close fallback: %w", err))
		}
	}
	s.providers = nil
	s.fallback = nil
	return errors.Join(errs...)
}

// resolveLocked returns the provider for the given namespace, or the fallback,
// or nil. Caller must hold at least a read lock.
func (s *NamespaceSelector) resolveLocked(namespace string) Provider {
	if p, ok := s.providers[namespace]; ok {
		return p
	}
	return s.fallback
}

// scopedProvider is a lightweight Provider that delegates to a NamespaceSelector
// for a specific namespace.
type scopedProvider struct {
	selector  *NamespaceSelector
	namespace string
}

func (p *scopedProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	p.selector.mu.RLock()
	if p.selector.closed {
		p.selector.mu.RUnlock()
		return nil, ErrProviderClosed
	}
	provider := p.selector.resolveLocked(p.namespace)
	p.selector.mu.RUnlock()
	if provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.Encrypt(ctx, plaintext)
}

func (p *scopedProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	p.selector.mu.RLock()
	if p.selector.closed {
		p.selector.mu.RUnlock()
		return nil, ErrProviderClosed
	}
	provider := p.selector.resolveLocked(p.namespace)
	p.selector.mu.RUnlock()
	if provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.Decrypt(ctx, ciphertext)
}

// HealthCheck delegates to the underlying provider for the scope's namespace.
// Returns ErrNoProviderForNamespace when no provider is registered.
func (p *scopedProvider) HealthCheck(ctx context.Context) error {
	p.selector.mu.RLock()
	if p.selector.closed {
		p.selector.mu.RUnlock()
		return ErrProviderClosed
	}
	provider := p.selector.resolveLocked(p.namespace)
	p.selector.mu.RUnlock()
	if provider == nil {
		return fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.HealthCheck(ctx)
}

// Name returns "namespace:" followed by the namespace string.
func (p *scopedProvider) Name() string { return "namespace:" + p.namespace }

// Connect delegates to the underlying provider for this namespace, if any.
func (p *scopedProvider) Connect(ctx context.Context) error {
	p.selector.mu.RLock()
	if p.selector.closed {
		p.selector.mu.RUnlock()
		return ErrProviderClosed
	}
	provider := p.selector.resolveLocked(p.namespace)
	p.selector.mu.RUnlock()
	if provider == nil {
		return fmt.Errorf("%w: %s", ErrNoProviderForNamespace, p.namespace)
	}
	return provider.Connect(ctx)
}

// Close on a scoped provider is a no-op; the underlying provider is owned by
// the selector or by the caller that registered it.
func (p *scopedProvider) Close() error { return nil }

// Compile-time interface check.
var _ Provider = (*scopedProvider)(nil)
