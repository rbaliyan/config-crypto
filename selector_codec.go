package crypto

import (
	"context"
	"fmt"

	"github.com/rbaliyan/config/codec"
)

// namespaceKey is the unexported context key type for the namespace value.
type namespaceKey struct{}

// NamespaceContextKey is the context key used to pass the config namespace
// into SelectorCodec.Encode and SelectorCodec.Decode. Set it with:
//
//	ctx = crypto.WithNamespace(ctx, "payments")
var NamespaceContextKey = namespaceKey{}

// WithNamespace returns a new context carrying the given namespace. Used to
// tell SelectorCodec which provider to route to during Encode/Decode.
func WithNamespace(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, NamespaceContextKey, namespace)
}

// NamespaceFromContext extracts the namespace previously set by WithNamespace.
// Returns an empty string if no namespace is present.
func NamespaceFromContext(ctx context.Context) string {
	ns, _ := ctx.Value(NamespaceContextKey).(string)
	return ns
}

// SelectorCodec wraps a NamespaceSelector with an inner codec (e.g. JSON)
// to provide per-namespace encryption through a single codec registration.
//
// On Encode, it reads the namespace from ctx (via WithNamespace), serializes
// the value with the inner codec, then encrypts with the namespace-specific
// provider from the selector.
//
// On Decode, it reads the namespace from ctx, decrypts with the matching
// provider, then deserializes with the inner codec.
//
// Register once at startup:
//
//	sel, _ := crypto.NewNamespaceSelector(
//	    crypto.WithNamespaceProvider("payments", awsProvider),
//	    crypto.WithNamespaceProvider("users",    gcpProvider),
//	    crypto.WithFallbackProvider(defaultProvider),
//	)
//	sc, _ := crypto.NewSelectorCodec(sel, jsoncodec.New())
//	codec.Register(sc) // one registration covers all namespaces
//
// When calling store operations, inject the namespace into ctx first:
//
//	ctx = crypto.WithNamespace(ctx, "payments")
//	store.Set(ctx, "payments", "db-password", value)
//
// SelectorCodec is safe for concurrent use if the NamespaceSelector and
// inner codec are safe for concurrent use.
type SelectorCodec struct {
	selector *NamespaceSelector
	inner    codec.Codec
	name     string
}

// Compile-time interface checks.
var (
	_ codec.Codec       = (*SelectorCodec)(nil)
	_ codec.Transformer = (*SelectorCodec)(nil)
)

// NewSelectorCodec creates a SelectorCodec. The codec name is
// "encrypted:<inner>" (e.g. "encrypted:json"). WithClientCodec and
// WithCodecPrefix options from NewCodec are reused here.
// Returns an error if selector or inner is nil.
func NewSelectorCodec(selector *NamespaceSelector, inner codec.Codec, opts ...CodecOption) (*SelectorCodec, error) {
	if selector == nil {
		return nil, fmt.Errorf("crypto: NewSelectorCodec selector is nil")
	}
	if inner == nil {
		return nil, fmt.Errorf("crypto: NewSelectorCodec inner codec is nil")
	}

	o := &codecOptions{}
	for _, opt := range opts {
		opt(o)
	}

	name := "encrypted:" + inner.Name()
	if o.prefix != "" {
		name = o.prefix + ":" + name
	}

	return &SelectorCodec{
		selector: selector,
		inner:    inner,
		name:     name,
	}, nil
}

// Name returns the codec name, e.g. "encrypted:json".
func (c *SelectorCodec) Name() string { return c.name }

// Encode serializes v with the inner codec then encrypts with the provider
// resolved from ctx's namespace. Returns ErrNoProviderForNamespace if no
// provider is registered for the namespace and no fallback is set.
func (c *SelectorCodec) Encode(ctx context.Context, v any) ([]byte, error) {
	p, err := c.resolveProvider(ctx)
	if err != nil {
		return nil, err
	}
	plaintext, err := c.inner.Encode(ctx, v)
	if err != nil {
		return nil, fmt.Errorf("crypto: inner encode failed: %w", err)
	}
	ciphertext, err := p.Encrypt(ctx, plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: encrypt failed: %w", err)
	}
	return ciphertext, nil
}

// Decode decrypts data with the provider resolved from ctx's namespace,
// then deserializes into v using the inner codec.
func (c *SelectorCodec) Decode(ctx context.Context, data []byte, v any) error {
	p, err := c.resolveProvider(ctx)
	if err != nil {
		return err
	}
	plaintext, err := p.Decrypt(ctx, data)
	if err != nil {
		return fmt.Errorf("crypto: decrypt failed: %w", err)
	}
	if err := c.inner.Decode(ctx, plaintext, v); err != nil {
		return fmt.Errorf("crypto: inner decode failed: %w", err)
	}
	return nil
}

// Transform encrypts raw bytes using the provider resolved from ctx's namespace.
// Implements codec.Transformer for use with codec.NewChain.
func (c *SelectorCodec) Transform(ctx context.Context, data []byte) ([]byte, error) {
	p, err := c.resolveProvider(ctx)
	if err != nil {
		return nil, err
	}
	return p.Encrypt(ctx, data)
}

// Reverse decrypts raw bytes using the provider resolved from ctx's namespace.
// Implements codec.Transformer for use with codec.NewChain.
func (c *SelectorCodec) Reverse(ctx context.Context, data []byte) ([]byte, error) {
	p, err := c.resolveProvider(ctx)
	if err != nil {
		return nil, err
	}
	return p.Decrypt(ctx, data)
}

// resolveProvider returns the Provider for the namespace stored in ctx.
func (c *SelectorCodec) resolveProvider(ctx context.Context) (Provider, error) {
	ns := NamespaceFromContext(ctx)
	p := c.selector.ForNamespace(ns)
	if p == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoProviderForNamespace, ns)
	}
	return p, nil
}
