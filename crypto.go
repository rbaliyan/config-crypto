package crypto

import (
	"fmt"

	"github.com/rbaliyan/config/codec"
)

// Codec wraps an inner codec with envelope encryption.
// On Encode, the inner codec serializes the value, then the result is encrypted.
// On Decode, the data is decrypted, then the inner codec deserializes the plaintext.
//
// Codec is safe for concurrent use if the underlying KeyProvider and inner codec are safe
// for concurrent use. StaticKeyProvider satisfies this requirement.
type Codec struct {
	inner    codec.Codec
	provider KeyProvider
	name     string
}

// Compile-time interface checks.
var (
	_ codec.Codec       = (*Codec)(nil)
	_ codec.Transformer = (*Codec)(nil)
)

// Option configures NewCodec behavior.
type Option func(*codecOptions)

type codecOptions struct {
	prefix string
}

// WithClientCodec prefixes the codec name with "client:" so the config-server
// recognises it as a client-managed codec and passes the bytes through
// without attempting to decode them. This is shorthand for WithCodecPrefix("client").
func WithClientCodec() Option {
	return WithCodecPrefix("client")
}

// WithCodecPrefix adds a custom prefix to the codec name.
// The resulting name is "<prefix>:encrypted:<inner>".
// Use this when you need a prefix other than the standard "client:".
func WithCodecPrefix(prefix string) Option {
	return func(o *codecOptions) {
		o.prefix = prefix
	}
}

// NewCodec creates an encrypting codec that wraps the given inner codec.
// The codec name is "encrypted:<inner>", e.g. "encrypted:json".
// With WithClientCodec the name becomes "client:encrypted:<inner>".
// Returns an error if inner or provider is nil.
func NewCodec(inner codec.Codec, provider KeyProvider, opts ...Option) (*Codec, error) {
	if inner == nil {
		return nil, fmt.Errorf("crypto: NewCodec inner codec is nil")
	}
	if provider == nil {
		return nil, fmt.Errorf("crypto: NewCodec provider is nil")
	}

	o := &codecOptions{}
	for _, opt := range opts {
		opt(o)
	}

	name := "encrypted:" + inner.Name()
	if o.prefix != "" {
		name = o.prefix + ":" + name
	}

	return &Codec{
		inner:    inner,
		provider: provider,
		name:     name,
	}, nil
}

// Name returns the codec name, e.g. "encrypted:json".
func (c *Codec) Name() string {
	return c.name
}

// Encode serializes the value using the inner codec, then encrypts the result.
func (c *Codec) Encode(v any) ([]byte, error) {
	plaintext, err := c.inner.Encode(v)
	if err != nil {
		return nil, fmt.Errorf("crypto: inner encode failed: %w", err)
	}

	key, err := c.provider.CurrentKey()
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to get current key: %w", err)
	}
	defer clear(key.Bytes)

	return encrypt(plaintext, key)
}

// Decode decrypts the data, then deserializes the plaintext using the inner codec.
func (c *Codec) Decode(data []byte, v any) error {
	plaintext, err := decrypt(data, c.provider)
	if err != nil {
		return fmt.Errorf("crypto: decrypt failed: %w", err)
	}

	if err := c.inner.Decode(plaintext, v); err != nil {
		return fmt.Errorf("crypto: inner decode failed: %w", err)
	}
	return nil
}

// Transform encrypts the raw bytes using envelope encryption.
// This implements codec.Transformer for use with codec.NewChain.
func (c *Codec) Transform(data []byte) ([]byte, error) {
	key, err := c.provider.CurrentKey()
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to get current key: %w", err)
	}
	defer clear(key.Bytes)
	return encrypt(data, key)
}

// Reverse decrypts the raw bytes, recovering the original plaintext.
// This implements codec.Transformer for use with codec.NewChain.
func (c *Codec) Reverse(data []byte) ([]byte, error) {
	return decrypt(data, c.provider)
}
