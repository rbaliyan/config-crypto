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

// Compile-time interface check.
var _ codec.Codec = (*Codec)(nil)

// NewCodec creates an encrypting codec that wraps the given inner codec.
// The codec name is "encrypted:<inner>", e.g. "encrypted:json".
// Returns an error if inner or provider is nil.
func NewCodec(inner codec.Codec, provider KeyProvider) (*Codec, error) {
	if inner == nil {
		return nil, fmt.Errorf("crypto: NewCodec inner codec is nil")
	}
	if provider == nil {
		return nil, fmt.Errorf("crypto: NewCodec provider is nil")
	}
	return &Codec{
		inner:    inner,
		provider: provider,
		name:     "encrypted:" + inner.Name(),
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
