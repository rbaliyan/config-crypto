// Package crypto provides an encryption codec for the rbaliyan/config
// library. It implements AES-256-GCM envelope encryption: each config
// value is encrypted with a freshly generated Data Encryption Key (DEK)
// that is itself wrapped by a Key Encryption Key (KEK) held by a
// pluggable Provider.
//
// The package is organised around four building blocks:
//
//   - Codec wraps an inner codec (json, yaml, toml, …) with transparent
//     encryption. Register the codec with config's codec registry and
//     configuration values are encrypted on Set and decrypted on Get.
//   - Provider abstracts KEK ownership. Built-ins: NewProvider (static
//     single-key), NewKeyRingProvider (multi-key with live rotation),
//     plus KMS-backed providers in the awskms, gcpkms, azurekv, vault,
//     and gpg sub-packages.
//   - NamespaceSelector routes Encrypt/Decrypt to different providers
//     based on the config namespace — useful for multi-tenant deployments
//     where each tenant holds its own KEK.
//   - Poll drives backend-agnostic runtime key rotation against any
//     KeyRingProvider. The AWS/GCP/Azure sub-packages ship a
//     NewPoller helper that returns a FetchFn ready to hand to Poll;
//     the vault sub-package has its own vault.Poll specialisation.
//
// For re-encrypting at-rest ciphertext after the current KEK changes,
// see the rotation sub-package.
package crypto

import (
	"context"
	"fmt"

	"github.com/rbaliyan/config/codec"
)

// Codec wraps an inner codec with envelope encryption.
// On Encode, the inner codec serializes the value, then the result is encrypted.
// On Decode, the data is decrypted, then the inner codec deserializes the plaintext.
//
// Codec is safe for concurrent use if the underlying Provider and inner codec are safe
// for concurrent use.
type Codec struct {
	inner    codec.Codec
	provider Provider
	name     string
}

// Compile-time interface checks.
var (
	_ codec.Codec       = (*Codec)(nil)
	_ codec.Transformer = (*Codec)(nil)
)

// CodecOption configures NewCodec behavior.
type CodecOption func(*codecOptions)

type codecOptions struct {
	prefix string
}

// WithClientCodec prefixes the codec name with "client:" so the config-server
// recognises it as a client-managed codec and passes the bytes through
// without attempting to decode them. This is shorthand for WithCodecPrefix("client").
func WithClientCodec() CodecOption {
	return WithCodecPrefix("client")
}

// WithCodecPrefix adds a custom prefix to the codec name.
// The resulting name is "<prefix>:encrypted:<inner>".
// Use this when you need a prefix other than the standard "client:".
func WithCodecPrefix(prefix string) CodecOption {
	return func(o *codecOptions) {
		o.prefix = prefix
	}
}

// NewCodec creates an encrypting codec that wraps the given inner codec.
// The codec name is "encrypted:<inner>", e.g. "encrypted:json".
// With WithClientCodec the name becomes "client:encrypted:<inner>".
// Returns an error if inner or provider is nil.
func NewCodec(inner codec.Codec, p Provider, opts ...CodecOption) (*Codec, error) {
	if inner == nil {
		return nil, fmt.Errorf("crypto: NewCodec inner codec is nil")
	}
	if p == nil {
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
		provider: p,
		name:     name,
	}, nil
}

// Name returns the codec name, e.g. "encrypted:json".
func (c *Codec) Name() string {
	return c.name
}

// Encode serializes the value using the inner codec, then encrypts the result.
func (c *Codec) Encode(ctx context.Context, v any) ([]byte, error) {
	plaintext, err := c.inner.Encode(ctx, v)
	if err != nil {
		return nil, fmt.Errorf("crypto: inner encode failed: %w", err)
	}

	ciphertext, err := c.provider.Encrypt(ctx, plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: encrypt failed: %w", err)
	}
	return ciphertext, nil
}

// Decode decrypts the data, then deserializes the plaintext using the inner codec.
func (c *Codec) Decode(ctx context.Context, data []byte, v any) error {
	plaintext, err := c.provider.Decrypt(ctx, data)
	if err != nil {
		return fmt.Errorf("crypto: decrypt failed: %w", err)
	}

	if err := c.inner.Decode(ctx, plaintext, v); err != nil {
		return fmt.Errorf("crypto: inner decode failed: %w", err)
	}
	return nil
}

// Transform encrypts the raw bytes using envelope encryption.
// This implements codec.Transformer for use with codec.NewChain.
func (c *Codec) Transform(ctx context.Context, data []byte) ([]byte, error) {
	return c.provider.Encrypt(ctx, data)
}

// Reverse decrypts the raw bytes, recovering the original plaintext.
// This implements codec.Transformer for use with codec.NewChain.
func (c *Codec) Reverse(ctx context.Context, data []byte) ([]byte, error) {
	return c.provider.Decrypt(ctx, data)
}
