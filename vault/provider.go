// Package vault provides a KeyProvider backed by HashiCorp Vault Transit secrets engine.
//
// Keys are decrypted via the Transit engine at construction time and cached in memory.
// The provider uses the Transit decrypt endpoint to unwrap encrypted key material
// that was previously encrypted via the Transit encrypt endpoint.
//
// Usage:
//
//	client := vault.NewClient("https://vault.example.com:8200", "hvs.token123")
//	provider, err := vault.New(ctx, client,
//	    vault.WithEncryptedKey(ciphertext, "key-1", "my-transit-key"),
//	)
package vault

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// Client abstracts the Vault Transit decrypt operation.
// This allows injecting a mock for testing or wrapping any Vault client library.
type Client interface {
	// TransitDecrypt decrypts ciphertext using the named Transit key.
	// The ciphertext should be in Vault's format (e.g., "vault:v1:base64data").
	// Returns the plaintext bytes.
	TransitDecrypt(ctx context.Context, keyName string, ciphertext string) ([]byte, error)
}

// Option configures a Provider.
type Option func(*options)

type options struct {
	encryptedKeys []encryptedKeyEntry
}

type encryptedKeyEntry struct {
	ciphertext     string // Vault Transit ciphertext (e.g., "vault:v1:...")
	id             string
	transitKeyName string
}

// WithEncryptedKey adds a Transit-encrypted key to be decrypted at construction time.
// The transitKeyName is the name of the Transit key in Vault.
// The ciphertext should be in Vault's format (e.g., "vault:v1:base64data").
// The id identifies this key in the config-crypto system.
// The first key added becomes the current key for new encryptions.
func WithEncryptedKey(ciphertext string, id, transitKeyName string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext:     ciphertext,
			id:             id,
			transitKeyName: transitKeyName,
		})
	}
}

// New creates a KeyProvider that decrypts keys using the Vault Transit engine.
//
// At least one key must be provided via WithEncryptedKey.
// The first key is the current key for new encryptions; additional keys
// are available for decryption (key rotation).
//
// Keys are decrypted during construction and cached in a StaticKeyProvider.
// The Vault client is not retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (*crypto.StaticKeyProvider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(o.encryptedKeys) == 0 {
		return nil, fmt.Errorf("vault: at least one encrypted key is required")
	}

	type decryptedKey struct {
		bytes []byte
		id    string
	}
	keys := make([]decryptedKey, 0, len(o.encryptedKeys))
	for _, ek := range o.encryptedKeys {
		plaintext, err := client.TransitDecrypt(ctx, ek.transitKeyName, ek.ciphertext)
		if err != nil {
			return nil, fmt.Errorf("vault: failed to decrypt key %q: %w", ek.id, err)
		}

		keys = append(keys, decryptedKey{bytes: plaintext, id: ek.id})
	}

	var staticOpts []crypto.StaticOption
	for _, k := range keys[1:] {
		staticOpts = append(staticOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	provider, err := crypto.NewStaticKeyProvider(keys[0].bytes, keys[0].id, staticOpts...)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}

	for _, k := range keys {
		clear(k.bytes)
	}

	return provider, nil
}
