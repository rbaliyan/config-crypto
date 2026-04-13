// Package gcpkms provides a crypto.Provider backed by Google Cloud KMS.
//
// Keys are fetched from Cloud KMS at construction time and cached in memory.
// The provider uses the CryptoKeys.Decrypt RPC to unwrap encrypted key material.
//
// Usage:
//
//	client, err := kms.NewKeyManagementClient(ctx)
//	provider, err := gcpkms.New(ctx, client, "key-1",
//	    gcpkms.WithEncryptedKey(ciphertext, "key-1", resourceName),
//	)
package gcpkms

import (
	"context"
	"fmt"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	crypto "github.com/rbaliyan/config-crypto"
)

// Client is the subset of the GCP Cloud KMS API used by this provider.
type Client interface {
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}

// Option configures a Provider.
type Option func(*options)

type options struct {
	encryptedKeys []encryptedKeyEntry
}

type encryptedKeyEntry struct {
	ciphertext   []byte
	id           string
	resourceName string // projects/*/locations/*/keyRings/*/cryptoKeys/*
}

// WithEncryptedKey adds an encrypted key to be unwrapped via Cloud KMS Decrypt.
// The resourceName is the full Cloud KMS CryptoKey resource name.
// The id identifies this key in the config-crypto system.
// The first key added becomes the current key for new encryptions.
func WithEncryptedKey(ciphertext []byte, id, resourceName string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext:   ciphertext,
			id:           id,
			resourceName: resourceName,
		})
	}
}

// New creates a crypto.Provider that unwraps encrypted keys using Google
// Cloud KMS.
//
// At least one key must be provided via WithEncryptedKey. The first key is
// the current key for new encryptions; additional keys are available for
// decryption (key rotation).
//
// Keys are decrypted during construction and cached. The KMS client is not
// retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.Provider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(o.encryptedKeys) == 0 {
		return nil, fmt.Errorf("gcpkms: at least one encrypted key is required")
	}

	type decryptedKey struct {
		bytes []byte
		id    string
	}
	keys := make([]decryptedKey, 0, len(o.encryptedKeys))
	defer func() {
		for _, k := range keys {
			clear(k.bytes)
		}
	}()
	for _, ek := range o.encryptedKeys {
		resp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:       ek.resourceName,
			Ciphertext: ek.ciphertext,
		})
		if err != nil {
			return nil, fmt.Errorf("gcpkms: failed to decrypt key %q: %w", ek.id, err)
		}
		if len(resp.Plaintext) != 32 {
			return nil, fmt.Errorf("gcpkms: decrypted key %q is %d bytes, want 32", ek.id, len(resp.Plaintext))
		}
		keys = append(keys, decryptedKey{bytes: resp.Plaintext, id: ek.id})
	}

	var providerOpts []crypto.Option
	for _, k := range keys[1:] {
		providerOpts = append(providerOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	provider, err := crypto.NewProvider(keys[0].bytes, keys[0].id, providerOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: %w", err)
	}
	return provider, nil
}
