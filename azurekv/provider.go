// Package azurekv provides a KeyProvider backed by Azure Key Vault.
//
// Keys are fetched from Key Vault at construction time and cached in memory.
// The provider uses the UnwrapKey operation to decrypt key material that was
// previously wrapped with WrapKey.
//
// Usage:
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil)
//	client, err := azkeys.NewClient("https://my-vault.vault.azure.net/", cred, nil)
//
//	provider, err := azurekv.New(ctx, client,
//	    azurekv.WithWrappedKey(wrappedKeyBytes, "key-1", "my-key-name", "key-version"),
//	)
package azurekv

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	crypto "github.com/rbaliyan/config-crypto"
)

// Client is the subset of the Azure Key Vault API used by this provider.
type Client interface {
	UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// Option configures a Provider.
type Option func(*options)

type options struct {
	wrappedKeys []wrappedKeyEntry
}

type wrappedKeyEntry struct {
	ciphertext []byte
	id         string
	keyName    string
	keyVersion string
	algorithm  azkeys.EncryptionAlgorithm
}

// WithWrappedKey adds a wrapped key to be unwrapped via Key Vault.
// The keyName and keyVersion identify the Key Vault key used for wrapping.
// The id identifies this key in the config-crypto system.
// Uses RSA-OAEP-256 by default.
// The first key added becomes the current key for new encryptions.
func WithWrappedKey(ciphertext []byte, id, keyName, keyVersion string) Option {
	return func(o *options) {
		o.wrappedKeys = append(o.wrappedKeys, wrappedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			keyName:    keyName,
			keyVersion: keyVersion,
			algorithm:  azkeys.EncryptionAlgorithmRSAOAEP256,
		})
	}
}

// WithWrappedKeyAlgorithm is like WithWrappedKey but allows specifying the unwrap algorithm.
func WithWrappedKeyAlgorithm(ciphertext []byte, id, keyName, keyVersion string, alg azkeys.EncryptionAlgorithm) Option {
	return func(o *options) {
		o.wrappedKeys = append(o.wrappedKeys, wrappedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			keyName:    keyName,
			keyVersion: keyVersion,
			algorithm:  alg,
		})
	}
}

// New creates a KeyProvider that unwraps keys using Azure Key Vault.
//
// At least one key must be provided via WithWrappedKey.
// The first key is the current key for new encryptions; additional keys
// are available for decryption (key rotation).
//
// Keys are unwrapped during construction and cached in a StaticKeyProvider.
// The Key Vault client is not retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (*crypto.StaticKeyProvider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(o.wrappedKeys) == 0 {
		return nil, fmt.Errorf("azurekv: at least one wrapped key is required")
	}

	type decryptedKey struct {
		bytes []byte
		id    string
	}
	keys := make([]decryptedKey, 0, len(o.wrappedKeys))
	for _, wk := range o.wrappedKeys {
		resp, err := client.UnwrapKey(ctx, wk.keyName, wk.keyVersion, azkeys.KeyOperationParameters{
			Algorithm: &wk.algorithm,
			Value:     wk.ciphertext,
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("azurekv: failed to unwrap key %q: %w", wk.id, err)
		}

		keys = append(keys, decryptedKey{bytes: resp.Result, id: wk.id})
	}

	var staticOpts []crypto.StaticOption
	for _, k := range keys[1:] {
		staticOpts = append(staticOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	provider, err := crypto.NewStaticKeyProvider(keys[0].bytes, keys[0].id, staticOpts...)
	if err != nil {
		return nil, fmt.Errorf("azurekv: %w", err)
	}

	for _, k := range keys {
		clear(k.bytes)
	}

	return provider, nil
}
