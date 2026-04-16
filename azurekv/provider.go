// Package azurekv provides a crypto.Provider backed by Azure Key Vault.
//
// Keys are unwrapped at construction time using a Client interface. Wire up
// the Azure SDK by implementing Client with a one-method wrapper:
//
//	type myAzureClient struct{ kv *azkeys.Client }
//
//	func (c *myAzureClient) UnwrapKey(ctx context.Context, keyName, keyVersion, algorithm string, ciphertext []byte) ([]byte, error) {
//	    alg := azkeys.EncryptionAlgorithm(algorithm)
//	    resp, err := c.kv.UnwrapKey(ctx, keyName, keyVersion, azkeys.KeyOperationParameters{Algorithm: &alg, Value: ciphertext}, nil)
//	    if err != nil { return nil, err }
//	    return resp.Result, nil
//	}
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil) // handle error
//	kv, err := azkeys.NewClient("https://my-vault.vault.azure.net/", cred, nil) // handle error
//	provider, err := azurekv.New(ctx, &myAzureClient{kv},
//	    azurekv.WithWrappedKey(wrappedKeyBytes, "key-1", "my-key-name", "key-version"),
//	)
package azurekv

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// Algorithm constants for the Key Vault UnwrapKey operation.
// These correspond to the Azure Key Vault EncryptionAlgorithm values.
const (
	AlgorithmRSAOAEP256 = "RSA-OAEP-256"
	AlgorithmRSAOAEP    = "RSA-OAEP"
	AlgorithmRSA15      = "RSA1_5"
)

// Client unwraps an AES-256 data key that was wrapped by Azure Key Vault.
// Implement this interface by calling the Key Vault UnwrapKey API with your
// SDK of choice. See the package-level doc for a wiring example using
// azure-sdk-for-go.
type Client interface {
	// UnwrapKey unwraps a data key that was wrapped by the specified Key Vault key.
	// algorithm is the wrapping algorithm (e.g. AlgorithmRSAOAEP256).
	UnwrapKey(ctx context.Context, keyName, keyVersion, algorithm string, ciphertext []byte) (plaintext []byte, err error)
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
	algorithm  string
}

// WithWrappedKey adds a wrapped key to be unwrapped via Key Vault.
// The keyName and keyVersion identify the Key Vault key used for wrapping.
// The id identifies this key in the config-crypto system.
// Uses AlgorithmRSAOAEP256 by default.
// The first key added becomes the current key for new encryptions.
func WithWrappedKey(ciphertext []byte, id, keyName, keyVersion string) Option {
	return func(o *options) {
		o.wrappedKeys = append(o.wrappedKeys, wrappedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			keyName:    keyName,
			keyVersion: keyVersion,
			algorithm:  AlgorithmRSAOAEP256,
		})
	}
}

// WithWrappedKeyAlgorithm is like WithWrappedKey but allows specifying the
// unwrap algorithm (e.g. AlgorithmRSAOAEP or AlgorithmRSA15).
func WithWrappedKeyAlgorithm(ciphertext []byte, id, keyName, keyVersion, algorithm string) Option {
	return func(o *options) {
		o.wrappedKeys = append(o.wrappedKeys, wrappedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			keyName:    keyName,
			keyVersion: keyVersion,
			algorithm:  algorithm,
		})
	}
}

// New creates a crypto.Provider that unwraps keys using Azure Key Vault.
//
// At least one key must be provided via WithWrappedKey. The first key is the
// current key for new encryptions; additional keys are available for
// decryption (key rotation).
//
// Keys are unwrapped during construction and cached. The Key Vault client is
// not retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.Provider, error) {
	if client == nil {
		return nil, fmt.Errorf("azurekv: Client must not be nil")
	}

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
	defer func() {
		for _, k := range keys {
			clear(k.bytes)
		}
	}()
	for _, wk := range o.wrappedKeys {
		plaintext, err := client.UnwrapKey(ctx, wk.keyName, wk.keyVersion, wk.algorithm, wk.ciphertext)
		if err != nil {
			return nil, fmt.Errorf("azurekv: failed to unwrap key %q: %w", wk.id, err)
		}
		if len(plaintext) != 32 {
			return nil, fmt.Errorf("azurekv: unwrapped key %q is %d bytes, want 32", wk.id, len(plaintext))
		}
		keys = append(keys, decryptedKey{bytes: plaintext, id: wk.id})
	}

	var providerOpts []crypto.Option
	for _, k := range keys[1:] {
		providerOpts = append(providerOpts, crypto.WithOldKey(k.bytes, k.id, 0))
	}

	provider, err := crypto.NewProvider(keys[0].bytes, keys[0].id, providerOpts...)
	if err != nil {
		return nil, fmt.Errorf("azurekv: %w", err)
	}
	return provider, nil
}
