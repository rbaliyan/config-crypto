// Package gcpkms provides a crypto.Provider backed by Google Cloud KMS.
//
// Keys are decrypted at construction time using a Client interface. Wire up
// the Cloud KMS Go SDK by implementing Client with a one-method wrapper:
//
//	type myGCPClient struct{ kms *kms.KeyManagementClient }
//
//	func (c *myGCPClient) Decrypt(ctx context.Context, resourceName string, ciphertext []byte) ([]byte, error) {
//	    resp, err := c.kms.Decrypt(ctx, &kmspb.DecryptRequest{Name: resourceName, Ciphertext: ciphertext})
//	    if err != nil { return nil, err }
//	    return resp.Plaintext, nil
//	}
//
//	kmsClient, err := kms.NewKeyManagementClient(ctx) // handle error
//	provider, err := gcpkms.New(ctx, &myGCPClient{kmsClient},
//	    gcpkms.WithEncryptedKey(ciphertext, "key-1", "projects/P/locations/L/keyRings/R/cryptoKeys/K"),
//	)
package gcpkms

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config-crypto/internal/kmsring"
)

// Client unwraps an AES-256 data key that was encrypted by Google Cloud KMS.
// Implement this interface by calling the Cloud KMS Decrypt RPC with your SDK
// of choice. See the package-level doc for a wiring example using
// cloud.google.com/go/kms.
type Client interface {
	// Decrypt decrypts a data key ciphertext using the specified Cloud KMS key.
	// resourceName is the full CryptoKey resource name:
	// "projects/P/locations/L/keyRings/R/cryptoKeys/K".
	Decrypt(ctx context.Context, resourceName string, ciphertext []byte) (plaintext []byte, err error)
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

// New creates a crypto.KeyRingProvider that unwraps encrypted keys using Google
// Cloud KMS.
//
// At least one key must be provided via WithEncryptedKey. The first key is
// the current key for new encryptions; additional keys are available for
// decryption (key rotation).
//
// Keys are decrypted during construction and cached. The KMS client is not
// retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.KeyRingProvider, error) {
	if client == nil {
		return nil, fmt.Errorf("gcpkms: Client must not be nil")
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	return kmsring.Build(len(o.encryptedKeys), "gcpkms", func(i int) ([]byte, string, error) {
		ek := o.encryptedKeys[i]
		pt, err := client.Decrypt(ctx, ek.resourceName, ek.ciphertext)
		return pt, ek.id, err
	})
}
