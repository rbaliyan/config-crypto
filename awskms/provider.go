// Package awskms provides a crypto.Provider backed by AWS KMS.
//
// Keys are decrypted at construction time using a Client interface. Wire up
// the AWS SDK v2 by implementing Client with a one-method wrapper:
//
//	type myAWSClient struct{ kms *kms.Client }
//
//	func (c *myAWSClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
//	    in := &kms.DecryptInput{CiphertextBlob: ciphertext}
//	    if keyID != "" { in.KeyId = aws.String(keyID) }
//	    out, err := c.kms.Decrypt(ctx, in)
//	    if err != nil { return nil, err }
//	    return out.Plaintext, nil
//	}
//
//	cfg, _ := awsconfig.LoadDefaultConfig(ctx)
//	provider, err := awskms.New(ctx, &myAWSClient{kms.NewFromConfig(cfg)},
//	    awskms.WithEncryptedKey(encryptedKeyBytes, "key-1"),
//	)
package awskms

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config-crypto/internal/kmsring"
)

// Client unwraps an AES-256 data key that was encrypted by AWS KMS.
// Implement this interface by calling the AWS KMS Decrypt API with your SDK of
// choice. See the package-level doc for a wiring example using aws-sdk-go-v2.
type Client interface {
	// Decrypt decrypts a data key ciphertext produced by AWS KMS.
	// keyID is the KMS key ARN or alias; pass an empty string to let KMS
	// determine the key from the ciphertext context.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (plaintext []byte, err error)
}

// Option configures a Provider.
type Option func(*options)

type options struct {
	encryptedKeys []encryptedKeyEntry
}

type encryptedKeyEntry struct {
	ciphertext []byte
	id         string
	kmsKeyID   string // KMS key ARN or alias; empty = let KMS determine
}

// WithEncryptedKey adds an encrypted key to be unwrapped via KMS Decrypt.
// The ciphertext should be the output of KMS Encrypt or GenerateDataKey.
// The id identifies this key in the config-crypto system.
// The first key added becomes the current key for new encryptions.
func WithEncryptedKey(ciphertext []byte, id string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
		})
	}
}

// WithEncryptedKeyForKMSKey is like WithEncryptedKey but specifies the KMS key
// ARN or alias to use for decryption. Use this when the ciphertext was
// encrypted with a specific KMS key.
func WithEncryptedKeyForKMSKey(ciphertext []byte, id, kmsKeyID string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			kmsKeyID:   kmsKeyID,
		})
	}
}

// New creates a crypto.KeyRingProvider that unwraps encrypted keys using AWS KMS.
//
// At least one key must be provided via WithEncryptedKey or
// WithEncryptedKeyForKMSKey. The first key added becomes the current key for
// new encryptions; additional keys are available for decryption (key rotation).
//
// Keys are decrypted during construction and cached. The KMS client is not
// retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.KeyRingProvider, error) {
	if client == nil {
		return nil, fmt.Errorf("awskms: Client must not be nil")
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	return kmsring.Build(len(o.encryptedKeys), "awskms", func(i int) ([]byte, string, error) {
		ek := o.encryptedKeys[i]
		pt, err := client.Decrypt(ctx, ek.kmsKeyID, ek.ciphertext)
		return pt, ek.id, err
	})
}
