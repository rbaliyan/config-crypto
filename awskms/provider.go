// Package awskms provides a crypto.Provider backed by AWS KMS.
//
// Keys are fetched from KMS at construction time and cached in memory.
// The provider uses AWS KMS Decrypt to unwrap encrypted key material
// that has been previously generated via GenerateDataKey or Encrypt.
//
// Usage:
//
//	cfg, err := awsconfig.LoadDefaultConfig(ctx)
//	kmsClient := kms.NewFromConfig(cfg)
//
//	provider, err := awskms.New(ctx, kmsClient, "key-1",
//	    awskms.WithEncryptedKey(encryptedKeyBytes),
//	)
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	crypto "github.com/rbaliyan/config-crypto"
)

// Client is the subset of the AWS KMS API used by this provider.
type Client interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
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

// WithEncryptedKeyForKMSKey is like WithEncryptedKey but specifies the KMS key ARN
// or alias to use for decryption. Use this when the ciphertext was encrypted with
// a specific KMS key.
func WithEncryptedKeyForKMSKey(ciphertext []byte, id, kmsKeyID string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
			kmsKeyID:   kmsKeyID,
		})
	}
}

// New creates a crypto.Provider that unwraps encrypted keys using AWS KMS.
//
// At least one key must be provided via WithEncryptedKey or
// WithEncryptedKeyForKMSKey. The first key added becomes the current key for
// new encryptions; additional keys are available for decryption (key rotation).
//
// Keys are decrypted during construction and cached. The KMS client is not
// retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.Provider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(o.encryptedKeys) == 0 {
		return nil, fmt.Errorf("awskms: at least one encrypted key is required")
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
		input := &kms.DecryptInput{CiphertextBlob: ek.ciphertext}
		if ek.kmsKeyID != "" {
			input.KeyId = &ek.kmsKeyID
		}
		out, err := client.Decrypt(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("awskms: failed to decrypt key %q: %w", ek.id, err)
		}
		if len(out.Plaintext) != 32 {
			return nil, fmt.Errorf("awskms: decrypted key %q is %d bytes, want 32", ek.id, len(out.Plaintext))
		}
		keys = append(keys, decryptedKey{bytes: out.Plaintext, id: ek.id})
	}

	var providerOpts []crypto.Option
	for _, k := range keys[1:] {
		providerOpts = append(providerOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	provider, err := crypto.NewProvider(keys[0].bytes, keys[0].id, providerOpts...)
	if err != nil {
		return nil, fmt.Errorf("awskms: %w", err)
	}
	return provider, nil
}
