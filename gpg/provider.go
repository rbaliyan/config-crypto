// Package gpg provides a crypto.Provider that decrypts AES-256 keys using GPG.
//
// Keys are stored as GPG-encrypted blobs (ASCII-armored or binary). At
// construction time each blob is decrypted via the provided Client and the
// plaintext key material is cached. The Client is not retained after
// construction.
//
// This provider is suited for non-server deployments where keys are distributed
// as GPG-encrypted files alongside the application — no KMS service required.
//
// Usage:
//
//	encryptedKey, _ := os.ReadFile("keys/current.key.gpg")
//	client := gpg.NewExecClient() // uses system gpg binary
//	provider, err := gpg.New(ctx, client,
//	    gpg.WithEncryptedKey(encryptedKey, "key-1"),
//	)
//
// For key rotation, add the previous key as a secondary entry:
//
//	provider, err := gpg.New(ctx, client,
//	    gpg.WithEncryptedKey(newKeyBlob, "key-2"),
//	    gpg.WithEncryptedKey(oldKeyBlob, "key-1"),
//	)
//	// key-2 is current; key-1 is available for decrypting existing data
package gpg

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// Client abstracts the GPG decryption operation.
// Implementations must decrypt the ciphertext and return the raw plaintext bytes.
// Callers bring their own implementation: ExecClient (system gpg binary),
// or a pure-Go wrapper around golang.org/x/crypto/openpgp or ProtonMail/go-crypto.
type Client interface {
	// Decrypt decrypts the GPG-encrypted ciphertext and returns the plaintext.
	// The ciphertext may be ASCII-armored or binary — implementations decide
	// which formats they support.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Option configures the GPG provider.
type Option func(*options)

type options struct {
	encryptedKeys []encryptedKeyEntry
}

type encryptedKeyEntry struct {
	ciphertext []byte
	id         string
}

// WithEncryptedKey registers a GPG-encrypted AES-256 key.
// The ciphertext is the GPG-encrypted 32-byte key material (ASCII-armored or binary).
// The id identifies this key in the config-crypto system.
//
// The first call to WithEncryptedKey sets the current key used for new encryptions.
// Subsequent calls register additional keys for decryption during key rotation.
func WithEncryptedKey(ciphertext []byte, id string) Option {
	return func(o *options) {
		o.encryptedKeys = append(o.encryptedKeys, encryptedKeyEntry{
			ciphertext: ciphertext,
			id:         id,
		})
	}
}

// New creates a crypto.Provider that decrypts key material using GPG.
//
// At least one key must be provided via WithEncryptedKey. The first key is the
// current key for new encryptions; additional keys support decryption during
// key rotation.
//
// All keys are decrypted during construction and cached. The Client is not
// retained after construction.
func New(ctx context.Context, client Client, opts ...Option) (crypto.Provider, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(o.encryptedKeys) == 0 {
		return nil, fmt.Errorf("gpg: at least one encrypted key is required")
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
		plaintext, err := client.Decrypt(ctx, ek.ciphertext)
		if err != nil {
			return nil, fmt.Errorf("gpg: failed to decrypt key %q: %w", ek.id, err)
		}
		if len(plaintext) != 32 {
			return nil, fmt.Errorf("gpg: decrypted key %q is %d bytes, want 32", ek.id, len(plaintext))
		}
		keys = append(keys, decryptedKey{bytes: plaintext, id: ek.id})
	}

	var providerOpts []crypto.Option
	for _, k := range keys[1:] {
		providerOpts = append(providerOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	provider, err := crypto.NewProvider(keys[0].bytes, keys[0].id, providerOpts...)
	if err != nil {
		return nil, fmt.Errorf("gpg: %w", err)
	}
	return provider, nil
}
