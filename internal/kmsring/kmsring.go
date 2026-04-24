// Package kmsring factors out the common "unwrap N encrypted keys and build
// a crypto.KeyRingProvider" loop shared by every KMS adapter in this module.
//
// Adapters call Build with the number of keys they hold and a closure that,
// given an index, unwraps the encrypted material and returns the decrypted
// bytes plus the identifier used inside the ring. Build zeroes every
// decrypted byte slice before returning — on success (after copying into the
// ring) and on error (before propagating).
package kmsring

import (
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// KeySize is the required AES-256 key size in bytes.
const KeySize = 32

// UnwrapFn unwraps the i-th encrypted key and returns (plaintext, id, err).
// plaintext must be exactly KeySize bytes; Build zeroes it before returning.
type UnwrapFn func(i int) (plaintext []byte, id string, err error)

// Build unwraps count keys via unwrap and returns a crypto.KeyRingProvider
// with the first key as current and the rest added for decryption. count must
// be at least 1. errPrefix is prepended to wrapped errors ("awskms", ...).
func Build(count int, errPrefix string, unwrap UnwrapFn) (crypto.KeyRingProvider, error) {
	if count < 1 {
		return nil, fmt.Errorf("%s: at least one encrypted key is required", errPrefix)
	}

	type decryptedKey struct {
		bytes []byte
		id    string
	}
	keys := make([]decryptedKey, 0, count)
	defer func() {
		for _, k := range keys {
			clear(k.bytes)
		}
	}()

	for i := range count {
		plaintext, id, err := unwrap(i)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to decrypt key %q: %w", errPrefix, id, err)
		}
		if len(plaintext) != KeySize {
			clear(plaintext)
			return nil, fmt.Errorf("%s: decrypted key %q is %d bytes, want %d", errPrefix, id, len(plaintext), KeySize)
		}
		keys = append(keys, decryptedKey{bytes: plaintext, id: id})
	}

	ring, err := crypto.NewKeyRingProvider(keys[0].bytes, keys[0].id, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	for _, k := range keys[1:] {
		if err := ring.AddKey(k.bytes, k.id, 0); err != nil {
			return nil, fmt.Errorf("%s: %w", errPrefix, err)
		}
	}
	return ring, nil
}
