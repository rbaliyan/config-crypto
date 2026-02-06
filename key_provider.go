package crypto

// Key represents a named encryption key.
type Key struct {
	// ID is a unique identifier for the key (e.g., "key-2024-01").
	ID string

	// Bytes is the raw key material. Must be 32 bytes for AES-256.
	Bytes []byte
}

// copy returns a Key with a copied byte slice, preventing callers from mutating internal state.
func (k Key) copy() Key {
	b := make([]byte, len(k.Bytes))
	copy(b, k.Bytes)
	return Key{ID: k.ID, Bytes: b}
}

// KeyProvider abstracts key retrieval for encryption and decryption.
// Implementations must be safe for concurrent use.
type KeyProvider interface {
	// CurrentKey returns the key to use for new encryptions.
	CurrentKey() (Key, error)

	// KeyByID returns the key with the given ID, used for decryption.
	// Returns ErrKeyNotFound if the key ID is not known.
	KeyByID(id string) (Key, error)
}
