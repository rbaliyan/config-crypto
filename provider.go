package crypto

import "context"

// Provider encrypts and decrypts data using envelope encryption.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Name returns a short human-readable identifier for this provider.
	// Used for logging and observability; need not be globally unique.
	Name() string

	// Connect initialises any remote connection the provider needs.
	// It is the caller's responsibility to call Connect before the first
	// Encrypt or Decrypt. Implementations backed by in-memory keys treat
	// this as a no-op; remote-key-wrapping implementations use it to
	// establish SDK sessions or verify credentials.
	Connect(ctx context.Context) error

	// Encrypt encrypts plaintext using envelope encryption.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext that was produced by Encrypt.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// HealthCheck reports whether the provider is currently usable. It
	// returns nil for a healthy provider and an error otherwise.
	// Implementations backed by remote services may use ctx to bound the
	// check; static providers ignore ctx and return nil unless closed.
	HealthCheck(ctx context.Context) error

	// Close zeros all key material and releases resources.
	// After Close, Encrypt, Decrypt, and HealthCheck return ErrProviderClosed.
	Close() error
}

// NewProvider builds a static Provider from raw 32-byte AES-256 key bytes.
// Key bytes are copied internally; the caller may safely zero the original
// after construction. The returned Provider does not expose key rotation
// methods; use NewKeyRingProvider when runtime rotation is required.
func NewProvider(keyBytes []byte, id string) (Provider, error) {
	return NewKeyRingProvider(keyBytes, id, 0)
}
