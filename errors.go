package crypto

import "errors"

var (
	// ErrKeyNotFound is returned when a key ID is not found in the provider.
	ErrKeyNotFound = errors.New("crypto: key not found")

	// ErrInvalidKeySize is returned when a key is not 32 bytes (AES-256).
	ErrInvalidKeySize = errors.New("crypto: invalid key size, must be 32 bytes")

	// ErrInvalidFormat is returned when encrypted data has an invalid format.
	ErrInvalidFormat = errors.New("crypto: invalid encrypted data format")

	// ErrDecryptionFailed is returned when decryption fails (wrong key, tampered data).
	ErrDecryptionFailed = errors.New("crypto: decryption failed")

	// ErrInvalidKeyID is returned when a key ID is empty or invalid.
	ErrInvalidKeyID = errors.New("crypto: invalid key ID")

	// ErrProviderDestroyed is returned when a provider has been destroyed.
	ErrProviderDestroyed = errors.New("crypto: provider has been destroyed")

	// ErrRemoveCurrentKey is returned when attempting to remove the active encryption key.
	ErrRemoveCurrentKey = errors.New("crypto: cannot remove current key")

	// ErrNoProviderForNamespace is returned when a namespace has no registered provider and no fallback is set.
	ErrNoProviderForNamespace = errors.New("crypto: no key provider for namespace")
)

// IsKeyNotFound returns true if the error is or wraps ErrKeyNotFound.
func IsKeyNotFound(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}

// IsInvalidKeySize returns true if the error is or wraps ErrInvalidKeySize.
func IsInvalidKeySize(err error) bool {
	return errors.Is(err, ErrInvalidKeySize)
}

// IsInvalidFormat returns true if the error is or wraps ErrInvalidFormat.
func IsInvalidFormat(err error) bool {
	return errors.Is(err, ErrInvalidFormat)
}

// IsDecryptionFailed returns true if the error is or wraps ErrDecryptionFailed.
func IsDecryptionFailed(err error) bool {
	return errors.Is(err, ErrDecryptionFailed)
}

// IsInvalidKeyID returns true if the error is or wraps ErrInvalidKeyID.
func IsInvalidKeyID(err error) bool {
	return errors.Is(err, ErrInvalidKeyID)
}

// IsProviderDestroyed returns true if the error is or wraps ErrProviderDestroyed.
func IsProviderDestroyed(err error) bool {
	return errors.Is(err, ErrProviderDestroyed)
}

// IsRemoveCurrentKey returns true if the error is or wraps ErrRemoveCurrentKey.
func IsRemoveCurrentKey(err error) bool {
	return errors.Is(err, ErrRemoveCurrentKey)
}

// IsNoProviderForNamespace returns true if the error is or wraps ErrNoProviderForNamespace.
func IsNoProviderForNamespace(err error) bool {
	return errors.Is(err, ErrNoProviderForNamespace)
}
