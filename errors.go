package crypto

import "errors"

var (
	// ErrKeyNotFound is returned when a key ID is not found in the provider.
	ErrKeyNotFound = errors.New("crypto: key not found")

	// ErrInvalidKeySize is returned when a key is not 32 bytes (AES-256).
	ErrInvalidKeySize = errors.New("crypto: invalid key size, must be 32 bytes")

	// ErrInvalidFormat is returned when encrypted data has an invalid format.
	ErrInvalidFormat = errors.New("crypto: invalid encrypted data format")

	// ErrUnsupportedFormat is returned when the format byte in a v2 header is not recognised.
	ErrUnsupportedFormat = errors.New("crypto: unsupported encrypted format")

	// ErrDecryptionFailed is returned when decryption fails (wrong key, tampered data).
	ErrDecryptionFailed = errors.New("crypto: decryption failed")

	// ErrInvalidKeyID is returned when a key ID is empty or invalid.
	ErrInvalidKeyID = errors.New("crypto: invalid key ID")

	// ErrProviderClosed is returned when a provider has been closed.
	ErrProviderClosed = errors.New("crypto: provider has been closed")

	// ErrRemoveCurrentKey is returned when attempting to remove the active encryption key.
	ErrRemoveCurrentKey = errors.New("crypto: cannot remove current key")

	// ErrNoProviderForNamespace is returned when a namespace has no registered provider and no fallback is set.
	ErrNoProviderForNamespace = errors.New("crypto: no key provider for namespace")

	// ErrDuplicateKeyID is returned from AddKey when the key ID is already present in the ring.
	ErrDuplicateKeyID = errors.New("crypto: duplicate key ID")
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

// IsUnsupportedFormat returns true if the error is or wraps ErrUnsupportedFormat.
func IsUnsupportedFormat(err error) bool {
	return errors.Is(err, ErrUnsupportedFormat)
}

// IsDecryptionFailed returns true if the error is or wraps ErrDecryptionFailed.
func IsDecryptionFailed(err error) bool {
	return errors.Is(err, ErrDecryptionFailed)
}

// IsInvalidKeyID returns true if the error is or wraps ErrInvalidKeyID.
func IsInvalidKeyID(err error) bool {
	return errors.Is(err, ErrInvalidKeyID)
}

// IsProviderClosed returns true if the error is or wraps ErrProviderClosed.
func IsProviderClosed(err error) bool {
	return errors.Is(err, ErrProviderClosed)
}

// IsRemoveCurrentKey returns true if the error is or wraps ErrRemoveCurrentKey.
func IsRemoveCurrentKey(err error) bool {
	return errors.Is(err, ErrRemoveCurrentKey)
}

// IsNoProviderForNamespace returns true if the error is or wraps ErrNoProviderForNamespace.
func IsNoProviderForNamespace(err error) bool {
	return errors.Is(err, ErrNoProviderForNamespace)
}

// IsDuplicateKeyID returns true if the error is or wraps ErrDuplicateKeyID.
func IsDuplicateKeyID(err error) bool {
	return errors.Is(err, ErrDuplicateKeyID)
}
