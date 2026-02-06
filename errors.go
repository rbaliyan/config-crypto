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
