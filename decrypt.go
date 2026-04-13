package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// keyLookupFunc returns a defensive copy of key bytes for the given ID.
type keyLookupFunc func(id string) ([]byte, error)

// decryptEnvelope decrypts data that was encrypted with envelope encryption.
// It supports both v1 and v2 header formats.
func decryptEnvelope(data []byte, lookupKey keyLookupFunc) ([]byte, error) {
	h, ciphertext, err := readHeader(data)
	if err != nil {
		return nil, err
	}

	// GCM ciphertext must contain at least the authentication tag.
	if len(ciphertext) < gcmTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidFormat)
	}

	// Look up the KEK by key ID.
	kekBytes, err := lookupKey(h.keyID)
	if err != nil {
		return nil, err
	}
	defer clear(kekBytes)

	if len(kekBytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(kekBytes))
	}

	// Decrypt the DEK, using key ID as AAD.
	kekBlock, err := aes.NewCipher(kekBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	dek, err := kekGCM.Open(nil, h.dekNonce, h.encryptedDEK, []byte(h.keyID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt DEK", ErrDecryptionFailed)
	}
	defer clear(dek)

	// Decrypt the data with the DEK.
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := dekGCM.Open(nil, h.dataNonce, ciphertext, []byte(h.keyID))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt data", ErrDecryptionFailed)
	}

	return plaintext, nil
}
