package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// decrypt decrypts data that was encrypted with envelope encryption.
// The key ID from the header is used to look up the KEK from the provider.
func decrypt(data []byte, provider KeyProvider) ([]byte, error) {
	h, ciphertext, err := readHeader(data)
	if err != nil {
		return nil, err
	}

	// Look up the KEK by key ID
	kek, err := provider.KeyByID(h.keyID)
	if err != nil {
		return nil, err
	}

	if len(kek.Bytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(kek.Bytes))
	}

	// Decrypt the DEK, using key ID as AAD to verify key identity binding
	kekBlock, err := aes.NewCipher(kek.Bytes)
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

	// Decrypt the data with the DEK
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
