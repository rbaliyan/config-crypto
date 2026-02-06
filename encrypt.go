package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// encrypt encrypts plaintext using envelope encryption with the given KEK.
// A random DEK is generated per call, encrypted with the KEK, and prepended to the output.
func encrypt(plaintext []byte, kek Key) ([]byte, error) {
	if len(kek.Bytes) != aesKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(kek.Bytes))
	}

	// Generate random DEK
	dek := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate DEK: %w", err)
	}
	defer clear(dek)

	// Encrypt DEK with KEK, using key ID as AAD to bind key identity to ciphertext
	kekBlock, err := aes.NewCipher(kek.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create KEK cipher: %w", err)
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create KEK GCM: %w", err)
	}

	dekNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate DEK nonce: %w", err)
	}
	encryptedDEK := kekGCM.Seal(nil, dekNonce, dek, []byte(kek.ID))

	// Encrypt data with DEK
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create DEK cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create DEK GCM: %w", err)
	}

	dataNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate data nonce: %w", err)
	}
	ciphertext := dekGCM.Seal(nil, dataNonce, plaintext, []byte(kek.ID))

	// Assemble output: header + ciphertext
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        kek.ID,
		dekNonce:     dekNonce,
		encryptedDEK: encryptedDEK,
		dataNonce:    dataNonce,
	}

	var buf bytes.Buffer
	buf.Grow(headerSize(kek.ID) + len(ciphertext))
	if err := writeHeader(&buf, h); err != nil {
		return nil, fmt.Errorf("crypto: failed to write header: %w", err)
	}
	buf.Write(ciphertext)

	return buf.Bytes(), nil
}
