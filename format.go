package crypto

import (
	"fmt"
	"io"
)

// Binary format constants.
const (
	// magic is the 2-byte file signature "EC" (Encrypted Config).
	magic = "EC"

	// formatVersion is the current binary format version.
	formatVersion = 0x01

	// algAES256GCM identifies AES-256-GCM as the encryption algorithm.
	algAES256GCM = 0x01

	// aesKeySize is the required key size in bytes (AES-256).
	aesKeySize = 32

	// gcmNonceSize is the nonce size for AES-GCM (12 bytes).
	gcmNonceSize = 12

	// gcmTagSize is the authentication tag size for GCM (16 bytes).
	gcmTagSize = 16

	// encryptedDEKSize is the size of an encrypted DEK: 32-byte key + 16-byte GCM tag.
	encryptedDEKSize = aesKeySize + gcmTagSize

	// minHeaderSize is the minimum header size: magic(2) + version(1) + alg(1) + keyIDLen(1).
	minHeaderSize = 5
)

// header represents the parsed header of an encrypted payload.
type header struct {
	version      byte
	algorithm    byte
	keyID        string
	dekNonce     []byte // 12 bytes
	encryptedDEK []byte // 48 bytes (32B DEK + 16B GCM tag)
	dataNonce    []byte // 12 bytes
}

// headerSize returns the total header size in bytes for the given key ID.
func headerSize(keyID string) int {
	return minHeaderSize + len(keyID) + gcmNonceSize + encryptedDEKSize + gcmNonceSize
}

// writeHeader writes the binary header to w.
func writeHeader(w io.Writer, h *header) error {
	// Magic bytes
	if _, err := w.Write([]byte(magic)); err != nil {
		return err
	}

	// Version + Algorithm + Key ID length
	keyIDBytes := []byte(h.keyID)
	if len(keyIDBytes) > 255 {
		return fmt.Errorf("%w: key ID too long", ErrInvalidFormat)
	}
	meta := []byte{h.version, h.algorithm, byte(len(keyIDBytes))}
	if _, err := w.Write(meta); err != nil {
		return err
	}

	// Key ID
	if _, err := w.Write(keyIDBytes); err != nil {
		return err
	}

	// DEK nonce
	if _, err := w.Write(h.dekNonce); err != nil {
		return err
	}

	// Encrypted DEK
	if _, err := w.Write(h.encryptedDEK); err != nil {
		return err
	}

	// Data nonce
	if _, err := w.Write(h.dataNonce); err != nil {
		return err
	}

	return nil
}

// readHeader parses the binary header from data, returning the header and remaining ciphertext.
// All byte slices in the returned header are defensive copies, safe from caller mutation.
func readHeader(data []byte) (*header, []byte, error) {
	if len(data) < minHeaderSize {
		return nil, nil, fmt.Errorf("%w: data too short", ErrInvalidFormat)
	}

	// Check magic bytes
	if string(data[0:2]) != magic {
		return nil, nil, fmt.Errorf("%w: invalid magic bytes", ErrInvalidFormat)
	}

	h := &header{
		version:   data[2],
		algorithm: data[3],
	}

	// Validate version
	if h.version != formatVersion {
		return nil, nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidFormat, h.version)
	}

	// Validate algorithm
	if h.algorithm != algAES256GCM {
		return nil, nil, fmt.Errorf("%w: unsupported algorithm %d", ErrInvalidFormat, h.algorithm)
	}

	keyIDLen := int(data[4])
	offset := minHeaderSize

	// Ensure enough data for key ID + DEK nonce + encrypted DEK + data nonce
	needed := keyIDLen + gcmNonceSize + encryptedDEKSize + gcmNonceSize
	if len(data) < offset+needed {
		return nil, nil, fmt.Errorf("%w: data too short for header", ErrInvalidFormat)
	}

	h.keyID = string(data[offset : offset+keyIDLen])
	offset += keyIDLen

	// Defensive copies to prevent corruption if caller mutates the input slice
	h.dekNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	h.encryptedDEK = append([]byte(nil), data[offset:offset+encryptedDEKSize]...)
	offset += encryptedDEKSize

	h.dataNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	return h, data[offset:], nil
}
