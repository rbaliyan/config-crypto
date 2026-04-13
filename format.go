package crypto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Binary format constants.
const (
	// magic is the 2-byte file signature "EC" (Encrypted Config).
	magic = "EC"

	// formatVersionV1 is the legacy binary format version (read-only).
	formatVersionV1 = 0x01

	// formatVersionV2 is the current binary format version.
	formatVersionV2 = 0x02

	// formatEnvelopeAESGCM is the v2 format byte indicating local AES-GCM envelope encryption.
	formatEnvelopeAESGCM = 0x01

	// algAES256GCM identifies AES-256-GCM as the encryption algorithm.
	algAES256GCM = 0x01

	// aesKeySize is the required key size in bytes (AES-256).
	aesKeySize = 32

	// gcmNonceSize is the nonce size for AES-GCM (12 bytes).
	gcmNonceSize = 12

	// gcmTagSize is the authentication tag size for GCM (16 bytes).
	gcmTagSize = 16

	// encryptedDEKSize is the size of a locally-wrapped DEK: 32-byte key + 16-byte GCM tag.
	encryptedDEKSize = aesKeySize + gcmTagSize

	// minHeaderSizeV1 is the minimum v1 header size: magic(2) + version(1) + alg(1) + keyIDLen(1).
	minHeaderSizeV1 = 5

	// minHeaderSizeV2 is the minimum v2 header size: magic(2) + version(1) + format(1) + alg(1) + keyIDLen(1).
	minHeaderSizeV2 = 6

	// maxKeyIDLen is the maximum key ID length in bytes (1-byte field, 0-255).
	maxKeyIDLen = 255
)

// header represents the parsed header of an encrypted payload.
type header struct {
	version      byte
	format       byte // v2 only; 0 for v1
	algorithm    byte
	keyID        string
	dekNonce     []byte // 12 bytes
	encryptedDEK []byte // variable length (48 for local AES-GCM wrap)
	dataNonce    []byte // 12 bytes
}

// headerSizeV2 returns the total v2 header size in bytes for the given key ID
// and encrypted DEK length.
func headerSizeV2(keyID string, encDEKLen int) int {
	// magic(2) + version(1) + format(1) + alg(1) + keyIDLen(1) + keyID + dekNonce(12) + encDEKLen(2) + encDEK + dataNonce(12)
	return minHeaderSizeV2 + len(keyID) + gcmNonceSize + 2 + encDEKLen + gcmNonceSize
}

// writeHeaderV2 writes the v2 binary header to w.
func writeHeaderV2(w io.Writer, h *header) error {
	if _, err := w.Write([]byte(magic)); err != nil {
		return err
	}

	keyIDBytes := []byte(h.keyID)
	if len(keyIDBytes) > maxKeyIDLen {
		return fmt.Errorf("%w: key ID too long (%d bytes, max %d)", ErrInvalidFormat, len(keyIDBytes), maxKeyIDLen)
	}

	meta := []byte{formatVersionV2, h.format, h.algorithm, byte(len(keyIDBytes))} // #nosec G115 -- keyID length validated above
	if _, err := w.Write(meta); err != nil {
		return err
	}

	if _, err := w.Write(keyIDBytes); err != nil {
		return err
	}

	if _, err := w.Write(h.dekNonce); err != nil {
		return err
	}

	// Variable-length encrypted DEK with 2-byte length prefix.
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(h.encryptedDEK))) // #nosec G115 -- encDEK length fits uint16
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(h.encryptedDEK); err != nil {
		return err
	}

	if _, err := w.Write(h.dataNonce); err != nil {
		return err
	}

	return nil
}

// readHeader parses the binary header from data, dispatching to v1 or v2
// based on the version byte. All byte slices in the returned header are
// defensive copies.
func readHeader(data []byte) (*header, []byte, error) {
	if len(data) < minHeaderSizeV1 {
		return nil, nil, fmt.Errorf("%w: data too short", ErrInvalidFormat)
	}

	if string(data[0:2]) != magic {
		return nil, nil, fmt.Errorf("%w: invalid magic bytes", ErrInvalidFormat)
	}

	version := data[2]
	switch version {
	case formatVersionV1:
		return readHeaderV1(data)
	case formatVersionV2:
		return readHeaderV2(data)
	default:
		return nil, nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidFormat, version)
	}
}

// readHeaderV1 parses a v1 header (backward compatibility for DB-stored ciphertext).
func readHeaderV1(data []byte) (*header, []byte, error) {
	// v1 layout: [2B magic][1B version=0x01][1B alg][1B keyIDLen][NB keyID]
	//            [12B dekNonce][48B encryptedDEK][12B dataNonce][remaining ciphertext]
	h := &header{
		version: formatVersionV1,
	}

	h.algorithm = data[3]
	if h.algorithm != algAES256GCM {
		return nil, nil, fmt.Errorf("%w: unsupported algorithm %d", ErrInvalidFormat, h.algorithm)
	}

	keyIDLen := int(data[4])
	offset := minHeaderSizeV1

	needed := keyIDLen + gcmNonceSize + encryptedDEKSize + gcmNonceSize
	if len(data) < offset+needed {
		return nil, nil, fmt.Errorf("%w: data too short for header", ErrInvalidFormat)
	}

	h.keyID = string(data[offset : offset+keyIDLen])
	offset += keyIDLen

	h.dekNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	h.encryptedDEK = append([]byte(nil), data[offset:offset+encryptedDEKSize]...)
	offset += encryptedDEKSize

	h.dataNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])

	return h, ciphertext, nil
}

// readHeaderV2 parses a v2 header.
func readHeaderV2(data []byte) (*header, []byte, error) {
	// v2 layout: [2B magic][1B version=0x02][1B format][1B alg][1B keyIDLen][NB keyID]
	//            [12B dekNonce][2B encDEKLen][MB encDEK][12B dataNonce][remaining ciphertext]
	if len(data) < minHeaderSizeV2 {
		return nil, nil, fmt.Errorf("%w: data too short for v2 header", ErrInvalidFormat)
	}

	h := &header{
		version: formatVersionV2,
		format:  data[3],
	}

	if h.format != formatEnvelopeAESGCM {
		return nil, nil, fmt.Errorf("%w: format byte 0x%02x", ErrUnsupportedFormat, h.format)
	}

	h.algorithm = data[4]
	if h.algorithm != algAES256GCM {
		return nil, nil, fmt.Errorf("%w: unsupported algorithm %d", ErrInvalidFormat, h.algorithm)
	}

	keyIDLen := int(data[5])
	offset := minHeaderSizeV2

	// Need at least: keyID + dekNonce + 2B encDEKLen
	if len(data) < offset+keyIDLen+gcmNonceSize+2 {
		return nil, nil, fmt.Errorf("%w: data too short for v2 header", ErrInvalidFormat)
	}

	h.keyID = string(data[offset : offset+keyIDLen])
	offset += keyIDLen

	h.dekNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	encDEKLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Need: encDEK + dataNonce
	if len(data) < offset+encDEKLen+gcmNonceSize {
		return nil, nil, fmt.Errorf("%w: data too short for v2 header", ErrInvalidFormat)
	}

	h.encryptedDEK = append([]byte(nil), data[offset:offset+encDEKLen]...)
	offset += encDEKLen

	h.dataNonce = append([]byte(nil), data[offset:offset+gcmNonceSize]...)
	offset += gcmNonceSize

	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])

	return h, ciphertext, nil
}
