package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        "key-1",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	// Fill with recognizable data
	for i := range h.dekNonce {
		h.dekNonce[i] = 0xAA
	}
	for i := range h.encryptedDEK {
		h.encryptedDEK[i] = 0xBB
	}
	for i := range h.dataNonce {
		h.dataNonce[i] = 0xCC
	}

	var buf bytes.Buffer
	if err := writeHeader(&buf, h); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	ciphertext := []byte("test-ciphertext")
	data := append(buf.Bytes(), ciphertext...)

	parsed, remaining, err := readHeader(data)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}

	if parsed.version != h.version {
		t.Errorf("version: got %d, want %d", parsed.version, h.version)
	}
	if parsed.algorithm != h.algorithm {
		t.Errorf("algorithm: got %d, want %d", parsed.algorithm, h.algorithm)
	}
	if parsed.keyID != h.keyID {
		t.Errorf("keyID: got %q, want %q", parsed.keyID, h.keyID)
	}
	if !bytes.Equal(parsed.dekNonce, h.dekNonce) {
		t.Error("dekNonce mismatch")
	}
	if !bytes.Equal(parsed.encryptedDEK, h.encryptedDEK) {
		t.Error("encryptedDEK mismatch")
	}
	if !bytes.Equal(parsed.dataNonce, h.dataNonce) {
		t.Error("dataNonce mismatch")
	}
	if !bytes.Equal(remaining, ciphertext) {
		t.Errorf("remaining: got %q, want %q", remaining, ciphertext)
	}
}

func TestHeaderEmptyKeyID(t *testing.T) {
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        "",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	var buf bytes.Buffer
	if err := writeHeader(&buf, h); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	parsed, _, err := readHeader(buf.Bytes())
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if parsed.keyID != "" {
		t.Errorf("keyID: got %q, want empty", parsed.keyID)
	}
}

func TestReadHeaderShortData(t *testing.T) {
	_, _, err := readHeader([]byte("EC"))
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderBadMagic(t *testing.T) {
	data := []byte("XX\x01\x01\x00")
	_, _, err := readHeader(data)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderUnsupportedVersion(t *testing.T) {
	data := []byte("EC\x99\x01\x00")
	_, _, err := readHeader(data)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderUnsupportedAlgorithm(t *testing.T) {
	data := []byte("EC\x01\x99\x00")
	_, _, err := readHeader(data)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderTruncatedBody(t *testing.T) {
	// Valid header start but truncated before DEK nonce
	data := []byte("EC\x01\x01\x04key1")
	_, _, err := readHeader(data)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderEmptyRemainingCiphertext(t *testing.T) {
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        "k",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	var buf bytes.Buffer
	if err := writeHeader(&buf, h); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}

	// Input ends exactly at header boundary — no ciphertext
	parsed, remaining, err := readHeader(buf.Bytes())
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if parsed.keyID != "k" {
		t.Errorf("keyID: got %q, want %q", parsed.keyID, "k")
	}
	if len(remaining) != 0 {
		t.Errorf("remaining: got %d bytes, want 0", len(remaining))
	}
}

// limitWriter writes up to n bytes then returns an error.
type limitWriter struct {
	n int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, fmt.Errorf("write limit reached")
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, fmt.Errorf("write limit reached")
	}
	w.n -= len(p)
	return len(p), nil
}

func TestWriteHeaderFailingWriter(t *testing.T) {
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        "key-1",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	// Test failure at various byte offsets
	totalSize := headerSize("key-1")
	for limit := 0; limit < totalSize; limit++ {
		w := &limitWriter{n: limit}
		err := writeHeader(w, h)
		if err == nil {
			t.Errorf("writeHeader with limit=%d: expected error", limit)
		}
	}

	// Writing the full size should succeed
	w := &limitWriter{n: totalSize}
	if err := writeHeader(w, h); err != nil {
		t.Errorf("writeHeader with full limit: %v", err)
	}
}

func TestHeaderSize(t *testing.T) {
	keyID := "key-1"
	expected := minHeaderSize + len(keyID) + gcmNonceSize + encryptedDEKSize + gcmNonceSize
	got := headerSize(keyID)
	if got != expected {
		t.Errorf("headerSize(%q): got %d, want %d", keyID, got, expected)
	}
}
