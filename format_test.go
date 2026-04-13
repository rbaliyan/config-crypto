package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestHeaderV2RoundTrip(t *testing.T) {
	h := &header{
		version:      formatVersionV2,
		format:       formatEnvelopeAESGCM,
		algorithm:    algAES256GCM,
		keyID:        "key-1",
		dekNonce:     bytes.Repeat([]byte{0xAA}, gcmNonceSize),
		encryptedDEK: bytes.Repeat([]byte{0xBB}, encryptedDEKSize),
		dataNonce:    bytes.Repeat([]byte{0xCC}, gcmNonceSize),
	}

	var buf bytes.Buffer
	if err := writeHeaderV2(&buf, h); err != nil {
		t.Fatalf("writeHeaderV2: %v", err)
	}

	ciphertext := []byte("test-ciphertext")
	data := append(buf.Bytes(), ciphertext...)

	parsed, remaining, err := readHeader(data)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if parsed.version != formatVersionV2 {
		t.Errorf("version: got %d, want %d", parsed.version, formatVersionV2)
	}
	if parsed.format != formatEnvelopeAESGCM {
		t.Errorf("format: got %d, want %d", parsed.format, formatEnvelopeAESGCM)
	}
	if parsed.algorithm != algAES256GCM {
		t.Errorf("algorithm: got %d", parsed.algorithm)
	}
	if parsed.keyID != "key-1" {
		t.Errorf("keyID: got %q, want key-1", parsed.keyID)
	}
	if !bytes.Equal(parsed.dekNonce, h.dekNonce) ||
		!bytes.Equal(parsed.encryptedDEK, h.encryptedDEK) ||
		!bytes.Equal(parsed.dataNonce, h.dataNonce) ||
		!bytes.Equal(remaining, ciphertext) {
		t.Error("byte fields round-tripped incorrectly")
	}
}

// goldenV1Hex is a v1 ciphertext captured once with deterministic inputs.
// The hex string IS the contract: if a future edit to the v1 reader path
// breaks decoding of this byte sequence, that's a data-compatibility
// regression. Regenerate via TestGoldenV1Drift only when the v1 wire format
// intentionally changes (which would itself be a data-compat break).
//
// Fixture inputs (fed to generateDeterministicV1):
//
//	keyBytes  = makeKey(32) (bytes 0..31)
//	keyID     = "v1-key"
//	plaintext = "legacy-v1"
//	DEK       = 32 × 0xAA
//	dekNonce  = 12 × 0xBB
//	dataNonce = 12 × 0xCC
const goldenV1Hex = "454301010676312d6b6579bbbbbbbbbbbbbbbbbbbbbbbb" +
	"29d6588500c2ed4dbe80c41e10152b89626d776d9d4ac9f0013eb392f9e8c8d0" +
	"21e82530098ddd465a258d0fb7ee3d9a" +
	"cccccccccccccccccccccccc" +
	"108fd9608b19f18f26836ec9601c9ab38ebd485f69e6f3450b"

// TestDecryptV1GoldenVector proves that DB-stored v1 ciphertext continues to
// decrypt under the new code. Decodes the hardcoded golden hex.
func TestDecryptV1GoldenVector(t *testing.T) {
	v1Bytes, err := hex.DecodeString(goldenV1Hex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	p := mustNewProvider(t, makeKey(32), "v1-key")
	got, err := p.Decrypt(context.Background(), v1Bytes)
	if err != nil {
		t.Fatalf("Decrypt v1 golden: %v", err)
	}
	if string(got) != "legacy-v1" {
		t.Errorf("got %q, want legacy-v1", got)
	}
}

// TestGoldenV1Drift detects unintentional changes to the golden vector. If
// this fires, either the v1 wire format moved (data-compat break — handle
// separately) or the deterministic fixture inputs changed.
func TestGoldenV1Drift(t *testing.T) {
	regenerated := generateDeterministicV1(t, makeKey(32), "v1-key", []byte("legacy-v1"),
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0xBB}, 12),
		bytes.Repeat([]byte{0xCC}, 12),
	)
	if hex.EncodeToString(regenerated) != goldenV1Hex {
		t.Errorf("v1 golden vector drift detected.\n got: %x\nwant: %s",
			regenerated, goldenV1Hex)
	}
}

// generateDeterministicV1 builds a v1 ciphertext with caller-supplied DEK and
// nonces so the output is reproducible bit-for-bit. Test-only helper.
func generateDeterministicV1(t *testing.T, kek []byte, keyID string, plaintext, dek, dekNonce, dataNonce []byte) []byte {
	t.Helper()
	kekBlock, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		t.Fatal(err)
	}
	encryptedDEK := kekGCM.Seal(nil, dekNonce, dek, []byte(keyID))

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		t.Fatal(err)
	}
	dataCiphertext := dekGCM.Seal(nil, dataNonce, plaintext, []byte(keyID))

	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.WriteByte(formatVersionV1)
	buf.WriteByte(algAES256GCM)
	buf.WriteByte(byte(len(keyID)))
	buf.WriteString(keyID)
	buf.Write(dekNonce)
	buf.Write(encryptedDEK)
	buf.Write(dataNonce)
	buf.Write(dataCiphertext)
	return buf.Bytes()
}

func TestReadHeaderShortData(t *testing.T) {
	if _, _, err := readHeader([]byte("EC")); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderBadMagic(t *testing.T) {
	if _, _, err := readHeader([]byte("XX\x01\x01\x00")); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderUnsupportedVersion(t *testing.T) {
	if _, _, err := readHeader([]byte("EC\x99\x01\x00")); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderV1UnsupportedAlgorithm(t *testing.T) {
	if _, _, err := readHeader([]byte("EC\x01\x99\x00")); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderV2UnsupportedFormat(t *testing.T) {
	// v2 with an unknown format byte must surface ErrUnsupportedFormat.
	data := []byte{
		'E', 'C',
		formatVersionV2,
		0x99, // unknown format
		algAES256GCM,
		0, // empty key ID
	}
	// Pad to minHeaderSizeV2 already; need also at least dekNonce + 2B encLen.
	data = append(data, make([]byte, gcmNonceSize+2)...)
	_, _, err := readHeader(data)
	if !IsUnsupportedFormat(err) {
		t.Errorf("expected ErrUnsupportedFormat, got %v", err)
	}
}

func TestReadHeaderV2TruncatedBody(t *testing.T) {
	// Valid v2 prefix but truncated before encDEK.
	data := []byte{'E', 'C', formatVersionV2, formatEnvelopeAESGCM, algAES256GCM, 0x04, 'k', 'e', 'y', '1'}
	if _, _, err := readHeader(data); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderV2Roundtrip_VarLengthDEK(t *testing.T) {
	// Construct a header with a non-48-byte wrapped DEK to exercise the
	// variable-length path.
	h := &header{
		version:      formatVersionV2,
		format:       formatEnvelopeAESGCM,
		algorithm:    algAES256GCM,
		keyID:        "k",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: bytes.Repeat([]byte{0xEE}, 100),
		dataNonce:    make([]byte, gcmNonceSize),
	}
	var buf bytes.Buffer
	if err := writeHeaderV2(&buf, h); err != nil {
		t.Fatal(err)
	}
	parsed, _, err := readHeader(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.encryptedDEK) != 100 {
		t.Errorf("encDEK len: got %d, want 100", len(parsed.encryptedDEK))
	}
}

func TestWriteHeaderV2KeyIDTooLong(t *testing.T) {
	h := &header{
		version:      formatVersionV2,
		format:       formatEnvelopeAESGCM,
		algorithm:    algAES256GCM,
		keyID:        string(make([]byte, 256)),
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}
	var buf bytes.Buffer
	if err := writeHeaderV2(&buf, h); !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestReadHeaderCiphertextIsolated(t *testing.T) {
	h := &header{
		version:      formatVersionV2,
		format:       formatEnvelopeAESGCM,
		algorithm:    algAES256GCM,
		keyID:        "k",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}
	var buf bytes.Buffer
	if err := writeHeaderV2(&buf, h); err != nil {
		t.Fatal(err)
	}
	original := []byte("test-ciphertext")
	input := append(buf.Bytes(), original...)
	inputCopy := append([]byte(nil), input...)

	_, ct, err := readHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		ct[i] = 0xFF
	}
	if !bytes.Equal(input, inputCopy) {
		t.Error("mutating ciphertext corrupted input")
	}
}

// limitWriter writes up to n bytes then errors.
type limitWriter struct{ n int }

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

func TestWriteHeaderV2FailingWriter(t *testing.T) {
	h := &header{
		version:      formatVersionV2,
		format:       formatEnvelopeAESGCM,
		algorithm:    algAES256GCM,
		keyID:        "key-1",
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}
	totalSize := headerSizeV2(h.keyID, encryptedDEKSize)
	for limit := range totalSize {
		w := &limitWriter{n: limit}
		if err := writeHeaderV2(w, h); err == nil {
			t.Errorf("limit=%d: expected error", limit)
		}
	}
	if err := writeHeaderV2(&limitWriter{n: totalSize}, h); err != nil {
		t.Errorf("full limit: %v", err)
	}
}

func TestHeaderSizeV2(t *testing.T) {
	keyID := "key-1"
	expected := minHeaderSizeV2 + len(keyID) + gcmNonceSize + 2 + encryptedDEKSize + gcmNonceSize
	if got := headerSizeV2(keyID, encryptedDEKSize); got != expected {
		t.Errorf("got %d, want %d", got, expected)
	}
}

// Ensure that big-endian length prefix decodes large values correctly.
func TestEncryptedDEKLenBigEndian(t *testing.T) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], 1024)
	if lenBuf[0] != 0x04 || lenBuf[1] != 0x00 {
		t.Fatalf("len encoding mismatch: %v", lenBuf)
	}
}
