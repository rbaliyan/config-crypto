package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/rbaliyan/config"
	"github.com/rbaliyan/config/codec"
	"github.com/rbaliyan/config/memory"
)

func testProvider(t *testing.T) *StaticKeyProvider {
	t.Helper()
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testCodec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec(codec.JSON(), testProvider(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

func TestCodecName(t *testing.T) {
	c := testCodec(t)
	if c.Name() != "encrypted:json" {
		t.Errorf("Name(): got %q, want %q", c.Name(), "encrypted:json")
	}
}

func TestCodecRoundTripString(t *testing.T) {
	c := testCodec(t)

	data, err := c.Encode("hello world")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Encrypted data should not contain plaintext
	if bytes.Contains(data, []byte("hello world")) {
		t.Error("encrypted data contains plaintext")
	}

	var got string
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "hello world" {
		t.Errorf("Decode: got %q, want %q", got, "hello world")
	}
}

func TestCodecRoundTripStruct(t *testing.T) {
	type Config struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}

	c := testCodec(t)

	original := Config{Host: "localhost", Port: 8080}
	data, err := c.Encode(original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got Config
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != original {
		t.Errorf("Decode: got %+v, want %+v", got, original)
	}
}

func TestCodecRoundTripMap(t *testing.T) {
	c := testCodec(t)

	original := map[string]any{
		"key": "value",
		"num": float64(42),
	}
	data, err := c.Encode(original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got map[string]any
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got["key"] != original["key"] || got["num"] != original["num"] {
		t.Errorf("Decode: got %v, want %v", got, original)
	}
}

func TestCodecRoundTripInt(t *testing.T) {
	c := testCodec(t)

	data, err := c.Encode(42)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got int
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != 42 {
		t.Errorf("Decode: got %d, want %d", got, 42)
	}
}

func TestCodecKeyRotation(t *testing.T) {
	oldKey := makeKey(32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}

	// Encrypt with old key
	oldProvider, err := NewStaticKeyProvider(oldKey, "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	oldCodec, err := NewCodec(codec.JSON(), oldProvider)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	data, err := oldCodec.Encode("secret")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decrypt with new provider that has both keys
	newProvider, err := NewStaticKeyProvider(newKey, "key-v2",
		WithOldKey(oldKey, "key-v1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	newCodec, err := NewCodec(codec.JSON(), newProvider)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	var got string
	if err := newCodec.Decode(data, &got); err != nil {
		t.Fatalf("Decode with rotated key: %v", err)
	}
	if got != "secret" {
		t.Errorf("got %q, want %q", got, "secret")
	}
}

func TestCodecWrongKey(t *testing.T) {
	c := testCodec(t)

	data, err := c.Encode("secret")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Try to decrypt with a different key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = 0xFF
	}
	wrongProvider, err := NewStaticKeyProvider(wrongKey, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	wrongCodec, err := NewCodec(codec.JSON(), wrongProvider)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	var got string
	err = wrongCodec.Decode(data, &got)
	if !IsDecryptionFailed(err) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCodecTamperedData(t *testing.T) {
	c := testCodec(t)

	data, err := c.Encode("secret")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Tamper with the last byte (in the ciphertext/GCM tag area)
	data[len(data)-1] ^= 0xFF

	var got string
	err = c.Decode(data, &got)
	if !IsDecryptionFailed(err) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCodecInvalidFormat(t *testing.T) {
	c := testCodec(t)

	var got string
	err := c.Decode([]byte("not encrypted"), &got)
	if !IsInvalidFormat(err) && !IsDecryptionFailed(err) {
		t.Errorf("expected format or decryption error, got %v", err)
	}
}

func TestCodecEmptyData(t *testing.T) {
	c := testCodec(t)

	// Encode empty string
	data, err := c.Encode("")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got string
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestCodecLargePayload(t *testing.T) {
	c := testCodec(t)

	// 1MB payload
	large := make([]byte, 1<<20)
	for i := range large {
		large[i] = byte(i % 256)
	}

	data, err := c.Encode(large)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got []byte
	if err := c.Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got, large) {
		t.Error("large payload round-trip mismatch")
	}
}

func TestCodecConcurrent(t *testing.T) {
	c := testCodec(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			data, err := c.Encode(n)
			if err != nil {
				t.Errorf("Encode(%d): %v", n, err)
				return
			}

			var got int
			if err := c.Decode(data, &got); err != nil {
				t.Errorf("Decode(%d): %v", n, err)
				return
			}
			if got != n {
				t.Errorf("got %d, want %d", got, n)
			}
		}(i)
	}
	wg.Wait()
}

func TestCodecDifferentEncryptionsSameInput(t *testing.T) {
	c := testCodec(t)

	data1, err := c.Encode("same input")
	if err != nil {
		t.Fatal(err)
	}
	data2, err := c.Encode("same input")
	if err != nil {
		t.Fatal(err)
	}

	// Random DEK and nonces mean outputs should differ
	if bytes.Equal(data1, data2) {
		t.Error("two encryptions of same input produced identical output")
	}

	// Both should decode to same value
	var got1, got2 string
	if err := c.Decode(data1, &got1); err != nil {
		t.Fatal(err)
	}
	if err := c.Decode(data2, &got2); err != nil {
		t.Fatal(err)
	}
	if got1 != got2 {
		t.Errorf("decoded values differ: %q vs %q", got1, got2)
	}
}

func TestCodecIntegrationWithMemoryStore(t *testing.T) {
	ctx := context.Background()

	// Set up encrypted codec
	key := makeKey(32)
	provider, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	encJSON, err := NewCodec(codec.JSON(), provider)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if err := codec.Register(encJSON); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Create a memory store
	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)

	// Create a value with the encrypted codec
	original := "my-secret-api-key"
	encoded, err := encJSON.Encode(original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Verify the encoded bytes don't contain the plaintext
	plainJSON, _ := json.Marshal(original)
	if bytes.Contains(encoded, plainJSON) {
		t.Error("encoded data contains plaintext JSON")
	}

	// Store the encrypted value
	val, err := config.NewValueFromBytes(encoded, encJSON.Name())
	if err != nil {
		t.Fatalf("NewValueFromBytes: %v", err)
	}
	_, err = store.Set(ctx, config.DefaultNamespace, "secrets/api-key", val)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Read it back
	got, err := store.Get(ctx, config.DefaultNamespace, "secrets/api-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Verify the codec name was preserved
	if got.Codec() != "encrypted:json" {
		t.Errorf("Codec(): got %q, want %q", got.Codec(), "encrypted:json")
	}

	// Unmarshal should decrypt and deserialize
	var result string
	if err := got.Unmarshal(&result); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if result != original {
		t.Errorf("Unmarshal: got %q, want %q", result, original)
	}
}

// --- New tests for uncovered error paths ---

func TestNewCodecReturnsErrorOnNilInner(t *testing.T) {
	_, err := NewCodec(nil, testProvider(t))
	if err == nil {
		t.Error("expected error for nil inner codec")
	}
}

func TestNewCodecReturnsErrorOnNilProvider(t *testing.T) {
	_, err := NewCodec(codec.JSON(), nil)
	if err == nil {
		t.Error("expected error for nil provider")
	}
}

// failingProvider is a KeyProvider that always returns errors.
type failingProvider struct{}

func (p *failingProvider) CurrentKey() (Key, error) {
	return Key{}, errors.New("key unavailable")
}

func (p *failingProvider) KeyByID(id string) (Key, error) {
	return Key{}, errors.New("key unavailable")
}

func TestCodecEncodeCurrentKeyFailure(t *testing.T) {
	c, err := NewCodec(codec.JSON(), &failingProvider{})
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	_, err = c.Encode("test")
	if err == nil {
		t.Error("expected error when CurrentKey fails")
	}
	if !strings.Contains(err.Error(), "failed to get current key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCodecDecodeInnerCodecFailure(t *testing.T) {
	c := testCodec(t)

	// Encrypt a string
	data, err := c.Encode("hello")
	if err != nil {
		t.Fatal(err)
	}

	// Try to decode into an incompatible type (int pointer)
	// JSON will fail to unmarshal "hello" into *int
	var got struct{ X chan int } // channels can't be unmarshalled
	err = c.Decode(data, &got)
	if err == nil {
		t.Error("expected error for inner decode failure")
	}
	if !strings.Contains(err.Error(), "inner decode failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCodecEncodeInnerCodecFailure(t *testing.T) {
	c := testCodec(t)

	// channels can't be JSON-encoded
	_, err := c.Encode(make(chan int))
	if err == nil {
		t.Error("expected error for inner encode failure")
	}
	if !strings.Contains(err.Error(), "inner encode failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDecryptCiphertextTooShort(t *testing.T) {
	// Encrypt something valid, then truncate the ciphertext
	key := makeKey(32)
	provider, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	data, err := encrypt([]byte("hello"), Key{ID: "test-key", Bytes: key})
	if err != nil {
		t.Fatal(err)
	}

	// Truncate to just the header (remove all ciphertext)
	h := headerSize("test-key")
	truncated := data[:h]

	_, err = decrypt(truncated, provider)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat for truncated ciphertext, got %v", err)
	}
}

func TestDecryptCiphertextPartialTag(t *testing.T) {
	key := makeKey(32)
	provider, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	data, err := encrypt([]byte("hello"), Key{ID: "test-key", Bytes: key})
	if err != nil {
		t.Fatal(err)
	}

	// Keep header + partial GCM tag (less than 16 bytes)
	h := headerSize("test-key")
	truncated := data[:h+8]

	_, err = decrypt(truncated, provider)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat for partial GCM tag, got %v", err)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := makeKey(32)
	provider, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	data, err := encrypt([]byte{}, Key{ID: "test-key", Bytes: key})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	plaintext, err := decrypt(data, provider)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(plaintext) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(plaintext))
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	_, err := encrypt([]byte("hello"), Key{ID: "bad", Bytes: makeKey(16)})
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestDecryptInvalidKeySize(t *testing.T) {
	key := makeKey(32)
	data, err := encrypt([]byte("hello"), Key{ID: "test-key", Bytes: key})
	if err != nil {
		t.Fatal(err)
	}

	// Provider returns a key with wrong size
	badProvider := &badKeySizeProvider{id: "test-key", bytes: makeKey(16)}
	_, err = decrypt(data, badProvider)
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

type badKeySizeProvider struct {
	id    string
	bytes []byte
}

func (p *badKeySizeProvider) CurrentKey() (Key, error) {
	return Key{ID: p.id, Bytes: p.bytes}, nil
}

func (p *badKeySizeProvider) KeyByID(id string) (Key, error) {
	if id == p.id {
		return Key{ID: p.id, Bytes: p.bytes}, nil
	}
	return Key{}, ErrKeyNotFound
}

func TestReadHeaderCiphertextIsolated(t *testing.T) {
	// Verify that mutating the returned ciphertext doesn't affect the input
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
		t.Fatal(err)
	}

	original := []byte("test-ciphertext")
	input := append(buf.Bytes(), original...)

	// Save a copy of the input for comparison
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)

	_, ciphertext, err := readHeader(input)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the returned ciphertext
	for i := range ciphertext {
		ciphertext[i] = 0xFF
	}

	// Input should be unchanged (defensive copy)
	if !bytes.Equal(input, inputCopy) {
		t.Error("mutating returned ciphertext corrupted the input slice")
	}
}

func TestWriteHeaderKeyIDTooLong(t *testing.T) {
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        strings.Repeat("x", 256),
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	var buf bytes.Buffer
	err := writeHeader(&buf, h)
	if !IsInvalidFormat(err) {
		t.Errorf("expected ErrInvalidFormat for key ID > 255 bytes, got %v", err)
	}
}

func TestWriteHeaderMaxKeyID(t *testing.T) {
	// 255-byte key ID should work
	h := &header{
		version:      formatVersion,
		algorithm:    algAES256GCM,
		keyID:        strings.Repeat("k", 255),
		dekNonce:     make([]byte, gcmNonceSize),
		encryptedDEK: make([]byte, encryptedDEKSize),
		dataNonce:    make([]byte, gcmNonceSize),
	}

	var buf bytes.Buffer
	if err := writeHeader(&buf, h); err != nil {
		t.Fatalf("writeHeader should accept 255-byte key ID: %v", err)
	}

	parsed, _, err := readHeader(buf.Bytes())
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if parsed.keyID != h.keyID {
		t.Errorf("keyID length: got %d, want %d", len(parsed.keyID), len(h.keyID))
	}
}
