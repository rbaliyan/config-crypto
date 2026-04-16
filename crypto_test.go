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
	jsoncodec "github.com/rbaliyan/config/codec/json"
	"github.com/rbaliyan/config/memory"
)

func testCodec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec(jsoncodec.New(), mustNewProvider(t, makeKey(32), "test-key"))
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

func TestWithClientCodec(t *testing.T) {
	ctx := context.Background()
	c, err := NewCodec(jsoncodec.New(), mustNewProvider(t, makeKey(32), "test-key"), WithClientCodec())
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if c.Name() != "client:encrypted:json" {
		t.Errorf("Name() = %q, want %q", c.Name(), "client:encrypted:json")
	}

	data, err := c.Encode(ctx, "hello")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got string
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "hello" {
		t.Errorf("Decode: got %q, want %q", got, "hello")
	}
}

func TestWithCodecPrefix(t *testing.T) {
	c, err := NewCodec(jsoncodec.New(), mustNewProvider(t, makeKey(32), "test-key"), WithCodecPrefix("custom"))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if c.Name() != "custom:encrypted:json" {
		t.Errorf("Name() = %q, want %q", c.Name(), "custom:encrypted:json")
	}
}

func TestCodecRoundTripString(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)

	data, err := c.Encode(ctx, "hello world")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Contains(data, []byte("hello world")) {
		t.Error("encrypted data contains plaintext")
	}

	var got string
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "hello world" {
		t.Errorf("Decode: got %q, want %q", got, "hello world")
	}
}

func TestCodecRoundTripStruct(t *testing.T) {
	ctx := context.Background()
	type Config struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	c := testCodec(t)
	original := Config{Host: "localhost", Port: 8080}
	data, err := c.Encode(ctx, original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got Config
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != original {
		t.Errorf("Decode: got %+v, want %+v", got, original)
	}
}

func TestCodecRoundTripMap(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	original := map[string]any{"key": "value", "num": float64(42)}
	data, err := c.Encode(ctx, original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got map[string]any
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got["key"] != original["key"] || got["num"] != original["num"] {
		t.Errorf("Decode: got %v, want %v", got, original)
	}
}

func TestCodecRoundTripInt(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	data, err := c.Encode(ctx, 42)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got int
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestCodecKeyRotation(t *testing.T) {
	ctx := context.Background()
	oldKey := makeKey(32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}

	oldP := mustNewProvider(t, oldKey, "key-v1")
	oldCodec, err := NewCodec(jsoncodec.New(), oldP)
	if err != nil {
		t.Fatal(err)
	}
	data, err := oldCodec.Encode(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}

	// KeyRingProvider with new key as current and old key for decryption.
	newP, err := NewKeyRingProvider(newKey, "key-v2", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = newP.Close() })
	if err := newP.AddKey(oldKey, "key-v1", 1); err != nil {
		t.Fatal(err)
	}
	newCodec, err := NewCodec(jsoncodec.New(), newP)
	if err != nil {
		t.Fatal(err)
	}

	var got string
	if err := newCodec.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode rotated: %v", err)
	}
	if got != "secret" {
		t.Errorf("got %q, want secret", got)
	}
}

func TestCodecWrongKey(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	data, err := c.Encode(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0xFF
	}
	wrongCodec, err := NewCodec(jsoncodec.New(), mustNewProvider(t, wrong, "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := wrongCodec.Decode(ctx, data, &got); !IsDecryptionFailed(err) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCodecTamperedData(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	data, err := c.Encode(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xFF
	var got string
	if err := c.Decode(ctx, data, &got); !IsDecryptionFailed(err) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCodecInvalidFormat(t *testing.T) {
	c := testCodec(t)
	var got string
	err := c.Decode(context.Background(), []byte("not encrypted"), &got)
	if !IsInvalidFormat(err) && !IsDecryptionFailed(err) {
		t.Errorf("expected format or decryption error, got %v", err)
	}
}

func TestCodecEmptyData(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	data, err := c.Encode(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestCodecLargePayload(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	large := make([]byte, 1<<20)
	for i := range large {
		large[i] = byte(i % 256)
	}
	data, err := c.Encode(ctx, large)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, large) {
		t.Error("large payload round-trip mismatch")
	}
}

func TestCodecConcurrent(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			data, err := c.Encode(ctx, n)
			if err != nil {
				t.Errorf("Encode(%d): %v", n, err)
				return
			}
			var got int
			if err := c.Decode(ctx, data, &got); err != nil {
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
	ctx := context.Background()
	c := testCodec(t)
	d1, err := c.Encode(ctx, "same input")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := c.Encode(ctx, "same input")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d1, d2) {
		t.Error("two encryptions of same input produced identical output")
	}
}

func TestCodecIntegrationWithMemoryStore(t *testing.T) {
	ctx := context.Background()
	encJSON, err := NewCodec(jsoncodec.New(), mustNewProvider(t, makeKey(32), "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.Register(encJSON); err != nil {
		t.Fatal(err)
	}

	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)

	original := "my-secret-api-key"
	encoded, err := encJSON.Encode(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	plainJSON, _ := json.Marshal(original)
	if bytes.Contains(encoded, plainJSON) {
		t.Error("encoded data contains plaintext JSON")
	}

	val, err := config.NewValueFromBytes(ctx, encoded, encJSON.Name())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set(ctx, config.DefaultNamespace, "secrets/api-key", val); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, config.DefaultNamespace, "secrets/api-key")
	if err != nil {
		t.Fatal(err)
	}
	if got.Codec() != "encrypted:json" {
		t.Errorf("Codec(): got %q, want %q", got.Codec(), "encrypted:json")
	}
	var result string
	if err := got.Unmarshal(ctx, &result); err != nil {
		t.Fatal(err)
	}
	if result != original {
		t.Errorf("got %q, want %q", result, original)
	}
}

func TestNewCodecReturnsErrorOnNilInner(t *testing.T) {
	if _, err := NewCodec(nil, mustNewProvider(t, makeKey(32), "k")); err == nil {
		t.Error("expected error for nil inner codec")
	}
}

func TestNewCodecReturnsErrorOnNilProvider(t *testing.T) {
	if _, err := NewCodec(jsoncodec.New(), nil); err == nil {
		t.Error("expected error for nil provider")
	}
}

// failingProvider returns errors from Encrypt/Decrypt; used to verify Codec
// error wrapping.
type failingProvider struct{}

func (p *failingProvider) Name() string                    { return "failing" }
func (p *failingProvider) Connect(_ context.Context) error { return nil }
func (p *failingProvider) Encrypt(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("encrypt unavailable")
}
func (p *failingProvider) Decrypt(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("decrypt unavailable")
}
func (p *failingProvider) HealthCheck(_ context.Context) error {
	return errors.New("provider unavailable")
}
func (p *failingProvider) Close() error { return nil }

func TestCodecEncryptFailureWrapped(t *testing.T) {
	c, err := NewCodec(jsoncodec.New(), &failingProvider{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Encode(context.Background(), "test")
	if err == nil || !strings.Contains(err.Error(), "encrypt failed") {
		t.Errorf("expected wrapped encrypt-failure, got %v", err)
	}
}

func TestCodecDecryptFailureWrapped(t *testing.T) {
	c, err := NewCodec(jsoncodec.New(), &failingProvider{})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Decode(context.Background(), []byte("anything"), nil)
	if err == nil || !strings.Contains(err.Error(), "decrypt failed") {
		t.Errorf("expected wrapped decrypt-failure, got %v", err)
	}
}

func TestCodecDecodeInnerCodecFailure(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	data, err := c.Encode(ctx, "hello")
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ X chan int }
	err = c.Decode(ctx, data, &got)
	if err == nil || !strings.Contains(err.Error(), "inner decode failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCodecEncodeInnerCodecFailure(t *testing.T) {
	c := testCodec(t)
	_, err := c.Encode(context.Background(), make(chan int))
	if err == nil || !strings.Contains(err.Error(), "inner encode failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTransformReverseRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := testCodec(t)
	plaintext := []byte("hello transform")
	ct, err := c.Transform(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Error("Transform did not change the data")
	}
	got, err := c.Reverse(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Reverse: got %q, want %q", got, plaintext)
	}
}

func TestChainWithCryptoTransformer(t *testing.T) {
	ctx := context.Background()
	chained := codec.NewChain(jsoncodec.New(), testCodec(t))
	if chained.Name() != "encrypted:json:json" {
		t.Errorf("Name() = %q, want %q", chained.Name(), "encrypted:json:json")
	}

	type Payload struct {
		Secret string `json:"secret"`
	}
	original := Payload{Secret: "my-api-key"}
	data, err := chained.Encode(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("my-api-key")) {
		t.Error("chain-encoded data contains plaintext")
	}
	var got Payload
	if err := chained.Decode(ctx, data, &got); err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Errorf("got %+v, want %+v", got, original)
	}
}
