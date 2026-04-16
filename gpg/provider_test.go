package gpg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte
	failOn string
}

func (m *mockClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := string(ciphertext)
	if key == m.failOn {
		return nil, fmt.Errorf("gpg: decryption failed")
	}
	plaintext, ok := m.keys[key]
	if !ok {
		return nil, fmt.Errorf("gpg: no key for ciphertext")
	}
	return plaintext, nil
}

func makeKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

var _ Client = (*mockClient)(nil)

func TestNew_RoundTrip(t *testing.T) {
	ctx := context.Background()
	client := &mockClient{keys: map[string][]byte{"enc:k1": makeKey(1)}}
	provider, err := New(ctx, client, WithEncryptedKey([]byte("enc:k1"), "key-1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer provider.Close()
	ct, err := provider.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Decrypt(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestNew_Rotation(t *testing.T) {
	ctx := context.Background()
	v1 := makeKey(1)
	v2 := makeKey(2)
	v1Copy := append([]byte(nil), v1...)
	v2Copy := append([]byte(nil), v2...)
	client := &mockClient{keys: map[string][]byte{"enc:v2": v2, "enc:v1": v1}}

	provider, err := New(ctx, client,
		WithEncryptedKey([]byte("enc:v2"), "key-v2"),
		WithEncryptedKey([]byte("enc:v1"), "key-v1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	ct, err := provider.Encrypt(ctx, []byte("rotated"))
	if err != nil {
		t.Fatal(err)
	}
	v2Only, err := crypto.NewProvider(v2Copy, "key-v2")
	if err != nil {
		t.Fatal(err)
	}
	defer v2Only.Close()
	if got, err := v2Only.Decrypt(ctx, ct); err != nil {
		t.Errorf("v2-only: %v", err)
	} else if string(got) != "rotated" {
		t.Errorf("got %q", got)
	}

	v1Only, err := crypto.NewProvider(v1Copy, "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	defer v1Only.Close()
	v1ct, err := v1Only.Encrypt(ctx, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Decrypt(ctx, v1ct); err != nil {
		t.Errorf("decrypt v1 via rotating: %v", err)
	}
}

func TestNew_NilClient(t *testing.T) {
	if _, err := New(context.Background(), nil, WithEncryptedKey([]byte("enc:k1"), "key-1")); err == nil {
		t.Error("expected error for nil client")
	}
}

func TestNew_NoKeys(t *testing.T) {
	if _, err := New(context.Background(), &mockClient{}); err == nil {
		t.Error("expected error")
	}
}

func TestNew_DecryptFailure(t *testing.T) {
	client := &mockClient{failOn: "enc:k1"}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc:k1"), "key-1")); err == nil {
		t.Error("expected error")
	}
}

func TestNew_DecryptFailureOnRotationKey(t *testing.T) {
	client := &mockClient{
		keys:   map[string][]byte{"enc:v2": makeKey(1)},
		failOn: "enc:v1",
	}
	if _, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:v2"), "key-v2"),
		WithEncryptedKey([]byte("enc:v1"), "key-v1"),
	); err == nil {
		t.Error("expected error when rotation key decrypt fails")
	}
}

func TestNew_InvalidKeySize(t *testing.T) {
	client := &mockClient{keys: map[string][]byte{"enc:short": {1, 2, 3}}}
	_, err := New(context.Background(), client, WithEncryptedKey([]byte("enc:short"), "key-1"))
	if err == nil || !strings.Contains(err.Error(), "3 bytes, want 32") {
		t.Errorf("expected key size error, got %v", err)
	}
}

func TestNew_RotationKeyInvalidSize(t *testing.T) {
	client := &mockClient{keys: map[string][]byte{
		"enc:v2": makeKey(1),
		"enc:v1": {1, 2, 3},
	}}
	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:v2"), "key-v2"),
		WithEncryptedKey([]byte("enc:v1"), "key-v1"),
	)
	if err == nil || !strings.Contains(err.Error(), "3 bytes, want 32") {
		t.Errorf("expected key size error, got %v", err)
	}
}

func TestNew_EmptyKeyID(t *testing.T) {
	client := &mockClient{keys: map[string][]byte{"enc": makeKey(1)}}
	_, err := New(context.Background(), client, WithEncryptedKey([]byte("enc"), ""))
	if err == nil || !crypto.IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestNew_DuplicateKeyID(t *testing.T) {
	client := &mockClient{keys: map[string][]byte{
		"enc:a": makeKey(1),
		"enc:b": makeKey(2),
	}}
	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:a"), "same-id"),
		WithEncryptedKey([]byte("enc:b"), "same-id"),
	)
	if err == nil || !crypto.IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestNew_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &mockClient{keys: map[string][]byte{"enc:k1": makeKey(1)}}
	_, err := New(ctx, client, WithEncryptedKey([]byte("enc:k1"), "key-1"))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestNew_DecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(1)
	client := &mockClient{keys: map[string][]byte{"enc:k1": plaintext}}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc:k1"), "key-1")); err != nil {
		t.Fatal(err)
	}
	for _, b := range plaintext {
		if b != 0 {
			t.Fatal("decrypted GPG key bytes were not zeroed after construction")
		}
	}
}
