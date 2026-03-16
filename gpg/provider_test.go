package gpg

import (
	"context"
	"errors"
	"fmt"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

// mockClient is a test double for Client that maps ciphertext to plaintext.
type mockClient struct {
	keys   map[string][]byte // string(ciphertext) -> plaintext
	failOn string            // if non-empty, fail when string(ciphertext) matches
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

func makeKey(size int) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// Compile-time interface check.
var _ Client = (*mockClient)(nil)

func TestNew(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"enc:key-1": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key, err := provider.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if key.ID != "key-1" {
		t.Errorf("CurrentKey().ID: got %q, want %q", key.ID, "key-1")
	}
}

func TestNewWithRotation(t *testing.T) {
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i + 100)
	}

	client := &mockClient{
		keys: map[string][]byte{
			"enc:key-2": makeKey(32),
			"enc:key-1": oldKey,
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-2"), "key-2"),
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	current, err := provider.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.ID != "key-2" {
		t.Errorf("CurrentKey().ID: got %q, want %q", current.ID, "key-2")
	}

	old, err := provider.KeyByID("key-1")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if old.ID != "key-1" {
		t.Errorf("KeyByID().ID: got %q, want %q", old.ID, "key-1")
	}
}

func TestNewNoKeys(t *testing.T) {
	_, err := New(context.Background(), &mockClient{})
	if err == nil {
		t.Error("expected error when no keys provided")
	}
}

func TestNewDecryptFailure(t *testing.T) {
	client := &mockClient{failOn: "enc:key-1"}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err == nil {
		t.Error("expected error on decrypt failure")
	}
}

func TestNewDecryptFailureOnRotationKey(t *testing.T) {
	// Failure on a rotation (non-current) key must also propagate.
	client := &mockClient{
		keys:   map[string][]byte{"enc:key-2": makeKey(32)},
		failOn: "enc:key-1",
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-2"), "key-2"),
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err == nil {
		t.Error("expected error when rotation key decrypt fails")
	}
}

func TestNewInvalidKeySize(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"enc:short": {1, 2, 3}, // 3 bytes — invalid for AES-256
		},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:short"), "key-1"),
	)
	if err == nil {
		t.Error("expected error for invalid key size")
	}
	if !crypto.IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestNewRotationKeyInvalidSize(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"enc:key-2": makeKey(32),
			"enc:key-1": {1, 2, 3}, // 3 bytes — invalid
		},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-2"), "key-2"),
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err == nil {
		t.Error("expected error when rotation key has invalid size")
	}
	if !crypto.IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestNewEmptyKeyID(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{"enc:key": makeKey(32)},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key"), ""),
	)
	if err == nil {
		t.Error("expected error for empty key ID")
	}
	if !crypto.IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestNewDuplicateKeyID(t *testing.T) {
	k1 := makeKey(32)
	k2 := make([]byte, 32)
	for i := range k2 {
		k2[i] = byte(i + 100)
	}

	client := &mockClient{
		keys: map[string][]byte{
			"enc:a": k1,
			"enc:b": k2,
		},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:a"), "same-id"),
		WithEncryptedKey([]byte("enc:b"), "same-id"),
	)
	if err == nil {
		t.Error("expected error for duplicate key ID")
	}
	if !crypto.IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestNewContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	client := &mockClient{
		keys: map[string][]byte{"enc:key-1": makeKey(32)},
	}

	_, err := New(ctx, client,
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got %v", err)
	}
}

func TestNewDecryptedKeyZeroed(t *testing.T) {
	// mockClient returns the same slice stored in the map, so clear() in New
	// will zero the backing array. This confirms key material is not retained.
	plaintext := makeKey(32)
	client := &mockClient{
		keys: map[string][]byte{"enc:key-1": plaintext},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i, b := range plaintext {
		if b != 0 {
			t.Errorf("decrypted key byte %d not zeroed after construction: got %d", i, b)
		}
	}
}

func TestNewRotationKeyZeroed(t *testing.T) {
	// Rotation key bytes must also be zeroed after construction.
	currentKey := makeKey(32)
	rotationKey := make([]byte, 32)
	for i := range rotationKey {
		rotationKey[i] = byte(i + 100)
	}

	client := &mockClient{
		keys: map[string][]byte{
			"enc:key-2": currentKey,
			"enc:key-1": rotationKey,
		},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-2"), "key-2"),
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i, b := range currentKey {
		if b != 0 {
			t.Errorf("current key byte %d not zeroed: got %d", i, b)
		}
	}
	for i, b := range rotationKey {
		if b != 0 {
			t.Errorf("rotation key byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestNewReturnsKeyProvider(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{"enc:key-1": makeKey(32)},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("enc:key-1"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var _ crypto.KeyProvider = provider
}
