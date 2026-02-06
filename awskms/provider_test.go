package awskms

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	crypto "github.com/rbaliyan/config-crypto"
)

// mockClient implements Client for testing.
type mockClient struct {
	keys   map[string][]byte // ciphertext -> plaintext
	failOn string            // ciphertext string to fail on
}

func (m *mockClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	ct := string(params.CiphertextBlob)
	if ct == m.failOn {
		return nil, fmt.Errorf("kms: access denied")
	}
	plaintext, ok := m.keys[ct]
	if !ok {
		return nil, fmt.Errorf("kms: invalid ciphertext")
	}
	return &kms.DecryptOutput{Plaintext: plaintext}, nil
}

func makeKey(size int) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestNew(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"encrypted-key-1": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted-key-1"), "key-1"),
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
	oldKey := makeKey(32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}

	client := &mockClient{
		keys: map[string][]byte{
			"encrypted-new": newKey,
			"encrypted-old": oldKey,
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted-new"), "key-v2"),
		WithEncryptedKey([]byte("encrypted-old"), "key-v1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Current key should be the first one
	current, err := provider.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.ID != "key-v2" {
		t.Errorf("CurrentKey().ID: got %q, want %q", current.ID, "key-v2")
	}

	// Old key should be accessible
	old, err := provider.KeyByID("key-v1")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if old.ID != "key-v1" {
		t.Errorf("KeyByID().ID: got %q, want %q", old.ID, "key-v1")
	}
}

func TestNewNoKeys(t *testing.T) {
	client := &mockClient{}

	_, err := New(context.Background(), client)
	if err == nil {
		t.Error("expected error for no keys")
	}
}

func TestNewDecryptFailure(t *testing.T) {
	client := &mockClient{
		failOn: "encrypted-key-1",
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted-key-1"), "key-1"),
	)
	if err == nil {
		t.Error("expected error for decrypt failure")
	}
}

func TestNewWithKMSKeyID(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"encrypted-key-1": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKeyForKMSKey([]byte("encrypted-key-1"), "key-1", "arn:aws:kms:us-east-1:123:key/abc"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key, err := provider.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if key.ID != "key-1" {
		t.Errorf("got %q, want %q", key.ID, "key-1")
	}
}

func TestNewDecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(32)
	client := &mockClient{
		keys: map[string][]byte{
			"encrypted": plaintext,
		},
	}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The provider copies the bytes, so the original plaintext from KMS should be zeroed
	// Note: the mock returns a direct reference, so we can verify zeroing
	allZero := true
	for _, b := range plaintext {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("decrypted key material was not zeroed after construction")
	}
}

func TestNewReturnsKeyProvider(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"encrypted": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted"), "key-1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify it satisfies KeyProvider interface
	var _ crypto.KeyProvider = provider
}
