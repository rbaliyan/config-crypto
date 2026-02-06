package vault

import (
	"context"
	"fmt"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte // "keyName:ciphertext" -> plaintext
	failOn string
}

func (m *mockClient) TransitDecrypt(ctx context.Context, keyName string, ciphertext string) ([]byte, error) {
	lookup := keyName + ":" + ciphertext
	if lookup == m.failOn {
		return nil, fmt.Errorf("vault: permission denied")
	}
	plaintext, ok := m.keys[lookup]
	if !ok {
		return nil, fmt.Errorf("vault: decryption failed")
	}
	return plaintext, nil
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
			"transit-key:vault:v1:abc123": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey("vault:v1:abc123", "key-1", "transit-key"),
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
	client := &mockClient{
		keys: map[string][]byte{
			"transit-key:vault:v2:new": makeKey(32),
			"transit-key:vault:v1:old": func() []byte {
				k := make([]byte, 32)
				for i := range k {
					k[i] = byte(i + 100)
				}
				return k
			}(),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey("vault:v2:new", "key-v2", "transit-key"),
		WithEncryptedKey("vault:v1:old", "key-v1", "transit-key"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	current, err := provider.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != "key-v2" {
		t.Errorf("CurrentKey().ID: got %q, want %q", current.ID, "key-v2")
	}

	old, err := provider.KeyByID("key-v1")
	if err != nil {
		t.Fatal(err)
	}
	if old.ID != "key-v1" {
		t.Errorf("KeyByID().ID: got %q, want %q", old.ID, "key-v1")
	}
}

func TestNewNoKeys(t *testing.T) {
	_, err := New(context.Background(), &mockClient{})
	if err == nil {
		t.Error("expected error for no keys")
	}
}

func TestNewDecryptFailure(t *testing.T) {
	client := &mockClient{failOn: "transit-key:vault:v1:abc123"}

	_, err := New(context.Background(), client,
		WithEncryptedKey("vault:v1:abc123", "key-1", "transit-key"),
	)
	if err == nil {
		t.Error("expected error for decrypt failure")
	}
}

func TestNewReturnsKeyProvider(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{
			"transit-key:vault:v1:data": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey("vault:v1:data", "key-1", "transit-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var _ crypto.KeyProvider = provider
}
