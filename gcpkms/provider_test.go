package gcpkms

import (
	"context"
	"fmt"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte // ciphertext -> plaintext
	failOn string
}

func (m *mockClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	ct := string(req.Ciphertext)
	if ct == m.failOn {
		return nil, fmt.Errorf("kms: permission denied")
	}
	plaintext, ok := m.keys[ct]
	if !ok {
		return nil, fmt.Errorf("kms: invalid ciphertext")
	}
	return &kmspb.DecryptResponse{Plaintext: plaintext}, nil
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
		WithEncryptedKey([]byte("encrypted-key-1"), "key-1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
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
			"encrypted-new": makeKey(32),
			"encrypted-old": func() []byte {
				k := make([]byte, 32)
				for i := range k {
					k[i] = byte(i + 100)
				}
				return k
			}(),
		},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted-new"), "key-v2", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
		WithEncryptedKey([]byte("encrypted-old"), "key-v1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
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
	client := &mockClient{failOn: "encrypted-key-1"}

	_, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted-key-1"), "key-1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
	)
	if err == nil {
		t.Error("expected error for decrypt failure")
	}
}

func TestNewReturnsKeyProvider(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{"encrypted": makeKey(32)},
	}

	provider, err := New(context.Background(), client,
		WithEncryptedKey([]byte("encrypted"), "key-1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var _ crypto.KeyProvider = provider
}
