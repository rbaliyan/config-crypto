package azurekv

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte // ciphertext -> plaintext
	failOn string
}

func (m *mockClient) UnwrapKey(ctx context.Context, keyName string, keyVersion string, params azkeys.KeyOperationParameters, opts *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	ct := string(params.Value)
	if ct == m.failOn {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("keyvault: access denied")
	}
	plaintext, ok := m.keys[ct]
	if !ok {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("keyvault: invalid ciphertext")
	}
	return azkeys.UnwrapKeyResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: plaintext,
		},
	}, nil
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
			"wrapped-key-1": makeKey(32),
		},
	}

	provider, err := New(context.Background(), client,
		WithWrappedKey([]byte("wrapped-key-1"), "key-1", "my-key", "v1"),
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
			"wrapped-new": makeKey(32),
			"wrapped-old": func() []byte {
				k := make([]byte, 32)
				for i := range k {
					k[i] = byte(i + 100)
				}
				return k
			}(),
		},
	}

	provider, err := New(context.Background(), client,
		WithWrappedKey([]byte("wrapped-new"), "key-v2", "my-key", "v2"),
		WithWrappedKey([]byte("wrapped-old"), "key-v1", "my-key", "v1"),
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

func TestNewUnwrapFailure(t *testing.T) {
	client := &mockClient{failOn: "wrapped-key-1"}

	_, err := New(context.Background(), client,
		WithWrappedKey([]byte("wrapped-key-1"), "key-1", "my-key", "v1"),
	)
	if err == nil {
		t.Error("expected error for unwrap failure")
	}
}

func TestNewDecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(32)
	client := &mockClient{
		keys: map[string][]byte{
			"wrapped": plaintext,
		},
	}

	_, err := New(context.Background(), client,
		WithWrappedKey([]byte("wrapped"), "key-1", "my-key", "v1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

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

func TestNewWithAlgorithm(t *testing.T) {
	client := &mockClient{
		keys: map[string][]byte{"wrapped": makeKey(32)},
	}

	provider, err := New(context.Background(), client,
		WithWrappedKeyAlgorithm([]byte("wrapped"), "key-1", "my-key", "v1", azkeys.EncryptionAlgorithmRSAOAEP),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var _ crypto.KeyProvider = provider
}
