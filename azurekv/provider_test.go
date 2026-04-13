package azurekv

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte
	failOn string
}

func (m *mockClient) UnwrapKey(_ context.Context, _ string, _ string, params azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	ct := string(params.Value)
	if ct == m.failOn {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("keyvault: access denied")
	}
	plaintext, ok := m.keys[ct]
	if !ok {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("keyvault: invalid ciphertext")
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: plaintext}}, nil
}

func makeKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestNew_RoundTrip(t *testing.T) {
	ctx := context.Background()
	client := &mockClient{keys: map[string][]byte{"wrap-1": makeKey(1)}}
	provider, err := New(ctx, client, WithWrappedKey([]byte("wrap-1"), "key-1", "my-key", "v1"))
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
	client := &mockClient{keys: map[string][]byte{"wrap-v2": v2, "wrap-v1": v1}}

	provider, err := New(ctx, client,
		WithWrappedKey([]byte("wrap-v2"), "key-v2", "my-key", "v2"),
		WithWrappedKey([]byte("wrap-v1"), "key-v1", "my-key", "v1"),
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

func TestNew_NoKeys(t *testing.T) {
	if _, err := New(context.Background(), &mockClient{}); err == nil {
		t.Error("expected error")
	}
}

func TestNew_UnwrapFailure(t *testing.T) {
	client := &mockClient{failOn: "wrap-1"}
	if _, err := New(context.Background(), client, WithWrappedKey([]byte("wrap-1"), "key-1", "my-key", "v1")); err == nil {
		t.Error("expected error")
	}
}

func TestNew_DecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(1)
	client := &mockClient{keys: map[string][]byte{"wrap": plaintext}}
	if _, err := New(context.Background(), client, WithWrappedKey([]byte("wrap"), "key-1", "my-key", "v1")); err != nil {
		t.Fatal(err)
	}
	for _, b := range plaintext {
		if b != 0 {
			t.Fatal("unwrapped key bytes were not zeroed after construction")
		}
	}
}

func TestNew_WithAlgorithm(t *testing.T) {
	client := &mockClient{keys: map[string][]byte{"wrap": makeKey(1)}}
	provider, err := New(context.Background(), client,
		WithWrappedKeyAlgorithm([]byte("wrap"), "key-1", "my-key", "v1", azkeys.EncryptionAlgorithmRSAOAEP),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer provider.Close()
}
