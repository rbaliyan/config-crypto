package gcpkms

import (
	"context"
	"fmt"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

type mockClient struct {
	keys   map[string][]byte
	failOn string
}

func (m *mockClient) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	ct := string(ciphertext)
	if ct == m.failOn {
		return nil, fmt.Errorf("kms: permission denied")
	}
	plaintext, ok := m.keys[ct]
	if !ok {
		return nil, fmt.Errorf("kms: invalid ciphertext")
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

const resourceName = "projects/p/locations/l/keyRings/r/cryptoKeys/k"

func TestNew_RoundTrip(t *testing.T) {
	ctx := context.Background()
	client := &mockClient{keys: map[string][]byte{"enc-1": makeKey(1)}}
	provider, err := New(ctx, client, WithEncryptedKey([]byte("enc-1"), "key-1", resourceName))
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
	client := &mockClient{keys: map[string][]byte{"enc-v2": v2, "enc-v1": v1}}

	provider, err := New(ctx, client,
		WithEncryptedKey([]byte("enc-v2"), "key-v2", resourceName),
		WithEncryptedKey([]byte("enc-v1"), "key-v1", resourceName),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	// Current key is v2.
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
		t.Errorf("v2-only decrypt: %v", err)
	} else if string(got) != "rotated" {
		t.Errorf("got %q", got)
	}

	// v1 ciphertext decrypts via the rotating provider.
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

func TestNew_NilClient(t *testing.T) {
	if _, err := New(context.Background(), nil, WithEncryptedKey([]byte("enc-1"), "key-1", resourceName)); err == nil {
		t.Error("expected error for nil client")
	}
}

func TestNew_DecryptFailure(t *testing.T) {
	client := &mockClient{failOn: "enc-1"}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc-1"), "key-1", resourceName)); err == nil {
		t.Error("expected error")
	}
}

func TestNew_DecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(1)
	client := &mockClient{keys: map[string][]byte{"enc": plaintext}}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc"), "key-1", resourceName)); err != nil {
		t.Fatal(err)
	}
	for _, b := range plaintext {
		if b != 0 {
			t.Fatal("decrypted KMS key bytes were not zeroed after construction")
		}
	}
}
