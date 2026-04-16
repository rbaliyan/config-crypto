package awskms

import (
	"context"
	"fmt"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

// mockClient implements Client for testing.
type mockClient struct {
	keys      map[string][]byte // ciphertext -> plaintext
	failOn    string            // ciphertext to fail on
	wantKeyID string            // if non-empty, assert keyID matches
}

func (m *mockClient) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if m.wantKeyID != "" && keyID != m.wantKeyID {
		return nil, fmt.Errorf("kms: got keyID %q, want %q", keyID, m.wantKeyID)
	}
	ct := string(ciphertext)
	if ct == m.failOn {
		return nil, fmt.Errorf("kms: access denied")
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

func TestNew_RoundTrip(t *testing.T) {
	ctx := context.Background()
	client := &mockClient{keys: map[string][]byte{"enc-1": makeKey(1)}}
	provider, err := New(ctx, client, WithEncryptedKey([]byte("enc-1"), "key-1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer provider.Close()

	ct, err := provider.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := provider.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestNew_Rotation(t *testing.T) {
	ctx := context.Background()
	v1 := makeKey(1)
	v2 := makeKey(2)
	// Copy before passing to mock — awskms zeros the slices the mock returns.
	v1Copy := append([]byte(nil), v1...)
	v2Copy := append([]byte(nil), v2...)
	client := &mockClient{keys: map[string][]byte{
		"enc-v2": v2,
		"enc-v1": v1,
	}}

	provider, err := New(ctx, client,
		WithEncryptedKey([]byte("enc-v2"), "key-v2"),
		WithEncryptedKey([]byte("enc-v1"), "key-v1"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer provider.Close()

	// Current is key-v2: encrypt → decrypts via standalone key-v2 provider.
	ct, err := provider.Encrypt(ctx, []byte("rotated"))
	if err != nil {
		t.Fatal(err)
	}
	v2Only, err := crypto.NewProvider(v2Copy, "key-v2")
	if err != nil {
		t.Fatal(err)
	}
	defer v2Only.Close()
	got, err := v2Only.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("decrypt with v2-only: %v", err)
	}
	if string(got) != "rotated" {
		t.Errorf("got %q", got)
	}

	// Old ciphertext (encrypted with v1 key directly) decrypts via the rotating provider.
	v1Only, err := crypto.NewProvider(v1Copy, "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	defer v1Only.Close()
	v1Cipher, err := v1Only.Encrypt(ctx, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := provider.Decrypt(ctx, v1Cipher); err != nil {
		t.Errorf("decrypt v1 via rotating: %v", err)
	} else if string(got) != "legacy" {
		t.Errorf("got %q", got)
	}
}

func TestNew_NoKeys(t *testing.T) {
	if _, err := New(context.Background(), &mockClient{}); err == nil {
		t.Error("expected error for no keys")
	}
}

func TestNew_DecryptFailure(t *testing.T) {
	client := &mockClient{failOn: "enc-1"}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc-1"), "key-1")); err == nil {
		t.Error("expected error for decrypt failure")
	}
}

func TestNew_WithKMSKeyID(t *testing.T) {
	ctx := context.Background()
	const arn = "arn:aws:kms:us-east-1:123:key/abc"
	client := &mockClient{
		keys:      map[string][]byte{"enc-1": makeKey(1)},
		wantKeyID: arn,
	}
	provider, err := New(ctx, client,
		WithEncryptedKeyForKMSKey([]byte("enc-1"), "key-1", arn),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer provider.Close()
	if _, err := provider.Encrypt(ctx, []byte("x")); err != nil {
		t.Errorf("Encrypt: %v", err)
	}
}

func TestNew_NilClient(t *testing.T) {
	if _, err := New(context.Background(), nil, WithEncryptedKey([]byte("enc-1"), "key-1")); err == nil {
		t.Error("expected error for nil client")
	}
}

func TestNew_DecryptedKeyZeroed(t *testing.T) {
	plaintext := makeKey(1)
	client := &mockClient{keys: map[string][]byte{"enc": plaintext}}
	if _, err := New(context.Background(), client, WithEncryptedKey([]byte("enc"), "key-1")); err != nil {
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
		t.Error("decrypted KMS key bytes were not zeroed after construction")
	}
}
