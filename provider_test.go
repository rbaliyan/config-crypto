package crypto

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func TestNewProvider_RoundTrip(t *testing.T) {
	p := mustNewProvider(t, makeKey(32), "key-1")
	ctx := context.Background()

	for _, plaintext := range [][]byte{
		[]byte("hello"),
		[]byte(""),
		bytes.Repeat([]byte{0xff}, 1024),
	} {
		ct, err := p.Encrypt(ctx, plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		pt, err := p.Decrypt(ctx, ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Errorf("round-trip mismatch: got %q want %q", pt, plaintext)
		}
	}
}

func TestNewProvider_OldKeyDecryptsLegacy(t *testing.T) {
	old := makeKey(32)
	newer := append([]byte(nil), old...)
	for i := range newer {
		newer[i] ^= 0x55
	}

	// Encrypt with old.
	oldP := mustNewProvider(t, old, "v1")
	ct, err := oldP.Encrypt(context.Background(), []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}

	// KeyRingProvider has both keys; current is "v2".
	rp, err := NewKeyRingProvider(newer, "v2", 2)
	if err != nil {
		t.Fatalf("NewKeyRingProvider: %v", err)
	}
	t.Cleanup(func() { _ = rp.Close() })
	if err := rp.AddKey(old, "v1", 1); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	got, err := rp.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "legacy" {
		t.Errorf("got %q, want %q", got, "legacy")
	}
}

func TestNewProvider_Validation(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		id   string
	}{
		{"short key", makeKey(16), "id"},
		{"long key", makeKey(64), "id"},
		{"empty id", makeKey(32), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewProvider(c.key, c.id)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewProvider_HealthCheck(t *testing.T) {
	p := mustNewProvider(t, makeKey(32), "k")
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("healthy: %v", err)
	}
}

func TestNewProvider_HealthCheckAfterClose(t *testing.T) {
	p, err := NewProvider(makeKey(32), "k")
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	if err := p.HealthCheck(context.Background()); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("got %v, want ErrProviderClosed", err)
	}
}

func TestNewProvider_Close(t *testing.T) {
	p, err := NewProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("Encrypt after Close: got %v, want ErrProviderClosed", err)
	}
	if _, err := p.Decrypt(context.Background(), []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("Decrypt after Close: got %v, want ErrProviderClosed", err)
	}
	// Idempotent.
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestNewProvider_KeyBytesIsolated(t *testing.T) {
	original := makeKey(32)
	p := mustNewProvider(t, original, "k")

	// Zero the original; provider must keep working.
	clear(original)

	ctx := context.Background()
	ct, err := p.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := p.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestKeyRingProvider_AddSetRemoveCurrent(t *testing.T) {
	rp := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)
	ctx := context.Background()

	// Encrypt with v1.
	ctV1, err := rp.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Add v2 and switch.
	v2 := append([]byte(nil), makeKey(32)...)
	for i := range v2 {
		v2[i] ^= 0xaa
	}
	if err := rp.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := rp.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	// New encryption uses v2.
	ctV2, err := rp.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ctV1, ctV2) {
		t.Error("ciphertexts should differ across rotations")
	}

	// Both still decrypt.
	for _, ct := range [][]byte{ctV1, ctV2} {
		got, err := rp.Decrypt(ctx, ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(got) != "hello" {
			t.Errorf("got %q, want hello", got)
		}
	}

	// Cannot remove current key.
	if err := rp.RemoveKey("v2"); !errors.Is(err, ErrRemoveCurrentKey) {
		t.Errorf("RemoveKey current: got %v, want ErrRemoveCurrentKey", err)
	}

	// Remove v1; ctV1 then fails to decrypt.
	if err := rp.RemoveKey("v1"); err != nil {
		t.Fatalf("RemoveKey v1: %v", err)
	}
	if _, err := rp.Decrypt(ctx, ctV1); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Decrypt with removed key: got %v, want ErrKeyNotFound", err)
	}
}

func TestKeyRingProvider_SetCurrentKeyUnknown(t *testing.T) {
	rp := mustNewKeyRingProvider(t, makeKey(32), "v1", 0)
	if err := rp.SetCurrentKey("nonexistent"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestKeyRingProvider_AddKeyValidation(t *testing.T) {
	rp := mustNewKeyRingProvider(t, makeKey(32), "v1", 0)
	if err := rp.AddKey(makeKey(16), "bad", 0); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("AddKey bad size: got %v, want ErrInvalidKeySize", err)
	}
	if err := rp.AddKey(makeKey(32), "", 0); !errors.Is(err, ErrInvalidKeyID) {
		t.Errorf("AddKey empty id: got %v, want ErrInvalidKeyID", err)
	}
	// Duplicate ID must be rejected.
	if err := rp.AddKey(makeKey(32), "v1", 0); !errors.Is(err, ErrDuplicateKeyID) {
		t.Errorf("AddKey duplicate id: got %v, want ErrDuplicateKeyID", err)
	}
}

func TestProvider_NameAndConnect(t *testing.T) {
	ctx := context.Background()

	p := mustNewProvider(t, makeKey(32), "my-key")
	if got := p.Name(); got != "my-key" {
		t.Errorf("Name() = %q, want %q", got, "my-key")
	}
	if err := p.Connect(ctx); err != nil {
		t.Errorf("Connect: %v", err)
	}
}

func TestKeyRingProvider_NameAndConnect(t *testing.T) {
	ctx := context.Background()

	rp := mustNewKeyRingProvider(t, makeKey(32), "v1", 0)
	if got := rp.Name(); got != "v1" {
		t.Errorf("Name() = %q, want %q", got, "v1")
	}
	if err := rp.Connect(ctx); err != nil {
		t.Errorf("Connect: %v", err)
	}

	// Name reflects the current key after SetCurrentKey.
	v2 := makeKey(32)
	for i := range v2 {
		v2[i] ^= 0xaa
	}
	if err := rp.AddKey(v2, "v2", 2); err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCurrentKey("v2"); err != nil {
		t.Fatal(err)
	}
	if got := rp.Name(); got != "v2" {
		t.Errorf("Name() after SetCurrentKey = %q, want %q", got, "v2")
	}
}

func TestKeyRingProvider_Close(t *testing.T) {
	rp, err := NewKeyRingProvider(makeKey(32), "v1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, fn := range []func() error{
		func() error { _, e := rp.Encrypt(context.Background(), []byte("x")); return e },
		func() error { _, e := rp.Decrypt(context.Background(), []byte("x")); return e },
		func() error { return rp.AddKey(makeKey(32), "v2", 0) },
		func() error { return rp.SetCurrentKey("v1") },
		func() error { return rp.RemoveKey("v1") },
	} {
		if err := fn(); !errors.Is(err, ErrProviderClosed) {
			t.Errorf("expected ErrProviderClosed, got %v", err)
		}
	}
}

func TestKeyRingProvider_Concurrent(t *testing.T) {
	rp := mustNewKeyRingProvider(t, makeKey(32), "v1", 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := rp.Encrypt(ctx, []byte("x")); err != nil {
				t.Errorf("Encrypt: %v", err)
			}
		}()
		go func(n int) {
			defer wg.Done()
			id := "v" + string(rune('A'+n%26))
			_ = rp.AddKey(makeKey(32), id, 0) // may already exist
		}(i)
	}
	wg.Wait()
}

func TestKeyRingProvider_NeedsReencryption(t *testing.T) {
	ctx := context.Background()

	v1 := makeKey(32)
	v2 := makeKey(32)
	for i := range v2 {
		v2[i] ^= 0xaa
	}

	// Build a ring with v1 (rank 1) as old and v2 (rank 2) as current.
	rp, err := NewKeyRingProvider(v2, "v2", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rp.Close() })
	if err := rp.AddKey(v1, "v1", 1); err != nil {
		t.Fatal(err)
	}

	// Helper: encrypt with a standalone single-key provider.
	encryptWith := func(t *testing.T, keyBytes []byte, id string) []byte {
		t.Helper()
		p, err := NewProvider(keyBytes, id)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		ct, err := p.Encrypt(ctx, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}

	t.Run("current key returns false", func(t *testing.T) {
		ct := encryptWith(t, v2, "v2")
		got, err := rp.NeedsReencryption(ct)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("ciphertext from current key should not need re-encryption")
		}
	})

	t.Run("older rank returns true", func(t *testing.T) {
		ct := encryptWith(t, v1, "v1")
		got, err := rp.NeedsReencryption(ct)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got {
			t.Error("ciphertext from older key should need re-encryption")
		}
	})

	t.Run("higher rank returns false", func(t *testing.T) {
		// Simulate a future key with a higher rank than current.
		v3 := makeKey(32)
		for i := range v3 {
			v3[i] ^= 0x55
		}
		ct := encryptWith(t, v3, "v3")
		// v3 is not in the ring, so ordering is unknown — should return false.
		got, err := rp.NeedsReencryption(ct)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("ciphertext from unknown key should return false, not true")
		}
	})

	t.Run("unknown key ID returns false", func(t *testing.T) {
		vUnknown := makeKey(32)
		for i := range vUnknown {
			vUnknown[i] ^= 0x33
		}
		ct := encryptWith(t, vUnknown, "unknown-id")
		got, err := rp.NeedsReencryption(ct)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("unknown key ID should return false, not true")
		}
	})

	t.Run("unparseable ciphertext returns error", func(t *testing.T) {
		_, err := rp.NeedsReencryption([]byte("not valid ciphertext"))
		if err == nil {
			t.Error("expected error for invalid ciphertext")
		}
	})

	t.Run("equal rank returns false", func(t *testing.T) {
		// Add a key with same rank as current (2); it is older by ID but not by rank.
		v2b := makeKey(32)
		for i := range v2b {
			v2b[i] ^= 0xbb
		}
		rp2, err := NewKeyRingProvider(v2, "v2", 2)
		if err != nil {
			t.Fatal(err)
		}
		defer rp2.Close()
		if err := rp2.AddKey(v2b, "v2b", 2); err != nil {
			t.Fatal(err)
		}
		ct := encryptWith(t, v2b, "v2b")
		got, err := rp2.NeedsReencryption(ct)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got {
			t.Error("equal rank should return false")
		}
	})
}

func TestKeyRingProvider_NeedsReencryption_Concurrent(t *testing.T) {
	ctx := context.Background()

	v1 := makeKey(32)
	v2 := makeKey(32)
	for i := range v2 {
		v2[i] ^= 0xaa
	}

	rp, err := NewKeyRingProvider(v2, "v2", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rp.Close() })
	if err := rp.AddKey(v1, "v1", 1); err != nil {
		t.Fatal(err)
	}

	oldP, err := NewProvider(v1, "v1")
	if err != nil {
		t.Fatal(err)
	}
	defer oldP.Close()
	ct, err := oldP.Encrypt(ctx, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := rp.NeedsReencryption(ct)
			if err != nil {
				t.Errorf("NeedsReencryption: %v", err)
			}
			if !got {
				t.Error("expected true for older key")
			}
		}()
	}
	wg.Wait()
}
