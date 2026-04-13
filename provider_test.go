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

	// New provider has both keys; current is "v2".
	p, err := NewProvider(newer, "v2", WithOldKey(old, "v1"))
	if err != nil {
		t.Fatalf("NewProvider with old key: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	got, err := p.Decrypt(context.Background(), ct)
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
		opts []Option
	}{
		{"short key", makeKey(16), "id", nil},
		{"long key", makeKey(64), "id", nil},
		{"empty id", makeKey(32), "", nil},
		{"old key bad size", makeKey(32), "id", []Option{WithOldKey(makeKey(16), "old")}},
		{"old key empty id", makeKey(32), "id", []Option{WithOldKey(makeKey(32), "")}},
		{"duplicate id", makeKey(32), "k", []Option{WithOldKey(makeKey(32), "k")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewProvider(c.key, c.id, c.opts...)
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

func TestRotatingProvider_AddSetRemoveCurrent(t *testing.T) {
	rp := mustNewRotatingProvider(t, makeKey(32), "v1")
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
	if err := rp.AddKey(v2, "v2"); err != nil {
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

func TestRotatingProvider_SetCurrentKeyUnknown(t *testing.T) {
	rp := mustNewRotatingProvider(t, makeKey(32), "v1")
	if err := rp.SetCurrentKey("nonexistent"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestRotatingProvider_AddKeyValidation(t *testing.T) {
	rp := mustNewRotatingProvider(t, makeKey(32), "v1")
	if err := rp.AddKey(makeKey(16), "bad"); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("AddKey bad size: got %v, want ErrInvalidKeySize", err)
	}
	if err := rp.AddKey(makeKey(32), ""); !errors.Is(err, ErrInvalidKeyID) {
		t.Errorf("AddKey empty id: got %v, want ErrInvalidKeyID", err)
	}
}

func TestRotatingProvider_Close(t *testing.T) {
	rp, err := NewRotatingProvider(makeKey(32), "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, fn := range []func() error{
		func() error { _, e := rp.Encrypt(context.Background(), []byte("x")); return e },
		func() error { _, e := rp.Decrypt(context.Background(), []byte("x")); return e },
		func() error { return rp.AddKey(makeKey(32), "v2") },
		func() error { return rp.SetCurrentKey("v1") },
		func() error { return rp.RemoveKey("v1") },
	} {
		if err := fn(); !errors.Is(err, ErrProviderClosed) {
			t.Errorf("expected ErrProviderClosed, got %v", err)
		}
	}
}

func TestRotatingProvider_Concurrent(t *testing.T) {
	rp := mustNewRotatingProvider(t, makeKey(32), "v1")
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
			_ = rp.AddKey(makeKey(32), id) // may already exist
		}(i)
	}
	wg.Wait()
}
