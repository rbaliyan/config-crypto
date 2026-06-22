package crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/rbaliyan/config"
	"github.com/rbaliyan/config/codec"
	jsoncodec "github.com/rbaliyan/config/codec/json"
)

// Smoke tests are fast liveness checks for the must-work happy paths. They are
// intentionally minimal — edge cases live in the dedicated *_test.go files.
// Run the subset with: go test -run '^TestSmoke|^Example' ./...

// TestSmoke_CoreRoundTrip verifies the headline path: encrypt then decrypt a
// value through the encrypting codec.
func TestSmoke_CoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := mustNewProvider(t, makeKey(32), "smoke-key")
	c, err := NewCodec(jsoncodec.New(), p)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	data, err := c.Encode(ctx, "hello-smoke")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got string
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "hello-smoke" {
		t.Errorf("got %q, want %q", got, "hello-smoke")
	}
}

// TestSmoke_CodecRegistration verifies a codec registers and resolves by name.
func TestSmoke_CodecRegistration(t *testing.T) {
	p := mustNewProvider(t, makeKey(32), "smoke-reg-key")
	// Use a distinct prefix so the registration name does not collide with
	// other tests that register "encrypted:json".
	c, err := NewCodec(jsoncodec.New(), p, WithCodecPrefix("smoke"))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if err := codec.Register(c); err != nil {
		t.Fatalf("Register: %v", err)
	}
	resolved := codec.Get(c.Name())
	if resolved == nil {
		t.Fatalf("codec %q did not resolve after registration", c.Name())
	}
	if resolved.Name() != c.Name() {
		t.Errorf("resolved %q, want %q", resolved.Name(), c.Name())
	}
}

// TestSmoke_EncryptedCache verifies a put/get round-trip through EncryptedCache.
func TestSmoke_EncryptedCache(t *testing.T) {
	ctx := context.Background()
	ec, err := NewEncryptedCache(newMapCache(), mustNewProvider(t, makeKey(32), "smoke-cache"))
	if err != nil {
		t.Fatalf("NewEncryptedCache: %v", err)
	}
	if err := ec.Set(ctx, "ns", "k", config.NewValue("cached")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := ec.Get(ctx, "ns", "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	s, _ := got.String()
	if s != "cached" {
		t.Errorf("got %q, want %q", s, "cached")
	}
}

// TestSmoke_SelectorCodecNamespaceIsolation verifies per-namespace routing and
// that one namespace cannot decrypt another's ciphertext.
func TestSmoke_SelectorCodecNamespaceIsolation(t *testing.T) {
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns1", mustNewProvider(t, makeKey(32), "smoke-ns1")),
		WithNamespaceProvider("ns2", mustNewProvider(t, makeKey(32), "smoke-ns2")),
	)
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}
	sc, err := NewSelectorCodec(sel, jsoncodec.New())
	if err != nil {
		t.Fatalf("NewSelectorCodec: %v", err)
	}

	ctx1 := WithNamespace(context.Background(), "ns1")
	data, err := sc.Encode(ctx1, "secret")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// ns1 round-trips.
	var out string
	if err := sc.Decode(ctx1, data, &out); err != nil || out != "secret" {
		t.Fatalf("ns1 round-trip: out=%q err=%v", out, err)
	}
	// ns2 cannot decrypt ns1's ciphertext. ns2's provider holds a different
	// key ID than the one recorded in ns1's ciphertext header, so the key
	// lookup misses and the failure surfaces as ErrKeyNotFound (wrapped inside
	// the decrypt error). Assert the specific sentinel rather than any error so
	// the negative path stays meaningful.
	ctx2 := WithNamespace(context.Background(), "ns2")
	if err := sc.Decode(ctx2, data, &out); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("cross-namespace decode: got %v, want ErrKeyNotFound", err)
	}
}

// TestSmoke_RotationRoundTrip verifies a value encrypted under one key still
// decrypts after the ring rotates to a new current key.
func TestSmoke_RotationRoundTrip(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)
	c, err := NewCodec(jsoncodec.New(), ring)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	data, err := c.Encode(ctx, "rotate-me")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	v2 := make([]byte, 32)
	for i := range v2 {
		v2[i] = byte(i + 100)
	}
	if err := ring.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := ring.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	// Old ciphertext still decrypts via the ring (old key retained).
	var got string
	if err := c.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode after rotation: %v", err)
	}
	if got != "rotate-me" {
		t.Errorf("got %q, want %q", got, "rotate-me")
	}
}
