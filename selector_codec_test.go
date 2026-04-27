package crypto

import (
	"context"
	"testing"

	jsoncodec "github.com/rbaliyan/config/codec/json"
)

func mustNewSelectorCodec(t *testing.T, selector *NamespaceSelector, opts ...CodecOption) *SelectorCodec {
	t.Helper()
	sc, err := NewSelectorCodec(selector, jsoncodec.New(), opts...)
	if err != nil {
		t.Fatalf("NewSelectorCodec: %v", err)
	}
	return sc
}

func mustNewSelector(t *testing.T) (*NamespaceSelector, Provider, Provider) {
	t.Helper()
	p1 := mustNewProvider(t, makeKey(32), "key-ns1")
	p2 := mustNewProvider(t, makeKey(32), "key-ns2")
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns1", p1),
		WithNamespaceProvider("ns2", p2),
	)
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}
	return sel, p1, p2
}

// TestSelectorCodecName verifies the codec is named "encrypted:json".
func TestSelectorCodecName(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	sc := mustNewSelectorCodec(t, sel)
	if sc.Name() != "encrypted:json" {
		t.Errorf("Name() = %q, want %q", sc.Name(), "encrypted:json")
	}
}

// TestSelectorCodecWithClientCodec verifies the "client:" prefix option works.
func TestSelectorCodecWithClientCodec(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	sc := mustNewSelectorCodec(t, sel, WithClientCodec())
	if sc.Name() != "client:encrypted:json" {
		t.Errorf("Name() = %q, want %q", sc.Name(), "client:encrypted:json")
	}
}

// TestSelectorCodecRoundTrip verifies encode→decode round-trip for two namespaces
// using distinct providers.
func TestSelectorCodecRoundTrip(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	sc := mustNewSelectorCodec(t, sel)

	type payload struct{ Secret string }

	for _, ns := range []string{"ns1", "ns2"} {
		ns := ns
		t.Run(ns, func(t *testing.T) {
			ctx := WithNamespace(context.Background(), ns)
			want := payload{Secret: "top-secret-" + ns}

			data, err := sc.Encode(ctx, want)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			var got payload
			if err := sc.Decode(ctx, data, &got); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

// TestSelectorCodecNamespacesAreIsolated verifies that ciphertext from one
// namespace cannot be decrypted by another namespace's provider.
func TestSelectorCodecNamespacesAreIsolated(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	sc := mustNewSelectorCodec(t, sel)

	ctx1 := WithNamespace(context.Background(), "ns1")
	data, err := sc.Encode(ctx1, "secret")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decoding with ns2's provider must fail — different KEK.
	ctx2 := WithNamespace(context.Background(), "ns2")
	var out string
	if err := sc.Decode(ctx2, data, &out); err == nil {
		t.Error("Decode with wrong namespace should fail, got nil error")
	}
}

// TestSelectorCodecFallback verifies that an unregistered namespace falls back
// to the fallback provider.
func TestSelectorCodecFallback(t *testing.T) {
	fallback := mustNewProvider(t, makeKey(32), "fallback-key")
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns1", mustNewProvider(t, makeKey(32), "ns1-key")),
		WithFallbackProvider(fallback),
	)
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}

	sc := mustNewSelectorCodec(t, sel)
	ctx := WithNamespace(context.Background(), "unknown-ns")

	data, err := sc.Encode(ctx, 42)
	if err != nil {
		t.Fatalf("Encode with fallback: %v", err)
	}
	var got int
	if err := sc.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode with fallback: %v", err)
	}
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

// TestSelectorCodecNoProviderNoFallback verifies ErrNoProviderForNamespace is
// returned when neither a namespace provider nor a fallback is registered.
func TestSelectorCodecNoProviderNoFallback(t *testing.T) {
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns1", mustNewProvider(t, makeKey(32), "ns1-key")),
	)
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}

	sc := mustNewSelectorCodec(t, sel)
	ctx := WithNamespace(context.Background(), "unregistered")

	if _, err := sc.Encode(ctx, "val"); !IsNoProviderForNamespace(err) {
		t.Errorf("Encode: want ErrNoProviderForNamespace, got %v", err)
	}
}

// TestSelectorCodecEmptyNamespaceFallback verifies that an empty namespace
// (no WithNamespace call) uses the fallback provider.
func TestSelectorCodecEmptyNamespaceFallback(t *testing.T) {
	fallback := mustNewProvider(t, makeKey(32), "fallback-key")
	sel, err := NewNamespaceSelector(WithFallbackProvider(fallback))
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}

	sc := mustNewSelectorCodec(t, sel)
	ctx := context.Background() // no WithNamespace

	data, err := sc.Encode(ctx, "hello")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got string
	if err := sc.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

// TestSelectorCodecTransform verifies Transform/Reverse (codec.Transformer).
func TestSelectorCodecTransform(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	sc := mustNewSelectorCodec(t, sel)
	ctx := WithNamespace(context.Background(), "ns1")

	plaintext := []byte(`{"key":"value"}`)
	ciphertext, err := sc.Transform(ctx, plaintext)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	recovered, err := sc.Reverse(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("Reverse: got %q, want %q", recovered, plaintext)
	}
}

// TestNewSelectorCodecNilSelector verifies nil selector is rejected.
func TestNewSelectorCodecNilSelector(t *testing.T) {
	if _, err := NewSelectorCodec(nil, jsoncodec.New()); err == nil {
		t.Error("NewSelectorCodec(nil, ...) should return error")
	}
}

// TestNewSelectorCodecNilInner verifies nil inner codec is rejected.
func TestNewSelectorCodecNilInner(t *testing.T) {
	sel, _, _ := mustNewSelector(t)
	if _, err := NewSelectorCodec(sel, nil); err == nil {
		t.Error("NewSelectorCodec(..., nil) should return error")
	}
}

// TestSelectorCodecRuntimeProviderAdd verifies that a provider added at runtime
// via AddProvider is immediately usable.
func TestSelectorCodecRuntimeProviderAdd(t *testing.T) {
	sel, err := NewNamespaceSelector()
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}

	sc := mustNewSelectorCodec(t, sel)

	// Before provider is registered: should fail.
	ctx := WithNamespace(context.Background(), "dynamic")
	if _, err := sc.Encode(ctx, "x"); !IsNoProviderForNamespace(err) {
		t.Errorf("before AddProvider: want ErrNoProviderForNamespace, got %v", err)
	}

	// Add provider at runtime.
	if err := sel.AddProvider("dynamic", mustNewProvider(t, makeKey(32), "dyn-key")); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}

	// Now it should work.
	data, err := sc.Encode(ctx, "hello")
	if err != nil {
		t.Fatalf("Encode after AddProvider: %v", err)
	}
	var got string
	if err := sc.Decode(ctx, data, &got); err != nil {
		t.Fatalf("Decode after AddProvider: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

// TestWithNamespace verifies context helpers.
func TestWithNamespace(t *testing.T) {
	ctx := WithNamespace(context.Background(), "tenant-a")
	if got := NamespaceFromContext(ctx); got != "tenant-a" {
		t.Errorf("NamespaceFromContext = %q, want %q", got, "tenant-a")
	}
}

// TestNamespaceFromContextEmpty verifies empty string is returned when unset.
func TestNamespaceFromContextEmpty(t *testing.T) {
	if got := NamespaceFromContext(context.Background()); got != "" {
		t.Errorf("NamespaceFromContext on empty ctx = %q, want %q", got, "")
	}
}

// TestSelectorCodecMultiNamespaceSetup verifies the intended single-setup
// pattern: one SelectorCodec registered once, serving multiple namespaces each
// with its own provider. Encodes in one namespace cannot be decoded in another.
func TestSelectorCodecMultiNamespaceSetup(t *testing.T) {
	// One-time setup at application startup.
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("payments", mustNewProvider(t, makeKey(32), "payments-key")),
		WithNamespaceProvider("users", mustNewProvider(t, makeKey(32), "users-key")),
		WithFallbackProvider(mustNewProvider(t, makeKey(32), "default-key")),
	)
	if err != nil {
		t.Fatalf("NewNamespaceSelector: %v", err)
	}
	sc, err := NewSelectorCodec(sel, jsoncodec.New())
	if err != nil {
		t.Fatalf("NewSelectorCodec: %v", err)
	}
	// codec.Register(sc) would be called once here in a real application.

	type creds struct{ Token string }

	// Encrypt two values in different namespaces.
	payCtx := WithNamespace(context.Background(), "payments")
	usrCtx := WithNamespace(context.Background(), "users")
	defCtx := WithNamespace(context.Background(), "audit") // uses fallback

	payData, err := sc.Encode(payCtx, creds{"pay-token"})
	if err != nil {
		t.Fatalf("Encode payments: %v", err)
	}
	usrData, err := sc.Encode(usrCtx, creds{"usr-token"})
	if err != nil {
		t.Fatalf("Encode users: %v", err)
	}
	defData, err := sc.Encode(defCtx, creds{"def-token"})
	if err != nil {
		t.Fatalf("Encode fallback: %v", err)
	}

	// Each decrypts correctly in its own namespace.
	var got creds
	for _, tc := range []struct {
		ctx  context.Context
		data []byte
		want string
	}{
		{payCtx, payData, "pay-token"},
		{usrCtx, usrData, "usr-token"},
		{defCtx, defData, "def-token"},
	} {
		got = creds{}
		if err := sc.Decode(tc.ctx, tc.data, &got); err != nil {
			t.Fatalf("Decode %q: %v", tc.want, err)
		}
		if got.Token != tc.want {
			t.Errorf("got %q, want %q", got.Token, tc.want)
		}
	}

	// Cross-namespace decryption must fail.
	if err := sc.Decode(usrCtx, payData, &got); err == nil {
		t.Error("cross-namespace decode should fail")
	}
}
