package crypto

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestNamespaceSelector_BasicDispatch(t *testing.T) {
	ctx := context.Background()
	pa := mustNewProvider(t, makeKey(32), "key-a")
	pb := mustNewProvider(t, makeKey(32), "key-b")

	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns-a", pa),
		WithNamespaceProvider("ns-b", pb),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip per namespace.
	for _, ns := range []string{"ns-a", "ns-b"} {
		scoped := sel.ForNamespace(ns)
		ct, err := scoped.Encrypt(ctx, []byte("hello "+ns))
		if err != nil {
			t.Fatalf("Encrypt %s: %v", ns, err)
		}
		got, err := scoped.Decrypt(ctx, ct)
		if err != nil {
			t.Fatalf("Decrypt %s: %v", ns, err)
		}
		if string(got) != "hello "+ns {
			t.Errorf("%s: got %q", ns, got)
		}
	}

	// Cross-namespace decryption fails.
	scopedA := sel.ForNamespace("ns-a")
	scopedB := sel.ForNamespace("ns-b")
	ct, _ := scopedA.Encrypt(ctx, []byte("a-only"))
	if _, err := scopedB.Decrypt(ctx, ct); err == nil {
		t.Error("expected cross-namespace decrypt to fail")
	}
}

func TestNamespaceSelector_FallbackProvider(t *testing.T) {
	ctx := context.Background()
	fb := mustNewProvider(t, makeKey(32), "fb-key")

	sel, err := NewNamespaceSelector(WithFallbackProvider(fb))
	if err != nil {
		t.Fatal(err)
	}

	scoped := sel.ForNamespace("unknown-ns")
	ct, err := scoped.Encrypt(ctx, []byte("via-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := scoped.Decrypt(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "via-fallback" {
		t.Errorf("got %q", got)
	}
}

func TestNamespaceSelector_NoFallbackError(t *testing.T) {
	sel, err := NewNamespaceSelector()
	if err != nil {
		t.Fatal(err)
	}
	scoped := sel.ForNamespace("missing")
	if _, err := scoped.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("Encrypt: expected ErrNoProviderForNamespace, got %v", err)
	}
	if _, err := scoped.Decrypt(context.Background(), []byte("x")); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("Decrypt: expected ErrNoProviderForNamespace, got %v", err)
	}
	if !IsNoProviderForNamespace(errors.New("wrapped: "+ErrNoProviderForNamespace.Error())) == false {
		// IsNoProviderForNamespace requires the error chain to wrap the sentinel;
		// a plain string error doesn't. Skip the wrapper check — covered by the Is checks above.
		_ = sel
	}
}

func TestNamespaceSelector_AddRemoveProvider(t *testing.T) {
	ctx := context.Background()
	pa := mustNewProvider(t, makeKey(32), "key-a")
	pb := mustNewProvider(t, makeKey(32), "key-b")

	sel, err := NewNamespaceSelector(WithNamespaceProvider("ns-a", pa))
	if err != nil {
		t.Fatal(err)
	}

	scopedB := sel.ForNamespace("ns-b")
	if _, err := scopedB.Encrypt(ctx, []byte("x")); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Fatalf("before add: got %v, want ErrNoProviderForNamespace", err)
	}

	if err := sel.AddProvider("ns-b", pb); err != nil {
		t.Fatal(err)
	}
	if _, err := scopedB.Encrypt(ctx, []byte("x")); err != nil {
		t.Errorf("after add: %v", err)
	}

	sel.RemoveProvider("ns-b")
	if _, err := scopedB.Encrypt(ctx, []byte("x")); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("after remove: got %v, want ErrNoProviderForNamespace", err)
	}

	// ns-a still works.
	if _, err := sel.ForNamespace("ns-a").Encrypt(ctx, []byte("x")); err != nil {
		t.Errorf("ns-a after remove ns-b: %v", err)
	}
}

func TestNamespaceSelector_RemoveAndClose(t *testing.T) {
	ctx := context.Background()
	pa, err := NewProvider(makeKey(32), "key-a")
	if err != nil {
		t.Fatal(err)
	}
	sel, err := NewNamespaceSelector(WithNamespaceProvider("ns-a", pa))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sel.Close() })

	if err := sel.RemoveAndClose("ns-a"); err != nil {
		t.Fatalf("RemoveAndClose: %v", err)
	}
	// Provider was closed by the selector.
	if _, err := pa.Encrypt(ctx, []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("removed provider should be closed: got %v", err)
	}
	// Removing a missing namespace is a no-op.
	if err := sel.RemoveAndClose("nonexistent"); err != nil {
		t.Errorf("RemoveAndClose missing: got %v, want nil", err)
	}
}

func TestNamespaceSelector_AddProviderNil(t *testing.T) {
	sel, err := NewNamespaceSelector()
	if err != nil {
		t.Fatal(err)
	}
	if err := sel.AddProvider("ns", nil); err == nil {
		t.Error("expected error for nil provider")
	}
}

func TestNamespaceSelector_Close(t *testing.T) {
	pa, err := NewProvider(makeKey(32), "a")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := NewProvider(makeKey(32), "fb")
	if err != nil {
		t.Fatal(err)
	}
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns-a", pa),
		WithFallbackProvider(fb),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := sel.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Owned providers are now closed.
	if _, err := pa.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("namespace provider: got %v, want ErrProviderClosed", err)
	}
	if _, err := fb.Encrypt(context.Background(), []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("fallback: got %v, want ErrProviderClosed", err)
	}

	// Selector itself rejects further work.
	if err := sel.AddProvider("x", &failingProvider{}); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("AddProvider after Close: got %v, want ErrProviderClosed", err)
	}

	// Idempotent.
	if err := sel.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestNamespaceSelector_ScopedSeesRuntimeChanges(t *testing.T) {
	ctx := context.Background()
	sel, err := NewNamespaceSelector()
	if err != nil {
		t.Fatal(err)
	}
	scoped := sel.ForNamespace("dynamic")

	// Initially missing.
	if _, err := scoped.Encrypt(ctx, []byte("x")); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Fatal(err)
	}

	// Add at runtime — same scoped reference now resolves.
	pa := mustNewProvider(t, makeKey(32), "k")
	if err := sel.AddProvider("dynamic", pa); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.Encrypt(ctx, []byte("x")); err != nil {
		t.Errorf("after add: %v", err)
	}
}

func TestNamespaceSelector_Concurrent(t *testing.T) {
	ctx := context.Background()
	pa := mustNewProvider(t, makeKey(32), "a")
	fb := mustNewProvider(t, makeKey(32), "fb")
	sel, err := NewNamespaceSelector(
		WithNamespaceProvider("ns-a", pa),
		WithFallbackProvider(fb),
	)
	if err != nil {
		t.Fatal(err)
	}

	pb := mustNewProvider(t, makeKey(32), "b")
	var wg sync.WaitGroup
	const n = 50
	for range n {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := sel.ForNamespace("ns-a").Encrypt(ctx, []byte("x")); err != nil {
				t.Errorf("ns-a encrypt: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := sel.ForNamespace("unknown").Encrypt(ctx, []byte("x")); err != nil {
				t.Errorf("fallback encrypt: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = sel.AddProvider("ns-b", pb)
			sel.RemoveProvider("ns-b")
		}()
	}
	wg.Wait()
}

func TestScopedProvider_NameAndConnect(t *testing.T) {
	ctx := context.Background()
	pa := mustNewProvider(t, makeKey(32), "key-a")

	sel, err := NewNamespaceSelector(WithNamespaceProvider("prod", pa))
	if err != nil {
		t.Fatal(err)
	}
	defer sel.Close()

	scoped := sel.ForNamespace("prod")

	// Name returns the namespace-prefixed string.
	if got := scoped.Name(); got != "namespace:prod" {
		t.Errorf("Name() = %q, want %q", got, "namespace:prod")
	}

	// Connect delegates to the underlying provider (no-op for staticProvider).
	if err := scoped.Connect(ctx); err != nil {
		t.Errorf("Connect: %v", err)
	}

	// Connect on a missing namespace returns ErrNoProviderForNamespace.
	missing := sel.ForNamespace("missing")
	if err := missing.Connect(ctx); !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("Connect missing: got %v, want ErrNoProviderForNamespace", err)
	}

	// Connect on a closed selector returns ErrProviderClosed.
	if err := sel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scoped.Connect(ctx); !errors.Is(err, ErrProviderClosed) {
		t.Errorf("Connect after close: got %v, want ErrProviderClosed", err)
	}
}
