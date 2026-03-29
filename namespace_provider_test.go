package crypto

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

func newTestKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	id := t.Name()
	return key, id
}

func newTestProvider(t *testing.T) (*StaticKeyProvider, Key) {
	t.Helper()
	keyBytes, id := newTestKey(t)
	p, err := NewStaticKeyProvider(keyBytes, id)
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}

func TestNamespaceKeySelector_BasicDispatch(t *testing.T) {
	provA, keyA := newTestProvider(t)
	provB, keyB := newTestProvider(t)

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
		WithNamespaceProvider("ns-b", provB),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Namespace A should return key A.
	scopedA := sel.ForNamespace("ns-a")
	gotA, err := scopedA.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if gotA.ID != keyA.ID {
		t.Errorf("namespace-a: got key ID %q, want %q", gotA.ID, keyA.ID)
	}

	// Namespace B should return key B.
	scopedB := sel.ForNamespace("ns-b")
	gotB, err := scopedB.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if gotB.ID != keyB.ID {
		t.Errorf("namespace-b: got key ID %q, want %q", gotB.ID, keyB.ID)
	}
}

func TestNamespaceKeySelector_FallbackProvider(t *testing.T) {
	provFB, keyFB := newTestProvider(t)

	sel, err := NewNamespaceKeySelector(
		WithFallbackProvider(provFB),
	)
	if err != nil {
		t.Fatal(err)
	}

	scoped := sel.ForNamespace("unknown-ns")
	got, err := scoped.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != keyFB.ID {
		t.Errorf("fallback: got key ID %q, want %q", got.ID, keyFB.ID)
	}
}

func TestNamespaceKeySelector_NoFallbackError(t *testing.T) {
	sel, err := NewNamespaceKeySelector()
	if err != nil {
		t.Fatal(err)
	}

	scoped := sel.ForNamespace("missing")
	_, err = scoped.CurrentKey()
	if !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("expected ErrNoProviderForNamespace, got %v", err)
	}
	if !IsNoProviderForNamespace(err) {
		t.Errorf("IsNoProviderForNamespace should return true")
	}

	_, err = scoped.KeyByID("any")
	if !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("KeyByID: expected ErrNoProviderForNamespace, got %v", err)
	}
}

func TestNamespaceKeySelector_ForNamespaceKeyByID(t *testing.T) {
	keyBytesA := make([]byte, 32)
	if _, err := rand.Read(keyBytesA); err != nil {
		t.Fatal(err)
	}
	keyBytesOld := make([]byte, 32)
	if _, err := rand.Read(keyBytesOld); err != nil {
		t.Fatal(err)
	}

	provA, err := NewStaticKeyProvider(keyBytesA, "current-a", WithOldKey(keyBytesOld, "old-a"))
	if err != nil {
		t.Fatal(err)
	}

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
	)
	if err != nil {
		t.Fatal(err)
	}

	scoped := sel.ForNamespace("ns-a")

	// CurrentKey works.
	cur, err := scoped.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if cur.ID != "current-a" {
		t.Errorf("CurrentKey: got %q, want %q", cur.ID, "current-a")
	}

	// KeyByID for current key.
	k, err := scoped.KeyByID("current-a")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "current-a" {
		t.Errorf("KeyByID current: got %q, want %q", k.ID, "current-a")
	}

	// KeyByID for old key.
	k, err = scoped.KeyByID("old-a")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "old-a" {
		t.Errorf("KeyByID old: got %q, want %q", k.ID, "old-a")
	}

	// KeyByID for unknown key.
	_, err = scoped.KeyByID("nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("KeyByID unknown: expected ErrKeyNotFound, got %v", err)
	}
}

func TestNamespaceKeySelector_ConcurrentAccess(t *testing.T) {
	provA, _ := newTestProvider(t)
	provB, _ := newTestProvider(t)
	provFB, _ := newTestProvider(t)

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
		WithFallbackProvider(provFB),
	)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent reads via ForNamespace.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scoped := sel.ForNamespace("ns-a")
			if _, err := scoped.CurrentKey(); err != nil {
				t.Errorf("concurrent CurrentKey: %v", err)
			}
		}()
	}

	// Concurrent reads via fallback.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scoped := sel.ForNamespace("unknown")
			if _, err := scoped.CurrentKey(); err != nil {
				t.Errorf("concurrent fallback CurrentKey: %v", err)
			}
		}()
	}

	// Concurrent writes (AddProvider/RemoveProvider).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sel.AddProvider("ns-b", provB)
			sel.RemoveProvider("ns-b")
		}()
	}

	wg.Wait()
}

func TestNamespaceKeySelector_AddRemoveProvider(t *testing.T) {
	provA, keyA := newTestProvider(t)
	provB, keyB := newTestProvider(t)

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
	)
	if err != nil {
		t.Fatal(err)
	}

	// ns-b not registered yet.
	scoped := sel.ForNamespace("ns-b")
	_, err = scoped.CurrentKey()
	if !errors.Is(err, ErrNoProviderForNamespace) {
		t.Fatalf("expected ErrNoProviderForNamespace before add, got %v", err)
	}

	// Add ns-b at runtime.
	sel.AddProvider("ns-b", provB)
	got, err := scoped.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != keyB.ID {
		t.Errorf("after add: got key ID %q, want %q", got.ID, keyB.ID)
	}

	// Remove ns-b.
	sel.RemoveProvider("ns-b")
	_, err = scoped.CurrentKey()
	if !errors.Is(err, ErrNoProviderForNamespace) {
		t.Fatalf("expected ErrNoProviderForNamespace after remove, got %v", err)
	}

	// ns-a still works.
	scopedA := sel.ForNamespace("ns-a")
	gotA, err := scopedA.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if gotA.ID != keyA.ID {
		t.Errorf("ns-a after remove ns-b: got key ID %q, want %q", gotA.ID, keyA.ID)
	}
}

func TestNamespaceKeySelector_RoundTrip(t *testing.T) {
	keyBytesA := make([]byte, 32)
	if _, err := rand.Read(keyBytesA); err != nil {
		t.Fatal(err)
	}
	keyBytesB := make([]byte, 32)
	if _, err := rand.Read(keyBytesB); err != nil {
		t.Fatal(err)
	}

	provA, err := NewStaticKeyProvider(keyBytesA, "key-a")
	if err != nil {
		t.Fatal(err)
	}
	provB, err := NewStaticKeyProvider(keyBytesB, "key-b")
	if err != nil {
		t.Fatal(err)
	}

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
		WithNamespaceProvider("ns-b", provB),
	)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret data for namespace A")

	// Encrypt using namespace A's provider.
	scopedA := sel.ForNamespace("ns-a")
	keyA, err := scopedA.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encrypt(plaintext, keyA)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt using the same namespace's provider.
	decrypted, err := decrypt(ciphertext, scopedA)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip: got %q, want %q", decrypted, plaintext)
	}

	// Decrypting with namespace B's provider should fail (different key).
	scopedB := sel.ForNamespace("ns-b")
	_, err = decrypt(ciphertext, scopedB)
	if err == nil {
		t.Error("expected decryption to fail with wrong namespace provider")
	}
}

func TestNamespaceKeySelector_CurrentKeyWithFallback(t *testing.T) {
	provFB, keyFB := newTestProvider(t)

	sel, err := NewNamespaceKeySelector(
		WithFallbackProvider(provFB),
	)
	if err != nil {
		t.Fatal(err)
	}

	// The selector itself implements KeyProvider; CurrentKey delegates to fallback.
	got, err := sel.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != keyFB.ID {
		t.Errorf("selector CurrentKey: got %q, want %q", got.ID, keyFB.ID)
	}
}

func TestNamespaceKeySelector_CurrentKeyNoFallback(t *testing.T) {
	sel, err := NewNamespaceKeySelector()
	if err != nil {
		t.Fatal(err)
	}

	_, err = sel.CurrentKey()
	if !errors.Is(err, ErrNoProviderForNamespace) {
		t.Errorf("selector CurrentKey without fallback: expected ErrNoProviderForNamespace, got %v", err)
	}
}

func TestNamespaceKeySelector_KeyByIDSearchesAll(t *testing.T) {
	keyBytesA := make([]byte, 32)
	if _, err := rand.Read(keyBytesA); err != nil {
		t.Fatal(err)
	}
	keyBytesB := make([]byte, 32)
	if _, err := rand.Read(keyBytesB); err != nil {
		t.Fatal(err)
	}

	provA, err := NewStaticKeyProvider(keyBytesA, "key-a")
	if err != nil {
		t.Fatal(err)
	}
	provB, err := NewStaticKeyProvider(keyBytesB, "key-b")
	if err != nil {
		t.Fatal(err)
	}

	sel, err := NewNamespaceKeySelector(
		WithNamespaceProvider("ns-a", provA),
		WithNamespaceProvider("ns-b", provB),
	)
	if err != nil {
		t.Fatal(err)
	}

	// KeyByID on the selector searches across all providers.
	k, err := sel.KeyByID("key-a")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "key-a" {
		t.Errorf("KeyByID: got %q, want %q", k.ID, "key-a")
	}

	k, err = sel.KeyByID("key-b")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "key-b" {
		t.Errorf("KeyByID: got %q, want %q", k.ID, "key-b")
	}

	// Unknown key ID.
	_, err = sel.KeyByID("nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("KeyByID unknown: expected ErrKeyNotFound, got %v", err)
	}
}
