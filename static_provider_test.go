package crypto

import (
	"sync"
	"testing"
)

func makeKey(size int) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestNewStaticKeyProvider(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatalf("NewStaticKeyProvider: %v", err)
	}

	current, err := p.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.ID != "key-1" {
		t.Errorf("CurrentKey().ID: got %q, want %q", current.ID, "key-1")
	}
}

func TestStaticKeyProviderKeyByID(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.KeyByID("key-1")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if got.ID != "key-1" {
		t.Errorf("KeyByID().ID: got %q, want %q", got.ID, "key-1")
	}
}

func TestStaticKeyProviderKeyNotFound(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.KeyByID("nonexistent")
	if !IsKeyNotFound(err) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestStaticKeyProviderInvalidSize(t *testing.T) {
	_, err := NewStaticKeyProvider(makeKey(16), "key-1")
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestStaticKeyProviderEmptyID(t *testing.T) {
	_, err := NewStaticKeyProvider(makeKey(32), "")
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestStaticKeyProviderWithOldKeys(t *testing.T) {
	current := makeKey(32)
	old1 := make([]byte, 32)
	for i := range old1 {
		old1[i] = byte(i + 100)
	}
	old2 := make([]byte, 32)
	for i := range old2 {
		old2[i] = byte(i + 200)
	}

	p, err := NewStaticKeyProvider(current, "key-3",
		WithOldKey(old1, "key-1"),
		WithOldKey(old2, "key-2"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Current key
	got, err := p.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "key-3" {
		t.Errorf("CurrentKey().ID: got %q, want %q", got.ID, "key-3")
	}

	// Old keys accessible by ID
	got, err = p.KeyByID("key-1")
	if err != nil {
		t.Fatalf("KeyByID(key-1): %v", err)
	}
	if got.ID != "key-1" {
		t.Errorf("KeyByID(key-1).ID: got %q, want %q", got.ID, "key-1")
	}

	got, err = p.KeyByID("key-2")
	if err != nil {
		t.Fatalf("KeyByID(key-2): %v", err)
	}
	if got.ID != "key-2" {
		t.Errorf("KeyByID(key-2).ID: got %q, want %q", got.ID, "key-2")
	}
}

func TestStaticKeyProviderConcurrent(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = p.CurrentKey()
		}()
		go func() {
			defer wg.Done()
			_, _ = p.KeyByID("key-1")
		}()
	}
	wg.Wait()
}

func TestStaticKeyProviderKeyBytesCopied(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	// Zero the original key bytes — provider should be unaffected
	clear(key)

	got, err := p.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	// Verify the provider's key is NOT zeroed
	allZero := true
	for _, b := range got.Bytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("provider key was corrupted by zeroing original bytes")
	}
}

func TestStaticKeyProviderOldKeyBytesCopied(t *testing.T) {
	current := makeKey(32)
	old := make([]byte, 32)
	for i := range old {
		old[i] = byte(i + 100)
	}

	p, err := NewStaticKeyProvider(current, "key-2",
		WithOldKey(old, "key-1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Zero the original old key bytes
	clear(old)

	got, err := p.KeyByID("key-1")
	if err != nil {
		t.Fatal(err)
	}
	allZero := true
	for _, b := range got.Bytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("old key was corrupted by zeroing original bytes")
	}
}

func TestWithOldKeyInvalidSize(t *testing.T) {
	current := makeKey(32)
	_, err := NewStaticKeyProvider(current, "key-2",
		WithOldKey(makeKey(16), "key-1"),
	)
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestWithOldKeyEmptyID(t *testing.T) {
	current := makeKey(32)
	_, err := NewStaticKeyProvider(current, "key-2",
		WithOldKey(makeKey(32), ""),
	)
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestStaticKeyProviderDestroy(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	// Should work before destroy
	_, err = p.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey before destroy: %v", err)
	}

	p.Destroy()

	// CurrentKey should fail
	_, err = p.CurrentKey()
	if !IsProviderDestroyed(err) {
		t.Errorf("CurrentKey after destroy: expected ErrProviderDestroyed, got %v", err)
	}

	// KeyByID should fail
	_, err = p.KeyByID("key-1")
	if !IsProviderDestroyed(err) {
		t.Errorf("KeyByID after destroy: expected ErrProviderDestroyed, got %v", err)
	}
}

func TestStaticKeyProviderDestroyZerosKeyMaterial(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	// Get a reference to the internal key bytes before destroy
	got, _ := p.CurrentKey()
	keyRef := got.Bytes

	p.Destroy()

	// Verify the bytes were zeroed
	for i, b := range keyRef {
		if b != 0 {
			t.Errorf("key byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestStaticKeyProviderDestroyWithOldKeys(t *testing.T) {
	current := makeKey(32)
	old := make([]byte, 32)
	for i := range old {
		old[i] = byte(i + 100)
	}

	p, err := NewStaticKeyProvider(current, "key-2",
		WithOldKey(old, "key-1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Get references before destroy
	currentKey, _ := p.CurrentKey()
	oldKey, _ := p.KeyByID("key-1")
	currentRef := currentKey.Bytes
	oldRef := oldKey.Bytes

	p.Destroy()

	// Both should be zeroed
	for i, b := range currentRef {
		if b != 0 {
			t.Errorf("current key byte %d not zeroed: got %d", i, b)
		}
	}
	for i, b := range oldRef {
		if b != 0 {
			t.Errorf("old key byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestStaticKeyProviderDestroyIdempotent(t *testing.T) {
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	// Double destroy should not panic
	p.Destroy()
	p.Destroy()
}
