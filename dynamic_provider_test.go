package crypto

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rbaliyan/config"
	"github.com/rbaliyan/config/memory"
)

func TestNewDynamicKeyProvider(t *testing.T) {
	key := makeKey(32)
	p, err := NewDynamicKeyProvider(key, "key-1")
	if err != nil {
		t.Fatalf("NewDynamicKeyProvider: %v", err)
	}

	current, err := p.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.ID != "key-1" {
		t.Errorf("CurrentKey().ID = %q, want %q", current.ID, "key-1")
	}
}

func TestNewDynamicKeyProviderInvalidSize(t *testing.T) {
	_, err := NewDynamicKeyProvider(makeKey(16), "key-1")
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestNewDynamicKeyProviderEmptyID(t *testing.T) {
	_, err := NewDynamicKeyProvider(makeKey(32), "")
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestDynamicKeyProviderWithOldKey(t *testing.T) {
	current := makeKey(32)
	old := make([]byte, 32)
	for i := range old {
		old[i] = byte(i + 100)
	}

	p, err := NewDynamicKeyProvider(current, "key-2",
		WithDynamicOldKey(old, "key-1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.KeyByID("key-1")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if got.ID != "key-1" {
		t.Errorf("KeyByID().ID = %q, want %q", got.ID, "key-1")
	}
}

func TestDynamicKeyProviderAddKeyAndSetCurrent(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}

	if err := p.AddKey(newKey, "key-2"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	if err := p.SetCurrentKeyID("key-2"); err != nil {
		t.Fatalf("SetCurrentKeyID: %v", err)
	}

	current, err := p.CurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != "key-2" {
		t.Errorf("CurrentKey().ID = %q, want %q", current.ID, "key-2")
	}

	// Old key still accessible
	got, err := p.KeyByID("key-1")
	if err != nil {
		t.Fatalf("KeyByID(key-1): %v", err)
	}
	if got.ID != "key-1" {
		t.Errorf("KeyByID().ID = %q, want %q", got.ID, "key-1")
	}
}

func TestDynamicKeyProviderSetCurrentKeyIDNotFound(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	err = p.SetCurrentKeyID("nonexistent")
	if !IsKeyNotFound(err) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDynamicKeyProviderAddKeyInvalidSize(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	err = p.AddKey(makeKey(16), "key-2")
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestDynamicKeyProviderAddKeyEmptyID(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	err = p.AddKey(makeKey(32), "")
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestDynamicKeyProviderRemoveKey(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}
	if err := p.AddKey(newKey, "key-2"); err != nil {
		t.Fatal(err)
	}

	if err := p.RemoveKey("key-2"); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}

	_, err = p.KeyByID("key-2")
	if !IsKeyNotFound(err) {
		t.Errorf("expected ErrKeyNotFound after remove, got %v", err)
	}
}

func TestDynamicKeyProviderRemoveCurrentKeyFails(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	err = p.RemoveKey("key-1")
	if !IsRemoveCurrentKey(err) {
		t.Errorf("expected ErrRemoveCurrentKey, got %v", err)
	}
}

func TestDynamicKeyProviderRemoveNonexistentKey(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	err = p.RemoveKey("nonexistent")
	if !IsKeyNotFound(err) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDynamicKeyProviderDestroy(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	p.Destroy()

	_, err = p.CurrentKey()
	if !IsProviderDestroyed(err) {
		t.Errorf("CurrentKey after destroy: expected ErrProviderDestroyed, got %v", err)
	}

	_, err = p.KeyByID("key-1")
	if !IsProviderDestroyed(err) {
		t.Errorf("KeyByID after destroy: expected ErrProviderDestroyed, got %v", err)
	}

	err = p.AddKey(makeKey(32), "key-2")
	if !errors.Is(err, ErrProviderDestroyed) {
		t.Errorf("AddKey after destroy: expected ErrProviderDestroyed, got %v", err)
	}

	err = p.SetCurrentKeyID("key-1")
	if !errors.Is(err, ErrProviderDestroyed) {
		t.Errorf("SetCurrentKeyID after destroy: expected ErrProviderDestroyed, got %v", err)
	}

	err = p.RemoveKey("key-1")
	if !errors.Is(err, ErrProviderDestroyed) {
		t.Errorf("RemoveKey after destroy: expected ErrProviderDestroyed, got %v", err)
	}
}

func TestDynamicKeyProviderDestroyZerosKeys(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}
	_ = p.AddKey(newKey, "key-2")

	// Hold references to internal backing arrays
	currentRef := p.current.Bytes
	key2Ref := p.keys["key-2"].Bytes

	p.Destroy()

	for i, b := range currentRef {
		if b != 0 {
			t.Errorf("current key byte %d not zeroed: got %d", i, b)
		}
	}
	for i, b := range key2Ref {
		if b != 0 {
			t.Errorf("key-2 byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestDynamicKeyProviderDestroyIdempotent(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	p.Destroy()
	p.Destroy() // should not panic
}

func TestDynamicKeyProviderConcurrent(t *testing.T) {
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}

	// Pre-add keys
	for i := 2; i <= 5; i++ {
		k := make([]byte, 32)
		for j := range k {
			k[j] = byte(i*10 + j)
		}
		if err := p.AddKey(k, fmt.Sprintf("key-%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		keyID := fmt.Sprintf("key-%d", (i%4)+1)
		go func() {
			defer wg.Done()
			_, _ = p.CurrentKey()
		}()
		go func() {
			defer wg.Done()
			_ = p.SetCurrentKeyID(keyID)
		}()
		go func() {
			defer wg.Done()
			_, _ = p.KeyByID(keyID)
		}()
	}
	wg.Wait()
}

func TestDynamicKeyProviderWatchKeyRotation(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)

	const ns = "internal:config:crypto"
	const keyName = "key/current-id"

	// Create provider with two keys
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Destroy()

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}
	if err := p.AddKey(newKey, "key-2"); err != nil {
		t.Fatal(err)
	}

	// Set initial value
	_, err = store.Set(ctx, ns, keyName, config.NewValue("key-1"))
	if err != nil {
		t.Fatal(err)
	}

	// Start watching
	cancel, err := p.WatchKeyRotation(ctx, store, ns, keyName)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	// Verify current key
	current, _ := p.CurrentKey()
	if current.ID != "key-1" {
		t.Fatalf("initial CurrentKey().ID = %q, want %q", current.ID, "key-1")
	}

	// Update config to trigger rotation
	_, err = store.Set(ctx, ns, keyName, config.NewValue("key-2"))
	if err != nil {
		t.Fatal(err)
	}

	// Wait for watch to propagate
	deadline := time.After(10 * time.Second)
	for {
		current, _ = p.CurrentKey()
		if current.ID == "key-2" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for key rotation: CurrentKey().ID = %q, want %q", current.ID, "key-2")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestDynamicKeyProviderWatchKeyRotationCancel(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)

	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Destroy()

	cancel, err := p.WatchKeyRotation(ctx, store, "internal:config:crypto", "key/current-id")
	if err != nil {
		t.Fatal(err)
	}

	// Cancel should stop the goroutine without blocking
	cancel()

	// Allow goroutine to drain
	time.Sleep(50 * time.Millisecond)
}

func TestWithDynamicOldKeyInvalidSize(t *testing.T) {
	_, err := NewDynamicKeyProvider(makeKey(32), "key-2",
		WithDynamicOldKey(makeKey(16), "key-1"),
	)
	if !IsInvalidKeySize(err) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestWithDynamicOldKeyEmptyID(t *testing.T) {
	_, err := NewDynamicKeyProvider(makeKey(32), "key-2",
		WithDynamicOldKey(makeKey(32), ""),
	)
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}
}

func TestWithDynamicOldKeyDuplicateID(t *testing.T) {
	old1 := make([]byte, 32)
	for i := range old1 {
		old1[i] = byte(i + 100)
	}
	old2 := make([]byte, 32)
	for i := range old2 {
		old2[i] = byte(i + 200)
	}

	_, err := NewDynamicKeyProvider(makeKey(32), "current",
		WithDynamicOldKey(old1, "old-key"),
		WithDynamicOldKey(old2, "old-key"),
	)
	if !IsInvalidKeyID(err) {
		t.Errorf("expected ErrInvalidKeyID for duplicate, got %v", err)
	}
}

func TestWithOnRotationError(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer store.Close(ctx)

	var mu sync.Mutex
	var gotErr error
	p, err := NewDynamicKeyProvider(makeKey(32), "key-1",
		WithOnRotationError(func(e error) {
			mu.Lock()
			gotErr = e
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatalf("NewDynamicKeyProvider: %v", err)
	}
	defer p.Destroy()

	cancel, err := p.WatchKeyRotation(ctx, store, "crypto", "active-key")
	if err != nil {
		t.Fatalf("WatchKeyRotation: %v", err)
	}
	defer cancel()

	// Set a key ID that is not registered — should trigger the callback.
	val := config.NewValue("key-99")
	if _, err := store.Set(ctx, "crypto", "active-key", val); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Wait for the watch goroutine to process the event.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		e := gotErr
		mu.Unlock()
		if e != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr == nil {
		t.Fatal("expected rotation error callback, got none")
	}
	if !IsKeyNotFound(gotErr) {
		t.Errorf("expected ErrKeyNotFound, got %v", gotErr)
	}
}

func TestWatchKeyRotation_SlogFallback(t *testing.T) {
	// When no WithOnRotationError callback is set, rotation errors must not
	// panic and must not be silently dropped (they log via slog.Default).
	store := memory.NewStore()
	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer store.Close(ctx)

	p, err := NewDynamicKeyProvider(makeKey(32), "key-1")
	if err != nil {
		t.Fatalf("NewDynamicKeyProvider: %v", err)
	}
	defer p.Destroy()

	cancel, err := p.WatchKeyRotation(ctx, store, "crypto", "active-key")
	if err != nil {
		t.Fatalf("WatchKeyRotation: %v", err)
	}
	defer cancel()

	// Trigger a rotation error (unregistered key ID). The fallback slog call
	// must not panic; if it does, the test will fail with a goroutine panic.
	val := config.NewValue("unregistered-key")
	if _, err := store.Set(ctx, "crypto", "active-key", val); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Give the watch goroutine time to process the event.
	time.Sleep(100 * time.Millisecond)
}
