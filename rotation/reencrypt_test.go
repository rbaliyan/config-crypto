package rotation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	config "github.com/rbaliyan/config"
	"github.com/rbaliyan/config/memory"
)

// seedStore connects an in-memory store and writes n encrypted values under
// the codec's current key (key-v1). Each value is "secret-<key>". It returns
// the store and the keys written.
func seedStore(t *testing.T, ctx context.Context, c interface {
	Encode(context.Context, any) ([]byte, error)
	Name() string
}, ns string, n int) (config.Store, []string) {
	t.Helper()
	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(ctx) })

	keys := make([]string, 0, n)
	for i := range n {
		key := keyName(i)
		plaintext := "secret-" + key
		ct, err := c.Encode(ctx, plaintext)
		if err != nil {
			t.Fatalf("Encode %s: %v", key, err)
		}
		if _, err := store.Set(ctx, ns, key, config.NewRawValue(ct, c.Name())); err != nil {
			t.Fatalf("Set %s: %v", key, err)
		}
		keys = append(keys, key)
	}
	return store, keys
}

func keyName(i int) string {
	return fmt.Sprintf("secret/k%04d", i)
}

// decodeFromStore reads (ns, key) from store and decrypts it via the codec,
// returning the recovered plaintext string.
func decodeFromStore(t *testing.T, ctx context.Context, store config.Store, c interface {
	Decode(context.Context, []byte, any) error
}, ns, key string) string {
	t.Helper()
	v, err := store.Get(ctx, ns, key)
	if err != nil {
		t.Fatalf("Get %s: %v", key, err)
	}
	raw, err := v.Marshal(ctx)
	if err != nil {
		t.Fatalf("Marshal %s: %v", key, err)
	}
	var out string
	if err := c.Decode(ctx, raw, &out); err != nil {
		t.Fatalf("Decode %s: %v", key, err)
	}
	return out
}

func TestOrchestrator_ReencryptNamespace_RotatesStaleKeys(t *testing.T) {
	ctx := context.Background()
	ring, c := mustRotatingCodec(t)

	const ns = "prod"
	const n = 5
	store, keys := seedStore(t, ctx, c, ns, n)

	// Rotate: add v2 and make it current.
	v2 := []byte("FEDCBA9876543210FEDCBA9876543210")
	if err := ring.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := ring.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	o, err := NewOrchestrator(ring, store, c, WithNamespaces(ns))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	count, err := o.ReencryptNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("ReencryptNamespace: %v", err)
	}
	if count != n {
		t.Errorf("re-encrypted count = %d, want %d", count, n)
	}

	// Every value still decrypts to its original plaintext, and is no longer stale.
	for _, key := range keys {
		got := decodeFromStore(t, ctx, store, c, ns, key)
		if want := "secret-" + key; got != want {
			t.Errorf("%s: decrypted %q, want %q", key, got, want)
		}

		v, _ := store.Get(ctx, ns, key)
		raw, _ := v.Marshal(ctx)
		needs, err := ring.NeedsReencryption(raw)
		if err != nil {
			t.Errorf("%s: NeedsReencryption err %v", key, err)
		}
		if needs {
			t.Errorf("%s: still flagged stale after re-encryption", key)
		}
	}

	// A second pass finds nothing to do.
	count, err = o.ReencryptNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("second ReencryptNamespace: %v", err)
	}
	if count != 0 {
		t.Errorf("second pass count = %d, want 0", count)
	}
}

// errInjectStore wraps a config.Store and returns an error from Set for one
// specific key, to exercise the orchestrator's per-value error path.
type errInjectStore struct {
	config.Store
	failKey string
	failErr error
	setErrs atomic.Int64
}

func (s *errInjectStore) Set(ctx context.Context, ns, key string, v config.Value) (config.Value, error) {
	if key == s.failKey {
		s.setErrs.Add(1)
		return nil, s.failErr
	}
	return s.Store.Set(ctx, ns, key, v)
}

func TestOrchestrator_ReencryptNamespace_PartialFailure(t *testing.T) {
	ctx := context.Background()
	ring, c := mustRotatingCodec(t)

	const ns = "prod"
	const n = 4
	base, keys := seedStore(t, ctx, c, ns, n)

	// Rotate so all seeded values become stale.
	v2 := []byte("FEDCBA9876543210FEDCBA9876543210")
	if err := ring.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := ring.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	failKey := keys[1]
	store := &errInjectStore{Store: base, failKey: failKey, failErr: errors.New("set boom")}

	var (
		mu      sync.Mutex
		gotKeys []string
		gotErrs []error
	)
	o, err := NewOrchestrator(ring, store, c,
		WithNamespaces(ns),
		WithConcurrency(2),
		WithErrorHandler(func(_, key string, err error) {
			mu.Lock()
			gotKeys = append(gotKeys, key)
			gotErrs = append(gotErrs, err)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	count, err := o.ReencryptNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("ReencryptNamespace: %v", err)
	}

	// Partial count: all but the one failing key.
	if count != n-1 {
		t.Errorf("count = %d, want %d", count, n-1)
	}

	// The error handler received exactly the failing key's error.
	mu.Lock()
	defer mu.Unlock()
	if len(gotErrs) != 1 {
		t.Fatalf("error handler invoked %d times, want 1", len(gotErrs))
	}
	if gotKeys[0] != failKey {
		t.Errorf("error reported for key %q, want %q", gotKeys[0], failKey)
	}
	if !errors.Is(gotErrs[0], store.failErr) {
		t.Errorf("reported error = %v, want chain to %v", gotErrs[0], store.failErr)
	}

	// The other keys were re-encrypted and still decrypt.
	for _, key := range keys {
		if key == failKey {
			continue
		}
		got := decodeFromStore(t, ctx, base, c, ns, key)
		if want := "secret-" + key; got != want {
			t.Errorf("%s: decrypted %q, want %q", key, got, want)
		}
	}
}

// findCancelStore wraps a store and cancels a context the first time Find is
// called, simulating a cancellation that lands partway through a multi-page
// namespace sweep. ReencryptNamespace re-checks ctx.Err() between Find pages,
// so the sweep must stop and return context.Canceled.
type findCancelStore struct {
	config.Store
	cancel context.CancelFunc
	fired  atomic.Bool
}

func (s *findCancelStore) Find(ctx context.Context, ns string, f config.Filter) (config.Page, error) {
	page, err := s.Store.Find(ctx, ns, f)
	// Cancel after the first page is returned so the next between-page check
	// observes the cancellation.
	if s.fired.CompareAndSwap(false, true) {
		s.cancel()
	}
	return page, err
}

func TestOrchestrator_ReencryptNamespace_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ring, c := mustRotatingCodec(t)

	const ns = "prod"
	// Seed enough values to span multiple Find pages (page size is 100) so the
	// between-page cancellation check is reached after the first page.
	const n = 250
	base, _ := seedStore(t, ctx, c, ns, n)

	store := &findCancelStore{Store: base, cancel: cancel}

	v2 := []byte("FEDCBA9876543210FEDCBA9876543210")
	if err := ring.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := ring.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	o, err := NewOrchestrator(ring, store, c, WithNamespaces(ns), WithConcurrency(1))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	_, err = o.ReencryptNamespace(ctx, ns)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOrchestrator_Start_BackgroundReencrypts(t *testing.T) {
	ctx := context.Background()
	ring, c := mustRotatingCodec(t)

	const ns = "prod"
	const n = 3
	store, keys := seedStore(t, ctx, c, ns, n)

	v2 := []byte("FEDCBA9876543210FEDCBA9876543210")
	if err := ring.AddKey(v2, "v2", 2); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := ring.SetCurrentKey("v2"); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	o, err := NewOrchestrator(ring, store, c,
		WithNamespaces(ns),
		WithScanInterval(2*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	stop, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Poll a real signal: all values are no longer stale.
	allFresh := func() bool {
		for _, key := range keys {
			v, err := store.Get(ctx, ns, key)
			if err != nil {
				return false
			}
			raw, err := v.Marshal(ctx)
			if err != nil {
				return false
			}
			needs, err := ring.NeedsReencryption(raw)
			if err != nil || needs {
				return false
			}
		}
		return true
	}

	deadline := time.Now().Add(3 * time.Second)
	done := false
	for time.Now().Before(deadline) {
		if allFresh() {
			done = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !done {
		t.Fatal("background loop never re-encrypted all values")
	}

	stop()

	// After stop, all values still decrypt correctly and remain fresh.
	for _, key := range keys {
		got := decodeFromStore(t, ctx, store, c, ns, key)
		if want := "secret-" + key; got != want {
			t.Errorf("%s: decrypted %q, want %q", key, got, want)
		}
	}
	if !allFresh() {
		t.Error("values became stale after stop")
	}
}
