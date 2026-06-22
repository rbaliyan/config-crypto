package crypto

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// eventually polls cond until it returns true or the deadline elapses.
// It avoids fixed sleeps so async tests stay deterministic under -race.
func eventually(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// fakeFetch is a controllable FetchFn whose returned versions can change
// between ticks. It records how many times it was called.
type fakeFetch struct {
	mu       sync.Mutex
	versions []KeyVersion
	err      error
	calls    atomic.Int64
}

func (f *fakeFetch) set(versions []KeyVersion, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions = versions
	f.err = err
}

func (f *fakeFetch) fn(_ context.Context) ([]KeyVersion, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	// Return fresh copies so Poll's defer-clear of key bytes cannot corrupt
	// the canonical version material held here.
	out := make([]KeyVersion, len(f.versions))
	for i, v := range f.versions {
		b := make([]byte, len(v.Bytes))
		copy(b, v.Bytes)
		out[i] = KeyVersion{ID: v.ID, Bytes: b, Rank: v.Rank, IsCurrent: v.IsCurrent}
	}
	return out, nil
}

func keyVersion(id string, seed byte, rank uint64, current bool) KeyVersion {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return KeyVersion{ID: id, Bytes: b, Rank: rank, IsCurrent: current}
}

// TestPoll_AddsNewVersionsAndPromotesCurrent verifies that on a later tick a
// new version is AddKey'd into the ring and the IsCurrent version is promoted.
func TestPoll_AddsNewVersionsAndPromotesCurrent(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)

	ff := &fakeFetch{}
	ff.set([]KeyVersion{keyVersion("v1", 1, 1, true)}, nil)

	stop, err := Poll(ctx, ring, 5*time.Millisecond, ff.fn)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	if got := ring.CurrentKeyID(); got != "v1" {
		t.Fatalf("initial current key = %q, want v1", got)
	}

	// Introduce a new, higher-ranked current version.
	ff.set([]KeyVersion{
		keyVersion("v1", 1, 1, false),
		keyVersion("v2", 2, 2, true),
	}, nil)

	if !eventually(t, 2*time.Second, func() bool { return ring.CurrentKeyID() == "v2" }) {
		t.Fatalf("poller never promoted v2; current = %q", ring.CurrentKeyID())
	}

	// v2 must be usable for encryption and v1 still usable for decryption.
	ct, err := ring.Encrypt(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := ring.Decrypt(ctx, ct); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}

// TestPoll_PermanentlyMalformedVersionRetriedThenSkipped verifies a version
// that always fails AddKey is retried up to WithPollMaxRetries and then
// skipped forever (the error count stabilises).
func TestPoll_PermanentlyMalformedVersionRetriedThenSkipped(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)

	const maxRetries = 3
	var errCount atomic.Int64

	ff := &fakeFetch{}
	ff.set([]KeyVersion{keyVersion("v1", 1, 1, true)}, nil)

	stop, err := Poll(ctx, ring, 2*time.Millisecond, ff.fn,
		WithPollMaxRetries(maxRetries),
		WithPollErrorHandler(func(error) { errCount.Add(1) }),
	)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	// A version whose key material is the wrong length always fails AddKey.
	bad := KeyVersion{ID: "bad", Bytes: make([]byte, 16), Rank: 2, IsCurrent: false}
	ff.set([]KeyVersion{keyVersion("v1", 1, 1, true), bad}, nil)

	// After maxRetries failures the version is given up on. The error count
	// reaches exactly maxRetries (one report per failed attempt) and stops.
	if !eventually(t, 2*time.Second, func() bool { return errCount.Load() >= int64(maxRetries) }) {
		t.Fatalf("expected at least %d errors, got %d", maxRetries, errCount.Load())
	}

	// Confirm the count is stable: poll across N consecutive identical
	// observations rather than sleeping a fixed window.
	stableAt := errCount.Load()
	stableObservations := 0
	ok := eventually(t, 2*time.Second, func() bool {
		cur := errCount.Load()
		if cur == stableAt {
			stableObservations++
		} else {
			stableAt = cur
			stableObservations = 0
		}
		return stableObservations >= 20
	})
	if !ok {
		t.Fatalf("error count never stabilised; last = %d", errCount.Load())
	}
	if errCount.Load() != int64(maxRetries) {
		t.Errorf("expected exactly %d errors after giving up, got %d", maxRetries, errCount.Load())
	}
}

// TestPoll_ErrorHandlerReceivesFetchErrors verifies WithPollErrorHandler is
// invoked when the FetchFn returns an error on a tick.
func TestPoll_ErrorHandlerReceivesFetchErrors(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)

	var errCount atomic.Int64
	ff := &fakeFetch{}
	ff.set([]KeyVersion{keyVersion("v1", 1, 1, true)}, nil)

	stop, err := Poll(ctx, ring, 2*time.Millisecond, ff.fn,
		WithPollErrorHandler(func(error) { errCount.Add(1) }),
	)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	// Make the fetch fail on every subsequent tick.
	ff.set(nil, context.DeadlineExceeded)

	if !eventually(t, 2*time.Second, func() bool { return errCount.Load() > 0 }) {
		t.Fatal("expected fetch error to be routed to the error handler")
	}
}

// TestPoll_StopHaltsGoroutine verifies the returned stop() halts the polling
// goroutine: no further fetches occur after stop() returns.
func TestPoll_StopHaltsGoroutine(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)

	ff := &fakeFetch{}
	ff.set([]KeyVersion{keyVersion("v1", 1, 1, true)}, nil)

	stop, err := Poll(ctx, ring, time.Millisecond, ff.fn)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	// Wait for at least one ticker-driven fetch beyond the initial one.
	if !eventually(t, 2*time.Second, func() bool { return ff.calls.Load() >= 2 }) {
		t.Fatal("poller never ticked")
	}

	// stop() cancels the context and blocks until the goroutine exits.
	stop()

	// After stop returns the goroutine is gone: the call count must not grow.
	before := ff.calls.Load()
	stableObservations := 0
	stable := eventually(t, time.Second, func() bool {
		if ff.calls.Load() == before {
			stableObservations++
		} else {
			before = ff.calls.Load()
			stableObservations = 0
		}
		return stableObservations >= 50
	})
	if !stable {
		t.Errorf("fetch calls kept growing after stop(): %d", ff.calls.Load())
	}
}

// TestPoll_ValidationErrors covers the fail-fast input checks.
func TestPoll_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)
	good := func(_ context.Context) ([]KeyVersion, error) { return nil, nil }

	if _, err := Poll(ctx, nil, time.Second, good); err == nil {
		t.Error("nil ring: expected error")
	}
	if _, err := Poll(ctx, ring, 0, good); err == nil {
		t.Error("zero interval: expected error")
	}
	if _, err := Poll(ctx, ring, time.Second, nil); err == nil {
		t.Error("nil fetchFn: expected error")
	}
}

// TestPoll_InitialFetchErrorFailsFast verifies a failing initial fetch returns
// an error from Poll without starting a goroutine.
func TestPoll_InitialFetchErrorFailsFast(t *testing.T) {
	ctx := context.Background()
	ring := mustNewKeyRingProvider(t, makeKey(32), "v1", 1)

	ff := &fakeFetch{}
	ff.set(nil, context.DeadlineExceeded)

	if _, err := Poll(ctx, ring, time.Second, ff.fn); err == nil {
		t.Fatal("expected initial fetch error to be returned")
	}
}
