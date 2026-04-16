package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	crypto "github.com/rbaliyan/config-crypto"
)

// mockClient is a configurable in-memory KV v2 mock.
type mockClient struct {
	mu       sync.Mutex
	mount    string
	path     string
	versions map[int]map[string]string
	current  int

	metaErr     error
	getErr      map[int]error
	metadataHit atomic.Int64
	getHit      atomic.Int64
}

func newMock(mount, path string) *mockClient {
	return &mockClient{
		mount:    mount,
		path:     path,
		versions: map[int]map[string]string{},
		getErr:   map[int]error{},
	}
}

func (m *mockClient) putKey(version int, keyBytes []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versions[version] = map[string]string{
		"key": base64.StdEncoding.EncodeToString(keyBytes),
	}
	if version > m.current {
		m.current = version
	}
}

func (m *mockClient) putRaw(version int, data map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versions[version] = data
	if version > m.current {
		m.current = version
	}
}

func (m *mockClient) KVMetadata(_ context.Context, mount, path string) ([]int, int, error) {
	m.metadataHit.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if mount != m.mount || path != m.path {
		return nil, 0, fmt.Errorf("unknown KV path %s/%s", mount, path)
	}
	if m.metaErr != nil {
		return nil, 0, m.metaErr
	}
	versions := make([]int, 0, len(m.versions))
	for v := range m.versions {
		versions = append(versions, v)
	}
	return versions, m.current, nil
}

func (m *mockClient) KVGet(_ context.Context, mount, path string, version int) (map[string]string, error) {
	m.getHit.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if mount != m.mount || path != m.path {
		return nil, fmt.Errorf("unknown KV path %s/%s", mount, path)
	}
	if err, ok := m.getErr[version]; ok && err != nil {
		return nil, err
	}
	data, ok := m.versions[version]
	if !ok {
		return nil, fmt.Errorf("version %d not found", version)
	}
	out := make(map[string]string, len(data))
	maps.Copy(out, data)
	return out, nil
}

func mkKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestNew_RoundTripDecryptsAcrossVersions(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))
	mock.putKey(2, mkKey(2))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ring.Close()

	// Encrypt with current (v2) and decrypt.
	ct, err := ring.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := ring.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestNew_CustomFieldAndIDFormat(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putRaw(7, map[string]string{
		"material": base64.StdEncoding.EncodeToString(mkKey(9)),
	})

	ring, err := New(ctx, mock, "secret", "config/key",
		WithField("material"),
		WithKeyIDFormat(func(v int) string { return fmt.Sprintf("kv-v%d", v) }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ring.Close()

	ct, err := ring.Encrypt(ctx, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Decrypt(ctx, ct); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}

func TestNew_PollsForNewVersions(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	v1Bytes := mkKey(1)
	v2Bytes := mkKey(2)
	mock.putKey(1, v1Bytes)

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ring.Close()

	stop, err := Poll(ctx, mock, ring, "secret", "config/key", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	// Encrypt before v2 exists.
	ctV1, err := ring.Encrypt(ctx, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}

	// Add v2; after the poller picks it up the current key should be v2.
	mock.putKey(2, v2Bytes)

	// A v2-only standalone provider can decrypt only ciphertexts that used v2.
	v2Only, err := crypto.NewProvider(v2Bytes, "2")
	if err != nil {
		t.Fatal(err)
	}
	defer v2Only.Close()

	deadline := time.Now().Add(2 * time.Second)
	var rotated bool
	for time.Now().Before(deadline) {
		ct, err := ring.Encrypt(ctx, []byte("after-rotation"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v2Only.Decrypt(ctx, ct); err == nil {
			rotated = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !rotated {
		t.Fatal("poller never promoted v2 to current")
	}

	// Both v1 and post-rotation ciphertexts decrypt via the ring.
	if _, err := ring.Decrypt(ctx, ctV1); err != nil {
		t.Errorf("v1 ciphertext: %v", err)
	}
}

func TestNew_HealthCheck(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatal(err)
	}

	// HealthCheck is liveness-only for the underlying KeyRingProvider.
	if err := ring.HealthCheck(ctx); err != nil {
		t.Errorf("healthy: %v", err)
	}

	// After close, HealthCheck returns ErrProviderClosed.
	if err := ring.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ring.HealthCheck(ctx); !crypto.IsProviderClosed(err) {
		t.Errorf("after close: got %v, want ErrProviderClosed", err)
	}
}

func TestNew_PollGivesUpOnPermanentFailure(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ring.Close()

	var errCount atomic.Int64
	stop, err := Poll(ctx, mock, ring, "secret", "config/key", 10*time.Millisecond,
		WithRefreshErrorHandler(func(error) { errCount.Add(1) }),
	)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	// Add a permanently-bad version (wrong key length).
	mock.putRaw(2, map[string]string{"key": base64.StdEncoding.EncodeToString(make([]byte, 16))})

	// Wait until the error rate stabilises (retries exhausted, version marked failed).
	var stable int64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		first := errCount.Load()
		time.Sleep(50 * time.Millisecond)
		second := errCount.Load()
		if first == second && first > 0 {
			stable = first
			break
		}
	}
	if stable == 0 {
		t.Fatalf("error rate never stabilised; final count = %d", errCount.Load())
	}

	// Confirm: count stays put for another window.
	time.Sleep(300 * time.Millisecond)
	if got := errCount.Load(); got != stable {
		t.Errorf("expected stable error count %d; got %d (poller still retrying)", stable, got)
	}
}

func TestNew_PollSurfacesErrors(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ring.Close()

	var errCount atomic.Int64
	stop, err := Poll(ctx, mock, ring, "secret", "config/key", 10*time.Millisecond,
		WithRefreshErrorHandler(func(error) { errCount.Add(1) }),
	)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	defer stop()

	mock.mu.Lock()
	mock.metaErr = errors.New("vault unreachable")
	mock.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && errCount.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if errCount.Load() == 0 {
		t.Fatal("expected refresh-error callback to fire")
	}
}

func TestNew_CloseStopsPolling(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stop, err := Poll(ctx, mock, ring, "secret", "config/key", 5*time.Millisecond)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	// Close the ring; the poller should exit when it detects ErrProviderClosed.
	if err := ring.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stop()

	before := mock.metadataHit.Load()
	time.Sleep(50 * time.Millisecond)
	after := mock.metadataHit.Load()
	if after != before {
		t.Errorf("poller still active after Close: %d -> %d", before, after)
	}
}

func TestNew_ValidationErrors(t *testing.T) {
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	cases := []struct {
		name   string
		client Client
		mount  string
		path   string
		opts   []Option
	}{
		{"nil client", nil, "secret", "config/key", nil},
		{"empty mount", mock, "", "config/key", nil},
		{"empty path", mock, "secret", "", nil},
		{"empty field", mock, "secret", "config/key", []Option{WithField("")}},
		{"nil id format", mock, "secret", "config/key", []Option{WithKeyIDFormat(nil)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(context.Background(), c.client, c.mount, c.path, c.opts...)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPoll_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	mock := newMock("secret", "config/key")
	mock.putKey(1, mkKey(1))

	ring, err := New(ctx, mock, "secret", "config/key")
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()

	cases := []struct {
		name     string
		client   Client
		ring     crypto.KeyRingProvider
		mount    string
		path     string
		interval time.Duration
	}{
		{"nil client", nil, ring, "secret", "config/key", time.Second},
		{"nil ring", mock, nil, "secret", "config/key", time.Second},
		{"empty mount", mock, ring, "", "config/key", time.Second},
		{"empty path", mock, ring, "secret", "", time.Second},
		{"zero interval", mock, ring, "secret", "config/key", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Poll(ctx, c.client, c.ring, c.mount, c.path, c.interval)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNew_BadKeyMaterial(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(mkKey(1))

	t.Run("missing field", func(t *testing.T) {
		mock := newMock("secret", "config/key")
		mock.putRaw(1, map[string]string{"other": good})
		_, err := New(context.Background(), mock, "secret", "config/key")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid base64", func(t *testing.T) {
		mock := newMock("secret", "config/key")
		mock.putRaw(1, map[string]string{"key": "!!!not base64!!!"})
		_, err := New(context.Background(), mock, "secret", "config/key")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		mock := newMock("secret", "config/key")
		mock.putRaw(1, map[string]string{"key": base64.StdEncoding.EncodeToString(make([]byte, 16))})
		_, err := New(context.Background(), mock, "secret", "config/key")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("no versions", func(t *testing.T) {
		mock := newMock("secret", "config/key")
		_, err := New(context.Background(), mock, "secret", "config/key")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("metadata error", func(t *testing.T) {
		mock := newMock("secret", "config/key")
		mock.metaErr = errors.New("forbidden")
		_, err := New(context.Background(), mock, "secret", "config/key")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
