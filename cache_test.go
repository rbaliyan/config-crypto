package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/rbaliyan/config"
)

// mapCache is a simple in-memory config.Cache used in tests.
type mapCache struct {
	mu      sync.Mutex
	entries map[string]config.Value
	hits    int64
	misses  int64
}

func newMapCache() *mapCache {
	return &mapCache{entries: make(map[string]config.Value)}
}

func (m *mapCache) key(ns, k string) string { return ns + "\x00" + k }

func (m *mapCache) Get(_ context.Context, ns, k string) (config.Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[m.key(ns, k)]
	if !ok {
		m.misses++
		return nil, config.ErrNotFound
	}
	m.hits++
	return v, nil
}

func (m *mapCache) Set(_ context.Context, ns, k string, v config.Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[m.key(ns, k)] = v
	return nil
}

func (m *mapCache) Delete(_ context.Context, ns, k string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, m.key(ns, k))
	return nil
}

func (m *mapCache) Stats() config.CacheStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return config.CacheStats{Size: int64(len(m.entries)), Hits: m.hits, Misses: m.misses}
}

var _ config.Cache = (*mapCache)(nil)

// rawBytes returns the ciphertext bytes stored in the inner mapCache for (ns, key).
func (m *mapCache) rawBytes(t *testing.T, ns, key string) []byte {
	t.Helper()
	m.mu.Lock()
	v, ok := m.entries[m.key(ns, key)]
	m.mu.Unlock()
	if !ok {
		t.Fatalf("rawBytes: no entry for %s/%s", ns, key)
	}
	data, err := v.Marshal(context.Background())
	if err != nil {
		t.Fatalf("rawBytes: marshal: %v", err)
	}
	return data
}

func TestNewEncryptedCache_NilInner(t *testing.T) {
	p := mustNewProvider(t, makeKey(32), "k")
	_, err := NewEncryptedCache(nil, p)
	if err == nil {
		t.Fatal("expected error for nil inner")
	}
}

func TestNewEncryptedCache_NilProvider(t *testing.T) {
	_, err := NewEncryptedCache(newMapCache(), nil)
	if err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestEncryptedCache_RoundTrip_String(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	p := mustNewProvider(t, makeKey(32), "k1")
	ec, err := NewEncryptedCache(inner, p)
	if err != nil {
		t.Fatalf("NewEncryptedCache: %v", err)
	}

	original := config.NewValue("my-secret-password")
	if err := ec.Set(ctx, "prod", "db/pass", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Inner cache must not store plaintext.
	raw := inner.rawBytes(t, "prod", "db/pass")
	if bytes.Contains(raw, []byte("my-secret-password")) {
		t.Error("inner cache contains plaintext — encryption did not happen")
	}

	got, err := ec.Get(ctx, "prod", "db/pass")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	s, err := got.String()
	if err != nil {
		t.Fatalf("String: %v", err)
	}
	if s != "my-secret-password" {
		t.Errorf("got %q, want %q", s, "my-secret-password")
	}
}

func TestEncryptedCache_RoundTrip_Int(t *testing.T) {
	ctx := context.Background()
	ec, _ := NewEncryptedCache(newMapCache(), mustNewProvider(t, makeKey(32), "k"))

	if err := ec.Set(ctx, "", "rate", config.NewValue(int64(42))); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := ec.Get(ctx, "", "rate")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	n, err := got.Int64()
	if err != nil {
		t.Fatalf("Int64: %v", err)
	}
	if n != 42 {
		t.Errorf("got %d, want 42", n)
	}
}

func TestEncryptedCache_Miss(t *testing.T) {
	ctx := context.Background()
	ec, _ := NewEncryptedCache(newMapCache(), mustNewProvider(t, makeKey(32), "k"))

	_, err := ec.Get(ctx, "ns", "missing")
	if !config.IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_Delete(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	if err := ec.Set(ctx, "ns", "key", config.NewValue("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := ec.Delete(ctx, "ns", "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := ec.Get(ctx, "ns", "key")
	if !config.IsNotFound(err) {
		t.Errorf("expected ErrNotFound after Delete, got %v", err)
	}
}

func TestEncryptedCache_KeyRotation_GracefulMiss(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()

	oldKey := makeKey(32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}

	oldProvider := mustNewProvider(t, oldKey, "old")
	newProvider := mustNewProvider(t, newKey, "new")

	// Write with old key.
	ecOld, _ := NewEncryptedCache(inner, oldProvider)
	if err := ecOld.Set(ctx, "ns", "secret", config.NewValue("topsecret")); err != nil {
		t.Fatalf("Set (old key): %v", err)
	}

	// Read with new key — must be a cache miss, not an error.
	ecNew, _ := NewEncryptedCache(inner, newProvider)
	_, err := ecNew.Get(ctx, "ns", "secret")
	if !config.IsNotFound(err) {
		t.Errorf("key rotation: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_MetadataPreserved(t *testing.T) {
	ctx := context.Background()
	ec, _ := NewEncryptedCache(newMapCache(), mustNewProvider(t, makeKey(32), "k"))

	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	original := config.NewValue("val",
		config.WithValueMetadata(7, createdAt, updatedAt),
	)

	if err := ec.Set(ctx, "ns", "meta", original); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := ec.Get(ctx, "ns", "meta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	meta := got.Metadata()
	if meta.Version() != 7 {
		t.Errorf("version: got %d, want 7", meta.Version())
	}
	if !meta.CreatedAt().Equal(createdAt) {
		t.Errorf("createdAt: got %v, want %v", meta.CreatedAt(), createdAt)
	}
	if !meta.UpdatedAt().Equal(updatedAt) {
		t.Errorf("updatedAt: got %v, want %v", meta.UpdatedAt(), updatedAt)
	}
}

func TestEncryptedCache_EntryIDPreserved(t *testing.T) {
	ctx := context.Background()
	ec, _ := NewEncryptedCache(newMapCache(), mustNewProvider(t, makeKey(32), "k"))

	original := config.NewValue("val", config.WithValueEntryID("pg-row-42"))

	if err := ec.Set(ctx, "ns", "key", original); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := ec.Get(ctx, "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if id := config.EntryID(got); id != "pg-row-42" {
		t.Errorf("EntryID: got %q, want %q", id, "pg-row-42")
	}
}

func TestEncryptedCache_ExpiresAt_Preserved(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	original := config.NewValue("temp", config.WithValueExpiresAt(expiry))

	if err := ec.Set(ctx, "ns", "ttl", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Outer wrapper value must carry ExpiresAt for inner-cache TTL propagation.
	inner.mu.Lock()
	outerVal, ok := inner.entries[inner.key("ns", "ttl")]
	inner.mu.Unlock()
	if !ok {
		t.Fatal("entry not in inner cache")
	}
	if outerMeta := outerVal.Metadata(); !outerMeta.ExpiresAt().Equal(expiry) {
		t.Errorf("outer ExpiresAt: got %v, want %v", outerMeta.ExpiresAt(), expiry)
	}

	got, err := ec.Get(ctx, "ns", "ttl")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Metadata().ExpiresAt().Equal(expiry) {
		t.Errorf("reconstructed ExpiresAt: got %v, want %v", got.Metadata().ExpiresAt(), expiry)
	}
}

func TestEncryptedCache_InnerStoresNoPlaintext(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	secrets := map[string]string{
		"db/password": "supersecret123",
		"api/key":     "sk-abcdef",
		"jwt/secret":  "my-jwt-signing-key",
	}
	for configKey, secretVal := range secrets {
		if err := ec.Set(ctx, "creds", configKey, config.NewValue(secretVal)); err != nil {
			t.Fatalf("Set %s: %v", configKey, err)
		}
	}

	// Scan all raw bytes in the inner cache — none should contain a secret value.
	inner.mu.Lock()
	defer inner.mu.Unlock()
	for cacheKey, v := range inner.entries {
		raw, _ := v.Marshal(ctx)
		codec := v.Codec()
		for _, secretVal := range secrets {
			if bytes.Contains(raw, []byte(secretVal)) {
				t.Errorf("inner cache key %q contains plaintext secret", cacheKey)
			}
		}
		// Inner codec name must be the sentinel, not a real codec.
		if codec == "json" {
			t.Errorf("inner cache key %q has codec %q — expected %q", cacheKey, codec, encryptedCacheCodec)
		}
	}
}

func TestEncryptedCache_InnerCodecSentinel(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	if err := ec.Set(ctx, "ns", "k", config.NewValue("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	inner.mu.Lock()
	outerVal := inner.entries[inner.key("ns", "k")]
	inner.mu.Unlock()

	if outerVal.Codec() != encryptedCacheCodec {
		t.Errorf("inner codec: got %q, want %q", outerVal.Codec(), encryptedCacheCodec)
	}
	raw, _ := outerVal.Marshal(ctx)
	if len(raw) == 0 {
		t.Error("inner ciphertext is empty — encryption produced no output")
	}
}

func TestEncryptedCache_CorruptedPayload_Miss(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	if err := ec.Set(ctx, "ns", "key", config.NewValue("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Overwrite the inner cache entry with garbage ciphertext.
	inner.mu.Lock()
	inner.entries[inner.key("ns", "key")] = config.NewRawValue([]byte("not-valid-ciphertext"), encryptedCacheCodec)
	inner.mu.Unlock()

	_, err := ec.Get(ctx, "ns", "key")
	if !config.IsNotFound(err) {
		t.Errorf("corrupted payload: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_Stats(t *testing.T) {
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	_ = ec.Set(ctx, "ns", "a", config.NewValue("1"))
	_ = ec.Set(ctx, "ns", "b", config.NewValue("2"))

	_, _ = ec.Get(ctx, "ns", "a") // hit
	_, _ = ec.Get(ctx, "ns", "b") // hit
	_, _ = ec.Get(ctx, "ns", "x") // miss

	stats := ec.Stats()
	if stats.Hits != 2 {
		t.Errorf("Hits: got %d, want 2", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses: got %d, want 1", stats.Misses)
	}
	if stats.Size != 2 {
		t.Errorf("Size: got %d, want 2 (from inner)", stats.Size)
	}
}

func TestEncryptedCache_ProviderClosed_PropagatesError(t *testing.T) {
	// Provider operational failures must not be swallowed as cache misses.
	ctx := context.Background()
	inner := newMapCache()
	p := mustNewProvider(t, makeKey(32), "k")
	ec, _ := NewEncryptedCache(inner, p)

	if err := ec.Set(ctx, "ns", "key", config.NewValue("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Close the provider to simulate an operational failure.
	_ = p.Close()

	_, err := ec.Get(ctx, "ns", "key")
	if err == nil {
		t.Fatal("expected an error when provider is closed, got nil")
	}
	if config.IsNotFound(err) {
		t.Error("provider-closed error must not be silently converted to ErrNotFound")
	}
}

func TestEncryptedCache_WrongCodecSentinel_Miss(t *testing.T) {
	// Values stored with a different codec must be rejected before decryption.
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	// Inject a value with the wrong codec directly into the inner cache.
	_ = inner.Set(ctx, "ns", "key", config.NewValue("plaintext"))

	_, err := ec.Get(ctx, "ns", "key")
	if !config.IsNotFound(err) {
		t.Errorf("wrong codec: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_ExpiredValue_Miss(t *testing.T) {
	// Reconstructed values that are already past ExpiresAt must not be returned.
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	// Store a value that expires in the past.
	pastExpiry := time.Now().Add(-time.Minute)
	original := config.NewValue("stale", config.WithValueExpiresAt(pastExpiry))
	if err := ec.Set(ctx, "ns", "expired", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// The inner mapCache does not enforce expiry; EncryptedCache must reject it.
	_, err := ec.Get(ctx, "ns", "expired")
	if !config.IsNotFound(err) {
		t.Errorf("expired value: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_OuterWrapperLeaksNoTimestamps(t *testing.T) {
	// Version, CreatedAt, UpdatedAt must NOT appear on the outer wrapper value
	// stored in the inner cache — they are encrypted inside the ciphertext only.
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	original := config.NewValue("secret",
		config.WithValueMetadata(42, createdAt, updatedAt),
	)
	if err := ec.Set(ctx, "ns", "key", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	inner.mu.Lock()
	outerVal := inner.entries[inner.key("ns", "key")]
	inner.mu.Unlock()

	meta := outerVal.Metadata()
	if meta.Version() != 0 {
		t.Errorf("outer wrapper must not carry Version, got %d", meta.Version())
	}
	if !meta.CreatedAt().IsZero() {
		t.Errorf("outer wrapper must not carry CreatedAt, got %v", meta.CreatedAt())
	}
	if !meta.UpdatedAt().IsZero() {
		t.Errorf("outer wrapper must not carry UpdatedAt, got %v", meta.UpdatedAt())
	}
}

func TestEncryptedCache_SchemaVersionMismatch_Miss(t *testing.T) {
	// An entry encrypted with an unknown schema version must be a cache miss.
	ctx := context.Background()
	inner := newMapCache()
	p := mustNewProvider(t, makeKey(32), "k")
	ec, _ := NewEncryptedCache(inner, p)

	// Craft an entry with a future schema version and encrypt it directly.
	future := cacheEntry{
		V:     entrySchemaVersion + 1,
		Data:  []byte(`"value"`),
		Codec: "json",
		Type:  int(config.TypeString),
	}
	plaintext, _ := json.Marshal(future)
	ciphertext, err := p.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_ = inner.Set(ctx, "ns", "k", config.NewRawValue(ciphertext, encryptedCacheCodec))

	_, err = ec.Get(ctx, "ns", "k")
	if !config.IsNotFound(err) {
		t.Errorf("unknown schema version: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_InvalidType_Miss(t *testing.T) {
	// An entry with an out-of-range Type field must be a cache miss.
	ctx := context.Background()
	inner := newMapCache()
	p := mustNewProvider(t, makeKey(32), "k")
	ec, _ := NewEncryptedCache(inner, p)

	bad := cacheEntry{
		V:     entrySchemaVersion,
		Data:  []byte(`"value"`),
		Codec: "json",
		Type:  typeMax + 99, // out of range
	}
	plaintext, _ := json.Marshal(bad)
	ciphertext, _ := p.Encrypt(ctx, plaintext)
	_ = inner.Set(ctx, "ns", "k", config.NewRawValue(ciphertext, encryptedCacheCodec))

	_, err := ec.Get(ctx, "ns", "k")
	if !config.IsNotFound(err) {
		t.Errorf("invalid type: expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedCache_PayloadNotJSON(t *testing.T) {
	// The payload stored in the inner cache must be opaque ciphertext,
	// not readable JSON containing the original value.
	ctx := context.Background()
	inner := newMapCache()
	ec, _ := NewEncryptedCache(inner, mustNewProvider(t, makeKey(32), "k"))

	if err := ec.Set(ctx, "ns", "key", config.NewValue("secretvalue")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw := inner.rawBytes(t, "ns", "key")

	// Attempt to decode as a cacheEntry (plaintext) — must fail or not match.
	var entry cacheEntry
	if err := json.Unmarshal(raw, &entry); err == nil && string(entry.Data) == "secretvalue" {
		t.Error("raw bytes decoded as plaintext cacheEntry — encryption is broken")
	}
}

func TestEncryptedCache_Concurrent(t *testing.T) {
	// Verify EncryptedCache is race-free under concurrent Set/Get/Delete with
	// multiple goroutines and a KeyRingProvider (which uses its own mutex).
	ctx := context.Background()
	inner := newMapCache()
	ring := mustNewKeyRingProvider(t, makeKey(32), "k1", 1)
	ec, _ := NewEncryptedCache(inner, ring)

	const (
		goroutines = 8
		iterations = 50
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				key := "key"
				if id%2 == 0 {
					// Even goroutines write.
					_ = ec.Set(ctx, "ns", key, config.NewValue(i))
				} else {
					// Odd goroutines read (may miss, that is fine).
					_, _ = ec.Get(ctx, "ns", key)
				}
				if id == 0 && i == iterations/2 {
					// Simulate key rotation mid-run.
					newKey := make([]byte, 32)
					for j := range newKey {
						newKey[j] = byte(j + 50)
					}
					_ = ring.AddKey(newKey, "k2", 2)
					_ = ring.SetCurrentKey("k2")
				}
			}
		}(g)
	}
	wg.Wait()
}
