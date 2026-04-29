package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rbaliyan/config"
)

// Compile-time interface check.
var _ config.Cache = (*EncryptedCache)(nil)

// encryptedCacheCodec is the sentinel codec name used for encrypted cache entries.
// It is intentionally not registered in the codec registry so the inner cache
// treats it as opaque bytes, preventing accidental decode attempts.
const encryptedCacheCodec = "crypto:cache"

// entrySchemaVersion is the current wire version of cacheEntry.
// Entries with a different V field are treated as cache misses so they are
// transparently re-fetched and re-written with the current schema. Bump this
// constant when a new field changes the interpretation of an existing entry
// (e.g. changing the encoding of an existing field). Pure additive fields whose
// zero value is safe to ignore on older readers do not require a bump.
const entrySchemaVersion = 1

// typeMax is the largest valid config.Type value. An entry whose Type field
// falls outside [0, typeMax] was produced by a bug and is rejected as corrupt.
const typeMax = int(config.TypeCustom)

// EncryptedCache wraps any config.Cache with transparent encryption using the
// supplied Provider. The full value payload (data bytes, codec name, type, entry
// ID, and metadata) is encrypted before being written to the inner cache, and
// decrypted on retrieval. This ensures credentials and other sensitive values are
// never stored in plaintext in external caches such as Redis, regardless of
// whether the backing store uses encryption at rest.
//
// EncryptedCache is safe for concurrent use by multiple goroutines.
//
// Error semantics:
//   - Cache misses, expired entries, and cryptographic failures (wrong key,
//     tampered ciphertext, corrupt payload, unknown schema version) return
//     config.ErrNotFound so the manager transparently re-fetches from the store.
//   - Entries not written by EncryptedCache (codec sentinel mismatch) are also
//     returned as config.ErrNotFound.
//   - Provider operational failures (e.g. ErrProviderClosed) are propagated as
//     real errors so callers can surface and handle them.
//
// Example:
//
//	provider, _ := crypto.NewProvider(keyBytes, "cache-key")
//	encCache, _ := crypto.NewEncryptedCache(
//	    configredis.NewCache(rdb, configredis.WithCacheTTL(5*time.Minute)),
//	    provider,
//	)
//	mgr, _ := config.New(
//	    config.WithStore(remoteStore),
//	    config.WithCache(encCache),
//	)
type EncryptedCache struct {
	inner  config.Cache
	p      Provider
	hits   atomic.Int64
	misses atomic.Int64
}

// cacheEntry is the plaintext envelope that is encrypted before storage.
// It captures everything needed to faithfully reconstruct a config.Value,
// including the storage-level entry ID used by store backends for pagination
// and conditional writes.
//
// V is a schema version field. All entries written by this package have V == 1.
// Entries with a different V are rejected as cache misses and re-fetched from the
// backing store, allowing safe evolution of the wire format over time.
//
// The short JSON field names (v, d, c, t, …) are part of the encrypted wire
// format. Do not rename them without bumping entrySchemaVersion.
type cacheEntry struct {
	V         int        `json:"v"`
	Data      []byte     `json:"d"`
	Codec     string     `json:"c"`
	Type      int        `json:"t"`
	EntryID   string     `json:"id,omitempty"`
	Version   int64      `json:"ver,omitempty"`
	CreatedAt time.Time  `json:"ca,omitempty"`
	UpdatedAt time.Time  `json:"ua,omitempty"`
	ExpiresAt *time.Time `json:"exp,omitempty"`
}

// NewEncryptedCache returns a cache that encrypts all values before writing them
// to inner and decrypts on retrieval. Returns an error if inner or p is nil.
func NewEncryptedCache(inner config.Cache, p Provider) (*EncryptedCache, error) {
	if inner == nil {
		return nil, fmt.Errorf("crypto: NewEncryptedCache inner cache is nil")
	}
	if p == nil {
		return nil, fmt.Errorf("crypto: NewEncryptedCache provider is nil")
	}
	return &EncryptedCache{inner: inner, p: p}, nil
}

// Set encrypts the value's full payload and stores the ciphertext in the inner cache.
// Only ExpiresAt is forwarded to the outer wrapper so the inner cache (e.g. Redis)
// can enforce TTL-based eviction without decrypting. All other metadata —
// including Version, CreatedAt, UpdatedAt, and EntryID — is kept exclusively
// inside the ciphertext to avoid leaking operational metadata in Redis plaintext.
func (c *EncryptedCache) Set(ctx context.Context, namespace, key string, value config.Value) error {
	data, err := value.Marshal(ctx)
	if err != nil {
		return fmt.Errorf("encrypted cache set: marshal: %w", err)
	}

	entry := cacheEntry{
		V:       entrySchemaVersion,
		Data:    data,
		Codec:   value.Codec(),
		Type:    int(value.Type()),
		EntryID: config.EntryID(value),
	}
	if meta := value.Metadata(); meta != nil {
		entry.Version = meta.Version()
		entry.CreatedAt = meta.CreatedAt()
		entry.UpdatedAt = meta.UpdatedAt()
		if !meta.ExpiresAt().IsZero() {
			t := meta.ExpiresAt()
			entry.ExpiresAt = &t
		}
	}

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encrypted cache set: encode entry: %w", err)
	}

	ciphertext, err := c.p.Encrypt(ctx, plaintext)
	if err != nil {
		return fmt.Errorf("encrypted cache set: encrypt: %w", err)
	}

	// Only ExpiresAt is forwarded to the outer value so the inner cache can
	// apply a matching TTL without having to decrypt the payload.
	opts := []config.ValueOption{config.WithValueType(config.TypeCustom)}
	if entry.ExpiresAt != nil {
		opts = append(opts, config.WithValueExpiresAt(*entry.ExpiresAt))
	}

	if err := c.inner.Set(ctx, namespace, key, config.NewRawValue(ciphertext, encryptedCacheCodec, opts...)); err != nil {
		return fmt.Errorf("encrypted cache set: inner set: %w", err)
	}
	return nil
}

// Get retrieves a value from the inner cache and decrypts it.
//
// Returns config.ErrNotFound for:
//   - Cache misses and expired entries.
//   - Cryptographic failures (wrong key after rotation, tampered ciphertext,
//     invalid or unsupported ciphertext format) — the manager re-fetches from
//     the store and the fresh value is re-encrypted with the current key.
//   - Corrupt payload (unknown schema version, out-of-range Type field,
//     malformed JSON) — same fallback behaviour.
//
// Returns a real error (not ErrNotFound) for provider operational failures
// such as ErrProviderClosed so callers can surface them rather than silently
// falling through to a potentially unavailable backend store.
func (c *EncryptedCache) Get(ctx context.Context, namespace, key string) (config.Value, error) {
	wrapped, err := c.inner.Get(ctx, namespace, key)
	if err != nil {
		c.misses.Add(1)
		return nil, err
	}

	// Reject entries not written by EncryptedCache before touching the crypto
	// layer. This catches direct writes to the inner store and future refactors
	// that bypass EncryptedCache.Set.
	if wrapped.Codec() != encryptedCacheCodec {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	ciphertext, err := wrapped.Marshal(ctx)
	if err != nil {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	plaintext, err := c.p.Decrypt(ctx, ciphertext)
	if err != nil {
		c.misses.Add(1)
		// Cryptographic and format failures are cache misses: the manager
		// re-fetches from the store and re-caches with the current key.
		// Provider operational failures (e.g. ErrProviderClosed) are
		// propagated so they remain visible to callers.
		if IsDecryptionFailed(err) || IsKeyNotFound(err) || IsInvalidFormat(err) || IsUnsupportedFormat(err) {
			return nil, config.ErrNotFound
		}
		return nil, fmt.Errorf("encrypted cache get: %w", err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	// Reject entries written by a future, incompatible schema version.
	// They are treated as misses so the manager re-fetches and re-caches with
	// the current schema, making rolling upgrades and downgrades transparent.
	if entry.V != entrySchemaVersion {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	// Reject entries whose Type field is outside the known enum range. This can
	// only occur due to a bug in the Set path since the payload is authenticated,
	// so corrupt-but-authentic entries are treated as misses rather than errors.
	if entry.Type < 0 || entry.Type > typeMax {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	opts := []config.ValueOption{config.WithValueType(config.Type(entry.Type))}
	if entry.Version > 0 || !entry.CreatedAt.IsZero() || !entry.UpdatedAt.IsZero() {
		opts = append(opts, config.WithValueMetadata(entry.Version, entry.CreatedAt, entry.UpdatedAt))
	}
	if entry.ExpiresAt != nil {
		opts = append(opts, config.WithValueExpiresAt(*entry.ExpiresAt))
	}
	if entry.EntryID != "" {
		opts = append(opts, config.WithValueEntryID(entry.EntryID))
	}

	v, err := config.NewValueFromBytes(ctx, entry.Data, entry.Codec, opts...)
	if err != nil {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	// Re-check expiry on the reconstructed value. The inner cache may enforce
	// per-entry TTL (e.g. Redis with a key-level TTL), but not all Cache
	// implementations do; this provides a last-line-of-defence guard.
	if config.IsExpired(v) {
		c.misses.Add(1)
		return nil, config.ErrNotFound
	}

	c.hits.Add(1)
	return v, nil
}

// Delete removes a cache entry from the inner cache.
func (c *EncryptedCache) Delete(ctx context.Context, namespace, key string) error {
	return c.inner.Delete(ctx, namespace, key)
}

// Stats returns cache statistics. Hits and Misses reflect post-decryption
// outcomes measured by EncryptedCache; Size, Capacity, and Evictions are
// sourced from the inner cache.
//
// A sudden miss-spike without a corresponding hit drop typically indicates key
// rotation: old ciphertext cannot be decrypted by the new provider, so each
// cached entry is re-fetched from the backing store and re-encrypted as it is
// accessed. This is expected behaviour during and shortly after a key rotation.
func (c *EncryptedCache) Stats() config.CacheStats {
	inner := c.inner.Stats()
	return config.CacheStats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Size:      inner.Size,
		Capacity:  inner.Capacity,
		Evictions: inner.Evictions,
	}
}
