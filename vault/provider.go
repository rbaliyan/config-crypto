// Package vault provides a crypto.KeyRingProvider backed by a HashiCorp Vault
// KV v2 secret. Each version of the secret becomes one key; the version number
// (formatted via WithKeyIDFormat) is used as the key ID stored in encrypted
// headers.
//
// Usage:
//
//	client := myvault.NewClient(...)
//	ring, err := vault.New(ctx, client, "secret", "config-crypto/keys")
//	defer ring.Close()
//
//	// Optional: start background polling so new versions are picked up automatically.
//	stop, err := vault.Poll(ctx, client, ring, "secret", "config-crypto/keys",
//	    30*time.Second,
//	    vault.WithRefreshErrorHandler(func(err error) { log.Println(err) }),
//	)
//	defer stop()
package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	crypto "github.com/rbaliyan/config-crypto"
)

// Client abstracts Vault's KV v2 secrets engine read operations.
//
// Implementations should target the KV v2 API (versioned secrets). The mount
// is the engine mount point (e.g. "secret"); the path is the secret's logical
// path within the mount (e.g. "config-crypto/keys/main").
type Client interface {
	// KVMetadata lists all versions of the secret at mount/path and reports
	// the version number Vault considers current. Returned versions need not
	// be sorted.
	KVMetadata(ctx context.Context, mount, path string) (versions []int, current int, err error)

	// KVGet reads a specific version of the secret at mount/path and returns
	// its data map (field name -> string value).
	KVGet(ctx context.Context, mount, path string, version int) (map[string]string, error)
}

// Option configures New and Poll.
type Option func(*options)

type options struct {
	field          string
	keyIDFormat    func(version int) string
	onRefreshError func(error)
}

// WithField sets the field name within the KV secret data that holds the
// base64-encoded 32-byte AES-256 key. Default: "key".
func WithField(field string) Option {
	return func(o *options) { o.field = field }
}

// WithKeyIDFormat sets the function that maps a KV version number to a key
// ID stored in encrypted headers. The mapping must be deterministic and
// stable across restarts, otherwise old ciphertexts will fail to decrypt.
// Default: strconv.Itoa (versions become "1", "2", ...).
func WithKeyIDFormat(fn func(version int) string) Option {
	return func(o *options) { o.keyIDFormat = fn }
}

// WithRefreshErrorHandler sets a callback invoked when a background poll
// fails. The callback runs on the polling goroutine; it must be safe for
// concurrent use and must not block. If unset, errors are logged via slog.
// This option is only meaningful when passed to Poll.
func WithRefreshErrorHandler(fn func(error)) Option {
	return func(o *options) { o.onRefreshError = fn }
}

// New creates a crypto.KeyRingProvider backed by a Vault KV v2 secret.
//
// At construction, KVMetadata is called once to enumerate every version,
// each version is fetched, and the configured field is base64-decoded into
// the 32-byte AES-256 key. The version Vault reports as current becomes the
// provider's current key; remaining versions are registered as old keys for
// decryption.
//
// To automatically pick up new secret versions at runtime, call Poll after
// construction.
func New(ctx context.Context, client Client, mount, path string, opts ...Option) (crypto.KeyRingProvider, error) {
	if client == nil {
		return nil, errors.New("vault: Client must not be nil")
	}
	if mount == "" {
		return nil, errors.New("vault: mount must not be empty")
	}
	if path == "" {
		return nil, errors.New("vault: path must not be empty")
	}

	o := options{
		field:       "key",
		keyIDFormat: strconv.Itoa,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.field == "" {
		return nil, errors.New("vault: field must not be empty")
	}
	if o.keyIDFormat == nil {
		return nil, errors.New("vault: keyIDFormat must not be nil")
	}

	versions, current, err := client.KVMetadata(ctx, mount, path)
	if err != nil {
		return nil, fmt.Errorf("vault: list KV versions for %s/%s: %w", mount, path, err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("vault: KV secret %s/%s has no versions", mount, path)
	}
	if !slices.Contains(versions, current) {
		return nil, fmt.Errorf("vault: KV current version %d not in metadata version list", current)
	}

	type fetched struct {
		bytes   []byte
		id      string
		version int
	}
	keys := make([]fetched, 0, len(versions))
	defer func() {
		for _, k := range keys {
			clear(k.bytes)
		}
	}()

	sortedVersions := append([]int(nil), versions...)
	sort.Ints(sortedVersions)

	for _, v := range sortedVersions {
		b, err := fetchKeyVersion(ctx, client, mount, path, v, o.field)
		if err != nil {
			return nil, err
		}
		keys = append(keys, fetched{bytes: b, id: o.keyIDFormat(v), version: v})
	}

	// Build a KeyRingProvider with current key and old keys for decryption.
	// KV version numbers are used as ranks so NeedsReencryption ordering is
	// stable across restarts.
	currentID := o.keyIDFormat(current)
	var currentBytes []byte
	for _, k := range keys {
		if k.version == current {
			currentBytes = k.bytes
			break
		}
	}

	ring, err := crypto.NewKeyRingProvider(currentBytes, currentID, uint64(current)) // #nosec G115 -- Vault KV versions are always positive
	if err != nil {
		return nil, fmt.Errorf("vault: build key ring: %w", err)
	}
	for _, k := range keys {
		if k.version == current {
			continue
		}
		if err := ring.AddKey(k.bytes, k.id, uint64(k.version)); err != nil { // #nosec G115 -- Vault KV versions are always positive
			return nil, fmt.Errorf("vault: add key version %d: %w", k.version, err)
		}
	}
	return ring, nil
}

// Poll starts a background goroutine that polls Vault KV metadata at the
// given interval and adds any newly-seen versions to ring. It performs an
// initial metadata read to seed the set of already-known versions; this read
// failing returns an error immediately.
//
// The returned stop function cancels the goroutine and blocks until it exits.
// Callers should defer stop() after a successful Poll call.
//
// The WithField and WithKeyIDFormat options passed to Poll must match those
// passed to New; mismatched options will cause the poller to look for the
// wrong field name or derive different key IDs, silently corrupting the ring.
// WithRefreshErrorHandler is the only Poll-specific option.
//
// Per-version fetch failures are retried up to maxVersionRetries times;
// after that the version is permanently skipped for the lifetime of the
// goroutine (until the process restarts). Errors are reported via
// WithRefreshErrorHandler or logged via slog.
func Poll(ctx context.Context, client Client, ring crypto.KeyRingProvider, mount, path string, interval time.Duration, opts ...Option) (func(), error) {
	if client == nil {
		return nil, errors.New("vault: Poll: Client must not be nil")
	}
	if ring == nil {
		return nil, errors.New("vault: Poll: ring must not be nil")
	}
	if mount == "" {
		return nil, errors.New("vault: Poll: mount must not be empty")
	}
	if path == "" {
		return nil, errors.New("vault: Poll: path must not be empty")
	}
	if interval <= 0 {
		return nil, errors.New("vault: Poll: interval must be positive")
	}

	o := options{
		field:       "key",
		keyIDFormat: strconv.Itoa,
	}
	for _, opt := range opts {
		opt(&o)
	}

	// Seed known versions so the poller doesn't re-fetch what's already loaded.
	versions, current, err := client.KVMetadata(ctx, mount, path)
	if err != nil {
		return nil, fmt.Errorf("vault: Poll initial metadata: %w", err)
	}

	known := make(map[int]struct{}, len(versions))
	for _, v := range versions {
		known[v] = struct{}{}
	}

	pollCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runKVPoll(pollCtx, client, ring, mount, path, known, current, interval, o)
	}()

	stop := func() {
		cancel()
		wg.Wait()
	}
	return stop, nil
}

// fetchKeyVersion reads one secret version and decodes its base64 key field.
func fetchKeyVersion(ctx context.Context, client Client, mount, path string, version int, field string) ([]byte, error) {
	data, err := client.KVGet(ctx, mount, path, version)
	if err != nil {
		return nil, fmt.Errorf("vault: read KV %s/%s version %d: %w", mount, path, version, err)
	}
	encoded, ok := data[field]
	if !ok {
		return nil, fmt.Errorf("vault: KV %s/%s version %d: missing field %q", mount, path, version, field)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("vault: KV %s/%s version %d: decode field %q: %w", mount, path, version, field, err)
	}
	if len(keyBytes) != 32 {
		clear(keyBytes)
		return nil, fmt.Errorf("vault: KV %s/%s version %d: key is %d bytes, want 32", mount, path, version, len(keyBytes))
	}
	return keyBytes, nil
}

// maxVersionRetries bounds how many times the poller will retry a single KV
// version before giving up on it.
const maxVersionRetries = 5

// runKVPoll polls KV metadata at interval and adds any newly-seen versions to
// ring. Per-version failures are retried up to maxVersionRetries times; after
// that the version is permanently skipped. Exits when ctx is canceled.
func runKVPoll(ctx context.Context, client Client, ring crypto.KeyRingProvider, mount, path string, known map[int]struct{}, lastCurrent int, interval time.Duration, o options) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failed := make(map[int]struct{})
	retries := make(map[int]int)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		versions, current, err := client.KVMetadata(ctx, mount, path)
		if err != nil {
			reportRefreshErr(o, fmt.Errorf("vault: poll KV metadata: %w", err))
			continue
		}

		var newVersions []int
		for _, v := range versions {
			if _, ok := known[v]; ok {
				continue
			}
			if _, ok := failed[v]; ok {
				continue
			}
			newVersions = append(newVersions, v)
		}
		sort.Ints(newVersions)

		for _, v := range newVersions {
			keyBytes, err := fetchKeyVersion(ctx, client, mount, path, v, o.field)
			if err != nil {
				retries[v]++
				if retries[v] >= maxVersionRetries {
					failed[v] = struct{}{}
					delete(retries, v)
					reportRefreshErr(o, fmt.Errorf("vault: giving up on KV version %d after %d retries: %w", v, maxVersionRetries, err))
				} else {
					reportRefreshErr(o, err)
				}
				continue
			}
			id := o.keyIDFormat(v)
			err = ring.AddKey(keyBytes, id, uint64(v)) // #nosec G115 -- Vault KV versions are always positive
			clear(keyBytes)
			if err != nil {
				if crypto.IsProviderClosed(err) {
					return
				}
				retries[v]++
				if retries[v] >= maxVersionRetries {
					failed[v] = struct{}{}
					delete(retries, v)
					reportRefreshErr(o, fmt.Errorf("vault: giving up on KV version %d after %d retries: %w", v, maxVersionRetries, err))
				} else {
					reportRefreshErr(o, fmt.Errorf("vault: register KV key version %d: %w", v, err))
				}
				continue
			}
			known[v] = struct{}{}
			delete(retries, v)
		}

		// Skip promotion if Vault's current version is one we've given up on.
		if _, isFailed := failed[current]; isFailed {
			continue
		}

		if current != lastCurrent {
			id := o.keyIDFormat(current)
			if err := ring.SetCurrentKey(id); err != nil {
				if crypto.IsProviderClosed(err) {
					return
				}
				reportRefreshErr(o, fmt.Errorf("vault: promote KV current to version %d: %w", current, err))
				continue
			}
			lastCurrent = current
		}
	}
}

func reportRefreshErr(o options, err error) {
	if o.onRefreshError != nil {
		o.onRefreshError(err)
		return
	}
	slog.Default().Error("vault: KV refresh failed", "error", err)
}
