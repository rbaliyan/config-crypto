// Package vault provides a crypto.Provider backed by a HashiCorp Vault KV v2
// secret. Each version of the secret becomes one key; the version number
// (formatted via WithKeyIDFormat) is used as the key ID stored in encrypted
// headers. New secret versions are picked up by an optional background
// poll (WithKeyVersionRefreshInterval).
//
// Usage:
//
//	client := myvault.NewClient(...)
//	provider, err := vault.New(ctx, client, "secret", "config-crypto/keys",
//	    vault.WithKeyVersionRefreshInterval(30*time.Second),
//	)
//	defer provider.Close()
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

// Option configures New.
type Option func(*options)

type options struct {
	field           string
	keyIDFormat     func(version int) string
	refreshInterval time.Duration
	onRefreshError  func(error)
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

// WithKeyVersionRefreshInterval enables background polling of KV metadata.
// When a new version appears, it is fetched, registered, and promoted to
// current. A non-positive interval disables polling (the default).
func WithKeyVersionRefreshInterval(d time.Duration) Option {
	return func(o *options) { o.refreshInterval = d }
}

// WithRefreshErrorHandler sets a callback invoked when a background poll
// fails. The callback runs on the polling goroutine; it must be safe for
// concurrent use and must not block. If unset, errors are logged via slog.
func WithRefreshErrorHandler(fn func(error)) Option {
	return func(o *options) { o.onRefreshError = fn }
}

// New creates a crypto.Provider backed by a Vault KV v2 secret.
//
// At construction, KVMetadata is called once to enumerate every version,
// each version is fetched, and the configured field is base64-decoded into
// the 32-byte AES-256 key. The version Vault reports as current becomes the
// provider's current key; remaining versions are added as old keys for
// decryption.
//
// If WithKeyVersionRefreshInterval is set to a positive duration, a
// background goroutine polls KVMetadata at that interval. New versions are
// registered and promoted automatically. The goroutine exits when ctx is
// canceled or Close is called on the returned Provider.
func New(ctx context.Context, client Client, mount, path string, opts ...Option) (crypto.Provider, error) {
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

	// Build a RotatingProvider with current key and old-key options.
	currentID := o.keyIDFormat(current)
	var currentBytes []byte
	dynOpts := make([]crypto.Option, 0, len(keys)-1)
	for _, k := range keys {
		if k.version == current {
			currentBytes = k.bytes
			continue
		}
		dynOpts = append(dynOpts, crypto.WithOldKey(k.bytes, k.id))
	}

	rp, err := crypto.NewRotatingProvider(currentBytes, currentID, dynOpts...)
	if err != nil {
		return nil, fmt.Errorf("vault: build rotating provider: %w", err)
	}

	p := &provider{rp: rp, client: client, mount: mount, path: path}
	if o.refreshInterval > 0 {
		known := make(map[int]struct{}, len(sortedVersions))
		for _, v := range sortedVersions {
			known[v] = struct{}{}
		}
		pollCtx, cancel := context.WithCancel(ctx)
		p.cancelPoll = cancel
		p.wg.Go(func() {
			runKVPoll(pollCtx, client, rp, mount, path, known, current, o)
		})
	}
	return p, nil
}

// provider wraps a *crypto.RotatingProvider with the optional polling
// goroutine lifecycle. Encrypt and Decrypt forward to the inner provider;
// Close stops polling and closes the inner. HealthCheck verifies both the
// inner state and connectivity to Vault.
type provider struct {
	rp         *crypto.RotatingProvider
	client     Client
	mount      string
	path       string
	cancelPoll context.CancelFunc
	wg         sync.WaitGroup
}

func (p *provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return p.rp.Encrypt(ctx, plaintext)
}

func (p *provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return p.rp.Decrypt(ctx, ciphertext)
}

// HealthCheck verifies the inner provider is open and that Vault is reachable
// by issuing a KVMetadata call against the configured secret. The ctx
// deadline bounds the Vault round-trip.
func (p *provider) HealthCheck(ctx context.Context) error {
	if err := p.rp.HealthCheck(ctx); err != nil {
		return err
	}
	if _, _, err := p.client.KVMetadata(ctx, p.mount, p.path); err != nil {
		return fmt.Errorf("vault: HealthCheck KVMetadata: %w", err)
	}
	return nil
}

func (p *provider) Close() error {
	if p.cancelPoll != nil {
		p.cancelPoll()
	}
	p.wg.Wait()
	return p.rp.Close()
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
// version before giving up on it. Permanent failures (malformed key material,
// wrong size, etc.) hit this limit and are skipped on subsequent ticks.
const maxVersionRetries = 5

// runKVPoll polls KV metadata at o.refreshInterval and adds any newly-seen
// versions to the provider. Per-version failures are retried up to
// maxVersionRetries times; after that the version is marked failed and
// permanently skipped. Exits when ctx is canceled or the provider is closed.
func runKVPoll(ctx context.Context, client Client, rp *crypto.RotatingProvider, mount, path string, known map[int]struct{}, lastCurrent int, o options) {
	ticker := time.NewTicker(o.refreshInterval)
	defer ticker.Stop()

	failed := make(map[int]struct{})  // versions we've permanently given up on
	retries := make(map[int]int)      // in-flight retry counter per version

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

		newVersions := make([]int, 0)
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
			err = rp.AddKey(keyBytes, id)
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

		// Skip promotion if Vault's current version is one we've given up on —
		// it'll never be in the rotating provider, and retrying SetCurrentKey
		// every tick would spam errors forever.
		if _, isFailed := failed[current]; isFailed {
			continue
		}

		if current != lastCurrent {
			id := o.keyIDFormat(current)
			if err := rp.SetCurrentKey(id); err != nil {
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
