// Package rotation provides a background Orchestrator that re-encrypts
// stored configuration values whose encryption key is no longer the
// current version of the ring.
//
// When a key is rotated (via crypto.Poll, vault.Poll, or manual
// ring.SetCurrentKey), existing ciphertext is still readable because the
// key ID is embedded in the envelope header and the ring retains older
// keys for decryption. New writes automatically use the current key, but
// previously-written ciphertext is never touched. Orchestrator closes
// that gap: on each scan it enumerates configured namespaces, filters to
// values whose codec is "encrypted:*", asks the ring via
// KeyRingProvider.NeedsReencryption whether a value's key rank is below
// the current rank, and rewrites stale values with the current key.
//
// Usage:
//
//	orch, err := rotation.NewOrchestrator(ring, store, encryptedCodec,
//	    rotation.WithNamespaces("production", "staging"),
//	    rotation.WithScanInterval(time.Hour),
//	    rotation.WithConcurrency(4),
//	)
//	if err != nil { return err }
//	stop, err := orch.Start(ctx)
//	if err != nil { return err }
//	defer stop()
package rotation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rbaliyan/config"
	crypto "github.com/rbaliyan/config-crypto"
)

// Orchestrator periodically scans the configured namespaces and re-encrypts
// any values whose data encryption key (DEK) is no longer the current key
// version. It is intended for rolling out KMS-driven key rotation without
// blocking operational traffic.
//
// Re-encryption is triggered by KeyRingProvider.NeedsReencryption, which
// returns true when the stored ciphertext's key rank is strictly below
// the current key's rank. Values written with the current key are left
// untouched.
//
// Lifecycle:
//   - NewOrchestrator validates inputs and returns a ready-but-idle instance.
//   - Start launches a single background goroutine that ticks at
//     WithScanInterval and, for each configured namespace, calls
//     ReencryptNamespace. Start may only be called once per Orchestrator.
//   - The stop function returned by Start cancels the goroutine and blocks
//     until it exits; after stop returns, no further Watch / Find / Set
//     calls will be issued. Callers should defer stop().
//
// ReencryptNamespace is safe to call concurrently, including while the
// background loop is running, and may be used to force an immediate scan.
type Orchestrator struct {
	ring    crypto.KeyRingProvider
	store   config.Store
	codec   *crypto.Codec
	opts    options
	started atomic.Bool
}

// NewOrchestrator creates an Orchestrator. ring is used both to detect
// stale ciphertext (NeedsReencryption) and to encrypt the rewritten
// values via codec. store is the config.Store that holds encrypted
// values; values are read and written back through it. codec is the
// encrypting codec previously constructed with crypto.NewCodec(ring, ...)
// — its Transform / Reverse methods are used to re-encrypt in place.
//
// All three parameters are required. NewOrchestrator returns an error if
// any is nil. Use the Option functions to configure namespaces, scan
// cadence, worker concurrency, and the error handler.
func NewOrchestrator(
	ring crypto.KeyRingProvider,
	store config.Store,
	codec *crypto.Codec,
	opts ...Option,
) (*Orchestrator, error) {
	if ring == nil {
		return nil, fmt.Errorf("rotation: ring must not be nil")
	}
	if store == nil {
		return nil, fmt.Errorf("rotation: store must not be nil")
	}
	if codec == nil {
		return nil, fmt.Errorf("rotation: codec must not be nil")
	}

	o := options{
		scanInterval: 5 * time.Minute,
		concurrency:  4,
	}
	for _, opt := range opts {
		opt(&o)
	}

	return &Orchestrator{ring: ring, store: store, codec: codec, opts: o}, nil
}

// Start begins the background re-encryption scan loop. The returned stop
// function cancels the goroutine and blocks until it exits; callers should
// defer stop() after a successful Start call.
//
// Start may only be called once per Orchestrator; subsequent calls return an
// error.
func (o *Orchestrator) Start(ctx context.Context) (stop func(), err error) {
	if len(o.opts.namespaces) == 0 {
		return nil, fmt.Errorf("rotation: Start requires WithNamespaces — no namespaces configured")
	}
	if !o.started.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("rotation: Start already called on this Orchestrator")
	}

	pollCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.runScanLoop(pollCtx)
	}()

	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			cancel()
			wg.Wait()
		})
	}, nil
}

// ReencryptNamespace performs a single pass over namespace, re-encrypting
// any encrypted value whose key rank is below the current ring key. It
// returns the number of values successfully re-encrypted. Per-value
// failures (marshal, decrypt, reencrypt, or Set errors) are routed through
// the configured error handler (see WithErrorHandler) and do not abort
// the scan. The returned error is non-nil only for namespace-level failures
// such as a store.Find error.
//
// Safe to call concurrently with the background scan started by Start.
func (o *Orchestrator) ReencryptNamespace(ctx context.Context, namespace string) (int, error) {
	type staleKey struct {
		key   string
		value config.Value
	}
	var stale []staleKey

	cursor := ""
	for {
		fb := config.NewFilter().WithLimit(100)
		if cursor != "" {
			fb = fb.WithCursor(cursor)
		}

		page, err := o.store.Find(ctx, namespace, fb.Build())
		if err != nil {
			return 0, fmt.Errorf("rotation: find %q: %w", namespace, err)
		}

		for key, val := range page.Results() {
			if !strings.Contains(val.Codec(), "encrypted:") {
				continue
			}

			raw, err := val.Marshal(ctx)
			if err != nil {
				o.reportErr(namespace, key, fmt.Errorf("marshal during scan: %w", err))
				continue
			}

			needs, err := o.ring.NeedsReencryption(raw)
			if err != nil {
				o.reportErr(namespace, key, fmt.Errorf("needs-reencryption check: %w", err))
				continue
			}
			if !needs {
				continue
			}

			stale = append(stale, staleKey{key: key, value: val})
		}

		cursor = page.NextCursor()
		if cursor == "" {
			break
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}

	if len(stale) == 0 {
		return 0, nil
	}

	type result struct {
		key string
		err error
	}
	work := make(chan staleKey, len(stale))
	for _, sk := range stale {
		work <- sk
	}
	close(work)

	results := make(chan result, len(stale))
	var wg sync.WaitGroup

	nWorkers := o.opts.concurrency
	if nWorkers > len(stale) {
		nWorkers = len(stale)
	}

	for range nWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sk := range work {
				err := o.reencryptKey(ctx, namespace, sk.key, sk.value)
				results <- result{key: sk.key, err: err}
			}
		}()
	}

	wg.Wait()
	close(results)

	count := 0
	for r := range results {
		if r.err != nil {
			o.reportErr(namespace, r.key, r.err)
		} else {
			count++
		}
	}
	return count, nil
}

func (o *Orchestrator) reencryptKey(ctx context.Context, namespace, key string, val config.Value) error {
	raw, err := val.Marshal(ctx)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	plaintext, err := o.codec.Reverse(ctx, raw)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	defer clear(plaintext)

	newRaw, err := o.codec.Transform(ctx, plaintext)
	if err != nil {
		return fmt.Errorf("reencrypt: %w", err)
	}

	newVal := config.NewRawValue(newRaw, val.Codec())

	_, err = o.store.Set(ctx, namespace, key, newVal)
	return err
}

func (o *Orchestrator) runScanLoop(ctx context.Context) {
	ticker := time.NewTicker(o.opts.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, ns := range o.opts.namespaces {
				if ctx.Err() != nil {
					return
				}
				if _, err := o.ReencryptNamespace(ctx, ns); err != nil {
					o.reportErr(ns, "", err)
				}
			}
		}
	}
}

func (o *Orchestrator) reportErr(namespace, key string, err error) {
	if o.opts.onError != nil {
		o.opts.onError(namespace, key, err)
		return
	}
	slog.Default().Error("rotation: re-encrypt failed", "namespace", namespace, "key", key, "error", err)
}
