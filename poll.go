package crypto

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Poll drives generic, backend-agnostic key rotation against any
// KeyRingProvider. The caller supplies a FetchFn that enumerates the
// current set of key versions from their KMS of choice; Poll compares the
// result against the versions already in the ring on each tick, adds any
// new versions, and promotes the one flagged IsCurrent to be the active
// encryption key.
//
// Poll is the generic counterpart to vault.Poll. vault.Poll is a
// specialisation that sources versions directly from Vault's KV v2
// metadata/get APIs and does not require the caller to write a FetchFn.
// Use Poll (together with the NewPoller helpers in awskms, gcpkms, and
// azurekv) when driving rotation against any other backend, or when you
// want full control over how versions are enumerated.

// KeyVersion is a single key version returned by a FetchFn.
type KeyVersion struct {
	ID        string // stable identifier (used as key ID in encrypted headers)
	Bytes     []byte // 32-byte AES-256 key material
	Rank      uint64 // ordering rank for NeedsReencryption; higher = newer
	IsCurrent bool   // true if this version should be the active encryption key
}

// FetchFn retrieves the current set of key versions from a KMS.
// It must be idempotent: returning the same version multiple times is safe.
// Returning versions already known to the ring is safe — Poll skips them.
type FetchFn func(ctx context.Context) ([]KeyVersion, error)

// PollOption configures Poll.
type PollOption func(*pollOptions)

type pollOptions struct {
	onError    func(error)
	maxRetries int
}

// WithPollErrorHandler sets a callback for poll errors (fetch failures, AddKey
// failures). The callback runs on the polling goroutine and must not block.
// If unset, errors are logged via slog.
func WithPollErrorHandler(fn func(error)) PollOption {
	return func(o *pollOptions) { o.onError = fn }
}

// WithPollMaxRetries sets the per-version retry cap. After this many failures,
// the version is permanently skipped for the lifetime of the goroutine.
// Default is 5.
func WithPollMaxRetries(n int) PollOption {
	return func(o *pollOptions) {
		if n > 0 {
			o.maxRetries = n
		}
	}
}

// Poll starts a background goroutine that calls fetchFn at interval, adding
// any newly-seen key versions to ring and promoting the current key.
//
// An initial fetch is performed before the ticker starts; if it fails, Poll
// returns an error immediately (fail-fast at startup).
//
// The returned stop function cancels the goroutine and blocks until it exits.
// Callers should defer stop() after a successful Poll call.
func Poll(ctx context.Context, ring KeyRingProvider, interval time.Duration, fetchFn FetchFn, opts ...PollOption) (func(), error) {
	if ring == nil {
		return nil, errors.New("crypto: Poll: ring must not be nil")
	}
	if interval <= 0 {
		return nil, errors.New("crypto: Poll: interval must be positive")
	}
	if fetchFn == nil {
		return nil, errors.New("crypto: Poll: fetchFn must not be nil")
	}

	o := pollOptions{maxRetries: 5}
	for _, opt := range opts {
		opt(&o)
	}

	versions, err := fetchFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("crypto: Poll initial fetch: %w", err)
	}

	// Sort by rank ascending so older versions are added before newer ones.
	sort.Slice(versions, func(i, j int) bool { return versions[i].Rank < versions[j].Rank })

	known := make(map[string]struct{}, len(versions))
	failed := make(map[string]struct{})
	var lastCurrentID string

	for _, v := range versions {
		// AddKey will return an error for versions already in the ring
		// (e.g. the initial key passed to NewKeyRingProvider). Treat that
		// as "known" — the version is present, we just didn't add it here.
		keyBytes := make([]byte, len(v.Bytes))
		copy(keyBytes, v.Bytes)
		addErr := ring.AddKey(keyBytes, v.ID, v.Rank)
		clear(keyBytes)
		if addErr != nil {
			if IsProviderClosed(addErr) {
				return nil, fmt.Errorf("crypto: Poll initial add %q: %w", v.ID, addErr)
			}
			// Duplicate-ID errors are expected for versions already in the
			// ring; we still mark them known. Other errors are fatal at
			// startup (fail-fast semantics).
			if !IsDuplicateKeyID(addErr) {
				return nil, fmt.Errorf("crypto: Poll initial add %q: %w", v.ID, addErr)
			}
		}
		known[v.ID] = struct{}{}
		if v.IsCurrent {
			lastCurrentID = v.ID
		}
	}

	if lastCurrentID != "" {
		if err := ring.SetCurrentKey(lastCurrentID); err != nil && !IsProviderClosed(err) {
			reportPollErr(&o, fmt.Errorf("crypto: Poll initial promote %q: %w", lastCurrentID, err))
		}
	}

	pollCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runPoll(pollCtx, ring, fetchFn, known, failed, lastCurrentID, interval, &o)
	}()

	stop := func() {
		cancel()
		wg.Wait()
	}
	return stop, nil
}

func runPoll(ctx context.Context, ring KeyRingProvider, fetchFn FetchFn, known, failed map[string]struct{}, lastCurrentID string, interval time.Duration, o *pollOptions) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	retries := make(map[string]int)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		versions, err := fetchFn(ctx)
		if err != nil {
			reportPollErr(o, err)
			continue
		}

		var newVersions []KeyVersion
		for _, v := range versions {
			if _, ok := known[v.ID]; ok {
				continue
			}
			if _, ok := failed[v.ID]; ok {
				continue
			}
			newVersions = append(newVersions, v)
		}
		sort.Slice(newVersions, func(i, j int) bool { return newVersions[i].Rank < newVersions[j].Rank })

		for _, v := range newVersions {
			keyBytes := make([]byte, len(v.Bytes))
			copy(keyBytes, v.Bytes)
			err := ring.AddKey(keyBytes, v.ID, v.Rank)
			clear(keyBytes)
			if err != nil {
				if IsProviderClosed(err) {
					return
				}
				retries[v.ID]++
				if retries[v.ID] >= o.maxRetries {
					failed[v.ID] = struct{}{}
					delete(retries, v.ID)
					reportPollErr(o, fmt.Errorf("poll: giving up on key version %q after %d retries: %w", v.ID, o.maxRetries, err))
				} else {
					reportPollErr(o, fmt.Errorf("poll: add key version %q: %w", v.ID, err))
				}
				continue
			}
			known[v.ID] = struct{}{}
			delete(retries, v.ID)
		}

		var newCurrentID string
		for _, v := range versions {
			if _, ok := failed[v.ID]; ok {
				continue
			}
			if v.IsCurrent {
				newCurrentID = v.ID
				break
			}
		}
		if newCurrentID != "" && newCurrentID != lastCurrentID {
			if err := ring.SetCurrentKey(newCurrentID); err != nil {
				if IsProviderClosed(err) {
					return
				}
				reportPollErr(o, fmt.Errorf("poll: promote current key to %q: %w", newCurrentID, err))
				continue
			}
			lastCurrentID = newCurrentID
		}
	}
}

func reportPollErr(o *pollOptions, err error) {
	if o.onError != nil {
		o.onError(err)
		return
	}
	slog.Default().Error("config-crypto: poll failed", "error", err)
}
