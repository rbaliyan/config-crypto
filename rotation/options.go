package rotation

import "time"

type options struct {
	namespaces   []string
	scanInterval time.Duration
	concurrency  int
	onError      func(namespace, key string, err error)
}

// Option configures an Orchestrator.
type Option func(*options)

// WithNamespaces sets the list of namespaces the background scan loop
// walks on each tick. Start fails if this is empty; ReencryptNamespace
// ignores this setting and operates on its explicit argument.
func WithNamespaces(ns ...string) Option {
	return func(o *options) { o.namespaces = ns }
}

// WithScanInterval sets the period between full scans of all configured
// namespaces. Default: 5 minutes. Zero or negative values are ignored.
func WithScanInterval(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.scanInterval = d
		}
	}
}

// WithConcurrency sets the number of worker goroutines used to re-encrypt
// stale values within a single namespace. Default: 4. Actual concurrency
// is capped at the number of stale values found per scan.
func WithConcurrency(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.concurrency = n
		}
	}
}

// WithErrorHandler sets a callback invoked for per-value and per-namespace
// errors during a scan. The callback is called from the background
// goroutine (and from the worker pool inside ReencryptNamespace) so it
// must be safe for concurrent use and must not block. The key is empty
// for namespace-level errors (e.g. a store.Find failure).
// If unset, errors are logged via slog.
func WithErrorHandler(fn func(namespace, key string, err error)) Option {
	return func(o *options) { o.onError = fn }
}
