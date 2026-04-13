package crypto

import "testing"

// makeKey returns a deterministic key of the given size with a sequential pattern.
// Use only in tests.
func makeKey(size int) []byte {
	k := make([]byte, size)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// mustNewProvider builds a Provider from raw bytes or fatals.
func mustNewProvider(t testing.TB, keyBytes []byte, id string, opts ...Option) Provider {
	t.Helper()
	p, err := NewProvider(keyBytes, id, opts...)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// mustNewRotatingProvider builds a RotatingProvider or fatals.
func mustNewRotatingProvider(t testing.TB, keyBytes []byte, id string, opts ...Option) *RotatingProvider {
	t.Helper()
	p, err := NewRotatingProvider(keyBytes, id, opts...)
	if err != nil {
		t.Fatalf("NewRotatingProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
