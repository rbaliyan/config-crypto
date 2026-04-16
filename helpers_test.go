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
func mustNewProvider(t testing.TB, keyBytes []byte, id string) Provider {
	t.Helper()
	p, err := NewProvider(keyBytes, id)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// mustNewKeyRingProvider builds a KeyRingProvider or fatals.
// rank is the KV store version for the initial key; pass 0 when ordering is not needed.
func mustNewKeyRingProvider(t testing.TB, keyBytes []byte, id string, rank uint64) KeyRingProvider {
	t.Helper()
	p, err := NewKeyRingProvider(keyBytes, id, rank)
	if err != nil {
		t.Fatalf("NewKeyRingProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
