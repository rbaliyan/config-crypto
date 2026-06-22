package crypto

import (
	"errors"
	"fmt"
	"testing"
)

// TestErrorPredicates exercises every Is* helper against its own sentinel,
// a foreign error, and a wrapped form of the sentinel.
func TestErrorPredicates(t *testing.T) {
	t.Parallel()
	other := errors.New("some unrelated error")

	cases := []struct {
		name     string
		sentinel error
		pred     func(error) bool
	}{
		{"KeyNotFound", ErrKeyNotFound, IsKeyNotFound},
		{"InvalidKeySize", ErrInvalidKeySize, IsInvalidKeySize},
		{"InvalidFormat", ErrInvalidFormat, IsInvalidFormat},
		{"UnsupportedFormat", ErrUnsupportedFormat, IsUnsupportedFormat},
		{"DecryptionFailed", ErrDecryptionFailed, IsDecryptionFailed},
		{"InvalidKeyID", ErrInvalidKeyID, IsInvalidKeyID},
		{"ProviderClosed", ErrProviderClosed, IsProviderClosed},
		{"RemoveCurrentKey", ErrRemoveCurrentKey, IsRemoveCurrentKey},
		{"NoProviderForNamespace", ErrNoProviderForNamespace, IsNoProviderForNamespace},
		{"DuplicateKeyID", ErrDuplicateKeyID, IsDuplicateKeyID},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if !c.pred(c.sentinel) {
				t.Errorf("%s: predicate returned false for its own sentinel", c.name)
			}
			if c.pred(other) {
				t.Errorf("%s: predicate returned true for an unrelated error", c.name)
			}
			if c.pred(nil) {
				t.Errorf("%s: predicate returned true for nil", c.name)
			}
			wrapped := fmt.Errorf("context: %w", c.sentinel)
			if !c.pred(wrapped) {
				t.Errorf("%s: predicate returned false for a wrapped sentinel", c.name)
			}
		})
	}
}
