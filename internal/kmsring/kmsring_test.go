package kmsring

import (
	"context"
	"fmt"
	"testing"
)

func makeKey(seed byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// TestBuild_RingLookupAndDecrypt builds a ring from N fake encrypted keys and
// verifies the first key is current while every key can decrypt its own
// ciphertext through the ring.
func TestBuild_RingLookupAndDecrypt(t *testing.T) {
	ctx := context.Background()

	// Three "encrypted" keys; the unwrap closure just returns deterministic bytes.
	ids := []string{"key-1", "key-2", "key-3"}
	plain := [][]byte{makeKey(1), makeKey(2), makeKey(3)}

	ring, err := Build(len(ids), "test", func(i int) ([]byte, string, error) {
		// Return a fresh copy each call; Build zeroes what it is handed.
		b := make([]byte, len(plain[i]))
		copy(b, plain[i])
		return b, ids[i], nil
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer ring.Close()

	// First key added is current.
	if got := ring.CurrentKeyID(); got != ids[0] {
		t.Errorf("CurrentKeyID = %q, want %q", got, ids[0])
	}

	// The current key round-trips through the ring.
	ct, err := ring.Encrypt(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := ring.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("decrypt got %q", got)
	}

	// Switch to each of the other keys and confirm they too round-trip,
	// proving all N keys were added.
	for _, id := range ids[1:] {
		if err := ring.SetCurrentKey(id); err != nil {
			t.Fatalf("SetCurrentKey %q: %v", id, err)
		}
		ct, err := ring.Encrypt(ctx, []byte("x-"+id))
		if err != nil {
			t.Fatalf("Encrypt under %q: %v", id, err)
		}
		out, err := ring.Decrypt(ctx, ct)
		if err != nil {
			t.Fatalf("Decrypt under %q: %v", id, err)
		}
		if string(out) != "x-"+id {
			t.Errorf("decrypt under %q got %q", id, out)
		}
	}
}

// TestBuild_ZeroesDecryptedInput verifies Build zeroes the plaintext byte
// slices it is handed (on the success path, after copying into the ring).
func TestBuild_ZeroesDecryptedInput(t *testing.T) {
	pt := makeKey(7)
	ring, err := Build(1, "test", func(_ int) ([]byte, string, error) {
		return pt, "key-1", nil
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer ring.Close()

	for i, b := range pt {
		if b != 0 {
			t.Fatalf("decrypted input not zeroed at index %d: %d", i, b)
		}
	}
}

// TestBuild_WrongKeySizeZeroesInput verifies a wrong-length plaintext is
// rejected and zeroed before the error is returned.
func TestBuild_WrongKeySizeZeroesInput(t *testing.T) {
	pt := make([]byte, 16) // not KeySize
	for i := range pt {
		pt[i] = byte(i + 1)
	}
	_, err := Build(1, "test", func(_ int) ([]byte, string, error) {
		return pt, "key-1", nil
	})
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
	for i, b := range pt {
		if b != 0 {
			t.Fatalf("rejected input not zeroed at index %d: %d", i, b)
		}
	}
}

func TestBuild_ZeroCount(t *testing.T) {
	if _, err := Build(0, "test", func(int) ([]byte, string, error) { return nil, "", nil }); err == nil {
		t.Error("expected error for count < 1")
	}
}

func TestBuild_UnwrapError(t *testing.T) {
	_, err := Build(1, "test", func(int) ([]byte, string, error) {
		return nil, "key-1", fmt.Errorf("boom")
	})
	if err == nil {
		t.Error("expected error when unwrap fails")
	}
}
