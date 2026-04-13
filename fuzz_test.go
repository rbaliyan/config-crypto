package crypto

import (
	"context"
	"testing"
)

func FuzzReadHeader(f *testing.F) {
	// v1 seeds.
	f.Add([]byte("EC\x01\x01\x00" + string(make([]byte, 72))))
	f.Add([]byte("EC\x01\x01\x03key" + string(make([]byte, 72))))
	// v2 seeds.
	f.Add([]byte("EC\x02\x01\x01\x00" + string(make([]byte, gcmNonceSize+2+encryptedDEKSize+gcmNonceSize))))
	// Bad inputs.
	f.Add([]byte("EC"))
	f.Add([]byte(""))
	f.Add([]byte("XX\x01\x01\x00"))
	f.Add([]byte("EC\x99\x01\x00"))
	f.Add([]byte("EC\x01\x02\x00"))
	f.Add([]byte("EC\x01\x01\xff"))
	f.Add([]byte{0x45, 0x43, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readHeader(data)
	})
}

func FuzzDecrypt(f *testing.F) {
	keyBytes := makeKey(32)
	p, err := NewProvider(keyBytes, "fuzz-key")
	if err != nil {
		f.Fatal(err)
	}
	encrypted, err := p.Encrypt(context.Background(), []byte("hello world"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(encrypted)
	f.Add([]byte(""))
	f.Add([]byte("EC\x01\x01\x00"))
	f.Add([]byte("not encrypted"))
	f.Add([]byte("EC\x02\x01\x01\x00" + string(make([]byte, 100))))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = p.Decrypt(context.Background(), data)
	})
}

func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte(`{"key":"value","nested":{"a":1}}`))
	f.Add(make([]byte, 1024))
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01})

	keyBytes := makeKey(32)
	p, err := NewProvider(keyBytes, "roundtrip-key")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := p.Encrypt(context.Background(), plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		got, err := p.Decrypt(context.Background(), ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if len(plaintext) == 0 && len(got) == 0 {
			return
		}
		if string(got) != string(plaintext) {
			t.Fatalf("mismatch: got %q, want %q", got, plaintext)
		}
	})
}
