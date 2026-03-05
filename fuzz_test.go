package crypto

import "testing"

func FuzzReadHeader(f *testing.F) {
	// Valid header prefix: "EC" + version(1) + alg(1) + keyIDLen(0)
	f.Add([]byte("EC\x01\x01\x00" + string(make([]byte, 72))))
	f.Add([]byte("EC\x01\x01\x03key" + string(make([]byte, 72))))
	f.Add([]byte("EC"))
	f.Add([]byte(""))
	f.Add([]byte("XX\x01\x01\x00"))
	f.Add([]byte("EC\x02\x01\x00"))
	f.Add([]byte("EC\x01\x02\x00"))
	f.Add([]byte("EC\x01\x01\xff"))
	f.Add([]byte{0x45, 0x43, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readHeader(data)
	})
}

func FuzzDecrypt(f *testing.F) {
	// Create a valid encrypted payload as seed
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	provider, err := NewStaticKeyProvider(key, "test-key")
	if err != nil {
		f.Fatal(err)
	}
	encrypted, err := encrypt([]byte("hello world"), Key{ID: "test-key", Bytes: key})
	if err != nil {
		f.Fatal(err)
	}

	f.Add(encrypted)
	f.Add([]byte(""))
	f.Add([]byte("EC\x01\x01\x00"))
	f.Add([]byte("not encrypted"))
	f.Add([]byte("EC\x01\x01\x08test-key" + string(make([]byte, 100))))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decrypt(data, provider)
	})
}

func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte(`{"key":"value","nested":{"a":1}}`))
	f.Add(make([]byte, 1024))
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01})

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kek := Key{ID: "roundtrip-key", Bytes: key}
	provider, err := NewStaticKeyProvider(key, "roundtrip-key")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		encrypted, err := encrypt(plaintext, kek)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		decrypted, err := decrypt(encrypted, provider)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if len(plaintext) == 0 && len(decrypted) == 0 {
			return
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("round trip mismatch: got %q, want %q", decrypted, plaintext)
		}
	})
}
