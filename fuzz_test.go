package crypto

import (
	"bytes"
	"context"
	"encoding/hex"

	"testing"
	"unicode/utf8"

	"github.com/rbaliyan/config"
	jsoncodec "github.com/rbaliyan/config/codec/json"
)

// fuzzKey is a local copy of a simple 32-byte key builder. Inlined rather
// than referencing the helper in helpers_test.go because compile_native_go_fuzzer
// only compiles the file containing the target fuzz function.
func fuzzKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// fuzzGoldenV1Hex mirrors goldenV1Hex from format_test.go. Inlined so the
// native fuzzer (which compiles only this file) can seed with the v1 wire
// vector. Keep in sync with format_test.go's goldenV1Hex.
const fuzzGoldenV1Hex = "454301010676312d6b6579bbbbbbbbbbbbbbbbbbbbbbbb" +
	"29d6588500c2ed4dbe80c41e10152b89626d776d9d4ac9f0013eb392f9e8c8d0" +
	"21e82530098ddd465a258d0fb7ee3d9a" +
	"cccccccccccccccccccccccc" +
	"108fd9608b19f18f26836ec9601c9ab38ebd485f69e6f3450b"

// fuzzKnownDecryptErr reports whether err is one of the sentinel error classes
// that decrypt / header-parse paths are allowed to return. Any other non-nil
// error indicates an unexpected failure mode.
func fuzzKnownDecryptErr(err error) bool {
	return IsInvalidFormat(err) ||
		IsUnsupportedFormat(err) ||
		IsDecryptionFailed(err) ||
		IsKeyNotFound(err) ||
		IsInvalidKeySize(err) ||
		IsProviderClosed(err)
}

func FuzzReadHeader(f *testing.F) {
	// v1 seeds.
	f.Add([]byte("EC\x01\x01\x00" + string(make([]byte, 72))))
	f.Add([]byte("EC\x01\x01\x03key" + string(make([]byte, 72))))
	// v2 seeds.
	f.Add([]byte("EC\x02\x01\x01\x00" + string(make([]byte, gcmNonceSize+2+encryptedDEKSize+gcmNonceSize))))
	// v2 boundary: keyIDLen=255 with a fully-sized trailing body.
	f.Add([]byte("EC\x02\x01\x01\xff" + string(make([]byte, 255+gcmNonceSize+2+encryptedDEKSize+gcmNonceSize))))
	// v2 boundary: explicit encDEKLen=48 with matching trailing bytes.
	f.Add(func() []byte {
		var b bytes.Buffer
		b.WriteString("EC")
		b.WriteByte(formatVersionV2)
		b.WriteByte(formatEnvelopeAESGCM)
		b.WriteByte(algAES256GCM)
		b.WriteByte(0) // empty key ID
		b.Write(make([]byte, gcmNonceSize))
		b.WriteByte(0x00)
		b.WriteByte(byte(encryptedDEKSize)) // encDEKLen = 48
		b.Write(make([]byte, encryptedDEKSize))
		b.Write(make([]byte, gcmNonceSize))
		b.Write(make([]byte, gcmTagSize)) // minimal ciphertext
		return b.Bytes()
	}())
	// v1 golden wire vector.
	if v1, err := hex.DecodeString(fuzzGoldenV1Hex); err == nil {
		f.Add(v1)
	}
	// Bad inputs.
	f.Add([]byte("EC"))
	f.Add([]byte(""))
	f.Add([]byte("XX\x01\x01\x00"))
	f.Add([]byte("EC\x99\x01\x00"))
	f.Add([]byte("EC\x01\x02\x00"))
	f.Add([]byte("EC\x01\x01\xff"))
	f.Add([]byte{0x45, 0x43, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse a private copy: libFuzzer forbids writing to the const input,
		// and we mutate the buffer below to detect defensive-copy violations.
		buf := append([]byte(nil), data...)

		h, ciphertext, err := readHeader(buf)
		if err != nil {
			// Header errors must be a known sentinel, never a surprise class.
			if !IsInvalidFormat(err) && !IsUnsupportedFormat(err) {
				t.Fatalf("readHeader returned unexpected error class: %v", err)
			}
			return
		}

		// On success the header must be internally self-consistent: the bytes
		// consumed (header + ciphertext) must exactly account for the input.
		var headerLen int
		switch h.version {
		case formatVersionV1:
			headerLen = minHeaderSizeV1 + len(h.keyID) + gcmNonceSize + encryptedDEKSize + gcmNonceSize
		case formatVersionV2:
			headerLen = headerSizeV2(h.keyID, len(h.encryptedDEK))
		default:
			t.Fatalf("parsed unexpected version %d", h.version)
		}
		if headerLen+len(ciphertext) != len(buf) {
			t.Fatalf("header accounting mismatch: headerLen=%d ciphertext=%d total=%d",
				headerLen, len(ciphertext), len(data))
		}

		// Nonces are fixed-size; encryptedDEK must be non-empty on a parse.
		if len(h.dekNonce) != gcmNonceSize || len(h.dataNonce) != gcmNonceSize {
			t.Fatalf("nonce sizes: dek=%d data=%d", len(h.dekNonce), len(h.dataNonce))
		}

		// Snapshot returned fields, then mutate the input slice. Defensive
		// copies in readHeader mean the returned header must be unaffected.
		keyIDCopy := h.keyID
		dekNonceCopy := append([]byte(nil), h.dekNonce...)
		encDEKCopy := append([]byte(nil), h.encryptedDEK...)
		dataNonceCopy := append([]byte(nil), h.dataNonce...)

		for i := range buf {
			buf[i] ^= 0xFF
		}

		if h.keyID != keyIDCopy {
			t.Fatalf("keyID aliased input: got %q want %q", h.keyID, keyIDCopy)
		}
		if !bytes.Equal(h.dekNonce, dekNonceCopy) {
			t.Fatal("dekNonce aliased input")
		}
		if !bytes.Equal(h.encryptedDEK, encDEKCopy) {
			t.Fatal("encryptedDEK aliased input")
		}
		if !bytes.Equal(h.dataNonce, dataNonceCopy) {
			t.Fatal("dataNonce aliased input")
		}
	})
}

func FuzzDecrypt(f *testing.F) {
	keyBytes := fuzzKey()
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
		_, err := p.Decrypt(context.Background(), data)
		if err != nil && !fuzzKnownDecryptErr(err) {
			t.Fatalf("Decrypt returned unexpected error class: %v", err)
		}
	})
}

func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte(`{"key":"value","nested":{"a":1}}`))
	f.Add(make([]byte, 1024))
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01})

	keyBytes := fuzzKey()
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

// FuzzNeedsReencryption exercises the second untrusted readHeader entry point,
// which additionally does a map lookup on the attacker-controlled key ID under
// an RLock. No input may panic; any error must be a known header sentinel.
func FuzzNeedsReencryption(f *testing.F) {
	ring, err := NewKeyRingProvider(fuzzKey(), "rk-current", 2)
	if err != nil {
		f.Fatal(err)
	}
	old := make([]byte, 32)
	for i := range old {
		old[i] = byte(255 - i)
	}
	if err := ring.AddKey(old, "rk-old", 1); err != nil {
		f.Fatal(err)
	}

	// Seed with a real ciphertext encrypted under the current key.
	if ct, err := ring.Encrypt(context.Background(), []byte("payload")); err == nil {
		f.Add(ct)
	}
	f.Add([]byte(""))
	f.Add([]byte("EC\x02\x01\x01\x00" + string(make([]byte, 100))))
	f.Add([]byte("EC\x01\x01\x06rk-old" + string(make([]byte, 72))))
	if v1, err := hex.DecodeString(fuzzGoldenV1Hex); err == nil {
		f.Add(v1)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := ring.NeedsReencryption(data)
		if err != nil && !IsInvalidFormat(err) && !IsUnsupportedFormat(err) {
			t.Fatalf("NeedsReencryption returned unexpected error class: %v", err)
		}
	})
}

// FuzzCodecDecode fuzzes the full decrypt -> inner-unmarshal chain in crypto.go
// with a real JSON inner codec. Any error is acceptable; only a panic fails.
func FuzzCodecDecode(f *testing.F) {
	p, err := NewProvider(fuzzKey(), "codec-key")
	if err != nil {
		f.Fatal(err)
	}
	c, err := NewCodec(jsoncodec.New(), p)
	if err != nil {
		f.Fatal(err)
	}

	ctx := context.Background()
	if enc, err := c.Encode(ctx, map[string]any{"a": 1, "b": "two"}); err == nil {
		f.Add(enc)
	}
	if enc, err := c.Encode(ctx, "plain-string"); err == nil {
		f.Add(enc)
	}
	f.Add([]byte(""))
	f.Add([]byte("EC\x02\x01\x01\x00" + string(make([]byte, 100))))
	f.Add([]byte("not encrypted at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var into any
		_ = c.Decode(ctx, data, &into)
	})
}

// FuzzEncryptedCacheGet drives the post-decrypt path in cache.go: provider
// decrypt -> json.Unmarshal(cacheEntry) -> config.NewValueFromBytes, including
// Type-range, schema-version, and time reconstruction.
//
// Angle (a): a fuzz-controlled payload is stored via Set then read back via
// Get, round-tripping through real encryption.
// Angle (b): raw fuzz bytes are written into the inner cache under the codec
// sentinel and read via Get, so the decrypt -> unmarshal path runs over
// attacker-controlled ciphertext. Get's internal path is unexported; it is
// reachable only via the public Get after seeding the inner cache, which this
// does. No input may panic.
func FuzzEncryptedCacheGet(f *testing.F) {
	p, err := NewProvider(fuzzKey(), "cache-key")
	if err != nil {
		f.Fatal(err)
	}
	inner, err := config.NewMemoryCache(0, 0)
	if err != nil {
		f.Fatal(err)
	}
	ec, err := NewEncryptedCache(inner, p)
	if err != nil {
		f.Fatal(err)
	}
	ctx := context.Background()

	// Seed corpus with valid ciphertext produced by the cache itself, plus a
	// directly-encrypted JSON cacheEntry-shaped blob, plus malformed inputs.
	_ = ec.Set(ctx, "ns", "seed", config.NewValue("seed-secret"))
	if w, err := inner.Get(ctx, "ns", "seed"); err == nil {
		if ct, err := w.Marshal(ctx); err == nil {
			f.Add(ct)
		}
	}
	if ct, err := p.Encrypt(ctx, []byte(`{"v":1,"d":"YWJj","c":"json","t":0}`)); err == nil {
		f.Add(ct)
	}
	if ct, err := p.Encrypt(ctx, []byte(`{"v":99,"t":-1}`)); err == nil {
		f.Add(ct)
	}
	f.Add([]byte(""))
	f.Add([]byte("not-valid-ciphertext"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Angle (a): round-trip the fuzz bytes as a string value. For valid
		// UTF-8 (a legitimate string payload) the recovered value must match
		// exactly; arbitrary non-UTF-8 bytes are not byte-preserved by a string
		// value's JSON encoding, so for those we only require no panic.
		if err := ec.Set(ctx, "ns", "fuzz-a", config.NewValue(string(data))); err == nil {
			got, getErr := ec.Get(ctx, "ns", "fuzz-a")
			if utf8.Valid(data) {
				if getErr != nil {
					t.Fatalf("Get after successful Set: %v", getErr)
				}
				s, err := got.String()
				if err != nil {
					t.Fatalf("String of round-tripped value: %v", err)
				}
				if s != string(data) {
					t.Fatalf("round-trip mismatch: got %q want %q", s, string(data))
				}
			}
		}

		// Angle (b): inject raw fuzz bytes as ciphertext under the sentinel codec
		// so Get's decrypt -> unmarshal -> NewValueFromBytes path runs on them.
		if err := inner.Set(ctx, "ns", "fuzz-b", config.NewRawValue(data, encryptedCacheCodec)); err == nil {
			_, _ = ec.Get(ctx, "ns", "fuzz-b")
		}
	})
}
