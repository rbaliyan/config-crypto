package crypto

import (
	"context"
	"fmt"
	"testing"

	"github.com/rbaliyan/config"
	jsoncodec "github.com/rbaliyan/config/codec/json"
)

// Package-level sinks defeat dead-code elimination of benchmark results.
var (
	sinkBytes []byte
	sinkBool  bool
	sinkAny   any
	sinkValue config.Value
)

func benchmarkCodec(b *testing.B) *Codec {
	b.Helper()
	p, err := NewProvider(makeKey(32), "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })
	c, err := NewCodec(jsoncodec.New(), p)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

func BenchmarkEncode1KB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(ctx, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode1KB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(ctx, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(ctx, data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncode64KB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(ctx, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode64KB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(ctx, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(ctx, data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncode1MB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(ctx, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode1MB(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(ctx, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(ctx, data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeString(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(ctx, "secret-api-key-value"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeString(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	data, err := c.Encode(ctx, "secret-api-key-value")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got string
		if err := c.Decode(ctx, data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

// benchPayload returns a deterministic byte slice of the given size.
func benchPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i % 256)
	}
	return p
}

// BenchmarkProviderEncrypt measures provider-level encryption (AES-GCM +
// DEK generation + memguard enclave open) without any codec/JSON cost.
func BenchmarkProviderEncrypt(b *testing.B) {
	ctx := context.Background()
	p, err := NewProvider(makeKey(32), "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })

	for _, size := range []int{20, 1024} {
		payload := benchPayload(size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				ct, err := p.Encrypt(ctx, payload)
				if err != nil {
					b.Fatal(err)
				}
				sinkBytes = ct
			}
		})
	}
}

// BenchmarkProviderDecrypt measures provider-level decryption (header parse +
// DEK unwrap + AES-GCM open + memguard enclave open) without codec/JSON cost.
func BenchmarkProviderDecrypt(b *testing.B) {
	ctx := context.Background()
	p, err := NewProvider(makeKey(32), "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })

	for _, size := range []int{20, 1024} {
		ct, err := p.Encrypt(ctx, benchPayload(size))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				pt, err := p.Decrypt(ctx, ct)
				if err != nil {
					b.Fatal(err)
				}
				sinkBytes = pt
			}
		})
	}
}

// BenchmarkKeyByID measures multi-key decrypt where the target ciphertext's key
// is NOT the current key, forcing a keyByID lookup plus a memguard enclave
// Open/Destroy on a ring of N keys. Isolates the per-op memguard cost.
func BenchmarkKeyByID(b *testing.B) {
	ctx := context.Background()
	for _, n := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("keys=%d", n), func(b *testing.B) {
			// "key-0" is the target (oldest) key; the last added key is current.
			ring, err := NewKeyRingProvider(makeKeyN(0), "key-0", 0)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = ring.Close() })
			for i := 1; i < n; i++ {
				if err := ring.AddKey(makeKeyN(i), fmt.Sprintf("key-%d", i), uint64(i)); err != nil {
					b.Fatal(err)
				}
			}
			// Encrypt under key-0 while it is current, then switch current away
			// so decrypt must look up a non-current key.
			ct, err := ring.Encrypt(ctx, benchPayload(1024))
			if err != nil {
				b.Fatal(err)
			}
			if n > 1 {
				if err := ring.SetCurrentKey(fmt.Sprintf("key-%d", n-1)); err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				pt, err := ring.Decrypt(ctx, ct)
				if err != nil {
					b.Fatal(err)
				}
				sinkBytes = pt
			}
		})
	}
}

// makeKeyN returns a distinct deterministic 32-byte key for index n.
func makeKeyN(n int) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte((i + n*7) % 256)
	}
	return k
}

// BenchmarkEncryptedCacheSet measures the cache Set path: value marshal ->
// JSON entry encode -> provider encrypt -> inner Set.
func BenchmarkEncryptedCacheSet(b *testing.B) {
	ctx := context.Background()
	ec, err := NewSessionCache(0)
	if err != nil {
		b.Fatal(err)
	}
	v := config.NewValue("a-representative-secret-value")

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := ec.Set(ctx, "ns", "key", v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptedCacheGet measures the cache Get path: inner Get -> provider
// decrypt -> JSON entry decode -> config.NewValueFromBytes.
func BenchmarkEncryptedCacheGet(b *testing.B) {
	ctx := context.Background()
	ec, err := NewSessionCache(0)
	if err != nil {
		b.Fatal(err)
	}
	if err := ec.Set(ctx, "ns", "key", config.NewValue("a-representative-secret-value")); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		v, err := ec.Get(ctx, "ns", "key")
		if err != nil {
			b.Fatal(err)
		}
		sinkValue = v
	}
}

// BenchmarkProviderDecryptParallel measures concurrent decrypt to surface
// RWMutex + memguard enclave-open contention under the many-readers pattern
// typical of a config-server.
func BenchmarkProviderDecryptParallel(b *testing.B) {
	ctx := context.Background()
	p, err := NewProvider(makeKey(32), "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })
	ct, err := p.Encrypt(ctx, benchPayload(1024))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var local []byte
		for pb.Next() {
			pt, err := p.Decrypt(ctx, ct)
			if err != nil {
				b.Fatal(err)
			}
			local = pt
		}
		sinkBytes = local
	})
}

// BenchmarkReadHeader measures the pure-CPU header parse that runs on every
// decrypt, over a captured valid v2 ciphertext.
func BenchmarkReadHeader(b *testing.B) {
	p, err := NewProvider(makeKey(32), "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })
	ct, err := p.Encrypt(context.Background(), benchPayload(1024))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		h, rest, err := readHeader(ct)
		if err != nil {
			b.Fatal(err)
		}
		sinkAny = h
		sinkBytes = rest
	}
}

// BenchmarkNeedsReencryption measures header parse plus the current-vs-stored
// rank map lookup under RLock.
func BenchmarkNeedsReencryption(b *testing.B) {
	ctx := context.Background()
	ring, err := NewKeyRingProvider(makeKeyN(1), "key-1", 1)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ring.Close() })
	if err := ring.AddKey(makeKeyN(2), "key-2", 2); err != nil {
		b.Fatal(err)
	}
	// Encrypt under key-1, then make key-2 current so reencryption is needed.
	ct, err := ring.Encrypt(ctx, benchPayload(1024))
	if err != nil {
		b.Fatal(err)
	}
	if err := ring.SetCurrentKey("key-2"); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		need, err := ring.NeedsReencryption(ct)
		if err != nil {
			b.Fatal(err)
		}
		sinkBool = need
	}
}

// benchStruct is a realistic nested config payload exercising JSON marshal cost
// of structured production values rather than flat byte filler.
type benchStruct struct {
	Service  string            `json:"service"`
	Replicas int               `json:"replicas"`
	Enabled  bool              `json:"enabled"`
	Tags     []string          `json:"tags"`
	Limits   map[string]int    `json:"limits"`
	Env      map[string]string `json:"env"`
	Nested   struct {
		Endpoint string `json:"endpoint"`
		Timeout  int    `json:"timeout"`
	} `json:"nested"`
}

func benchStructValue() benchStruct {
	s := benchStruct{
		Service:  "payments-api",
		Replicas: 6,
		Enabled:  true,
		Tags:     []string{"prod", "pci", "us-east-1"},
		Limits:   map[string]int{"cpu": 2000, "memory": 4096, "connections": 512},
		Env:      map[string]string{"LOG_LEVEL": "info", "REGION": "us-east-1", "TIER": "gold"},
	}
	s.Nested.Endpoint = "https://payments.internal.example.com/v2"
	s.Nested.Timeout = 30
	return s
}

// BenchmarkEncodeStruct measures encrypting a realistic nested struct through
// the codec, capturing the JSON-marshal cost of structured config values.
func BenchmarkEncodeStruct(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	v := benchStructValue()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		out, err := c.Encode(ctx, v)
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}

// BenchmarkDecodeStruct measures decrypting and unmarshalling a realistic
// nested struct through the codec.
func BenchmarkDecodeStruct(b *testing.B) {
	ctx := context.Background()
	c := benchmarkCodec(b)
	data, err := c.Encode(ctx, benchStructValue())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got benchStruct
		if err := c.Decode(ctx, data, &got); err != nil {
			b.Fatal(err)
		}
		sinkAny = got
	}
}
