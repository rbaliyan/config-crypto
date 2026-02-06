package crypto

import (
	"testing"

	"github.com/rbaliyan/config/codec"
)

func benchmarkCodec(b *testing.B) *Codec {
	b.Helper()
	key := makeKey(32)
	p, err := NewStaticKeyProvider(key, "bench-key")
	if err != nil {
		b.Fatal(err)
	}
	return NewCodec(codec.JSON(), p)
}

func BenchmarkEncode1KB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode1KB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncode64KB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode64KB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncode1MB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode1MB(b *testing.B) {
	c := benchmarkCodec(b)
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	data, err := c.Encode(payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got []byte
		if err := c.Decode(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeString(b *testing.B) {
	c := benchmarkCodec(b)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Encode("secret-api-key-value"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeString(b *testing.B) {
	c := benchmarkCodec(b)
	data, err := c.Encode("secret-api-key-value")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var got string
		if err := c.Decode(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}
