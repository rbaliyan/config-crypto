package crypto

import (
	"context"
	"testing"

	jsoncodec "github.com/rbaliyan/config/codec/json"
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
