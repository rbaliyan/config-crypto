package otel

import (
	"context"
	"errors"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

func makeKey(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func mustWrap(t *testing.T, opts ...Option) *InstrumentedProvider {
	t.Helper()
	p, err := crypto.NewProvider(makeKey(32), "test-key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ip, err := WrapProvider(p, opts...)
	if err != nil {
		t.Fatalf("WrapProvider: %v", err)
	}
	return ip
}

func TestWrapProvider(t *testing.T) {
	ip := mustWrap(t)
	if ip == nil {
		t.Fatal("WrapProvider returned nil")
	}
}

func TestWrapProvider_Unwrap(t *testing.T) {
	p, err := crypto.NewProvider(makeKey(32), "k")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	ip, err := WrapProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Unwrap() != p {
		t.Error("Unwrap did not return the original provider")
	}
}

func TestInstrumentedProvider_Name(t *testing.T) {
	ip := mustWrap(t)
	if got := ip.Name(); got != "test-key" {
		t.Errorf("Name() = %q, want %q", got, "test-key")
	}
}

func TestInstrumentedProvider_Connect(t *testing.T) {
	ip := mustWrap(t)
	if err := ip.Connect(context.Background()); err != nil {
		t.Errorf("Connect: %v", err)
	}
}

func TestInstrumentedProvider_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t)

	ct, err := ip.Encrypt(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := ip.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q, want hello", pt)
	}
}

func TestInstrumentedProvider_HealthCheck(t *testing.T) {
	ip := mustWrap(t)
	if err := ip.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}

func TestInstrumentedProvider_Close(t *testing.T) {
	p, err := crypto.NewProvider(makeKey(32), "k")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := WrapProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := ip.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// After Close, the underlying provider is closed.
	if err := ip.HealthCheck(context.Background()); !errors.Is(err, crypto.ErrProviderClosed) {
		t.Errorf("HealthCheck after Close: got %v, want ErrProviderClosed", err)
	}
}

func TestInstrumentedProvider_WithTracesEnabled(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t, WithTracesEnabled(true))

	ct, err := ip.Encrypt(ctx, []byte("traced"))
	if err != nil {
		t.Fatalf("Encrypt with traces: %v", err)
	}
	pt, err := ip.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("Decrypt with traces: %v", err)
	}
	if string(pt) != "traced" {
		t.Errorf("got %q, want traced", pt)
	}
	if err := ip.Connect(ctx); err != nil {
		t.Errorf("Connect with traces: %v", err)
	}
	if err := ip.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck with traces: %v", err)
	}
}

func TestInstrumentedProvider_WithMetricsEnabled(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t, WithMetricsEnabled(true))

	ct, err := ip.Encrypt(ctx, []byte("metered"))
	if err != nil {
		t.Fatalf("Encrypt with metrics: %v", err)
	}
	if _, err := ip.Decrypt(ctx, ct); err != nil {
		t.Fatalf("Decrypt with metrics: %v", err)
	}
	if err := ip.Connect(ctx); err != nil {
		t.Errorf("Connect with metrics: %v", err)
	}
}

func TestInstrumentedProvider_WithTracesAndMetricsEnabled(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t,
		WithTracesEnabled(true),
		WithMetricsEnabled(true),
		WithTracerName("test-tracer"),
		WithMeterName("test-meter"),
	)

	ct, err := ip.Encrypt(ctx, []byte("full"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := ip.Decrypt(ctx, ct); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}

func TestInstrumentedProvider_ErrorPath_Metrics(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t, WithMetricsEnabled(true))

	// Force a decryption error with garbage input.
	if _, err := ip.Decrypt(ctx, []byte("not-valid")); err == nil {
		t.Error("expected error decrypting garbage")
	}
}

func TestInstrumentedProvider_ErrorPath_Traces(t *testing.T) {
	ctx := context.Background()
	ip := mustWrap(t, WithTracesEnabled(true))

	if _, err := ip.Decrypt(ctx, []byte("not-valid")); err == nil {
		t.Error("expected error decrypting garbage")
	}
}

func TestWrapProvider_NilProviderName(t *testing.T) {
	// Verify Name() delegates through correctly.
	p, err := crypto.NewProvider(makeKey(32), "my-provider")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	ip, err := WrapProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.Name(); got != "my-provider" {
		t.Errorf("got %q, want my-provider", got)
	}
}
