// Package otel provides OpenTelemetry instrumentation for the config-crypto Provider interface.
package otel

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	crypto "github.com/rbaliyan/config-crypto"
)

// InstrumentedProvider wraps a Provider with OpenTelemetry tracing and metrics.
type InstrumentedProvider struct {
	provider crypto.Provider
	tracer   trace.Tracer
	meter    metric.Meter
	metrics  *providerMetrics
	opts     options
}

// Compile-time interface check.
var _ crypto.Provider = (*InstrumentedProvider)(nil)

// WrapProvider wraps a Provider with OpenTelemetry instrumentation.
// By default, both tracing and metrics are disabled. Use WithTracesEnabled(true)
// and/or WithMetricsEnabled(true) to enable them.
func WrapProvider(provider crypto.Provider, opts ...Option) (*InstrumentedProvider, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	ip := &InstrumentedProvider{
		provider: provider,
		opts:     o,
	}

	if o.enableTraces {
		if o.tracer != nil {
			ip.tracer = o.tracer
		} else {
			ip.tracer = otel.Tracer(o.tracerName)
		}
	}

	if o.enableMetrics {
		var meter metric.Meter
		if o.meter != nil {
			meter = o.meter
		} else {
			meter = otel.Meter(o.meterName)
		}
		ip.meter = meter

		m, err := initMetrics(meter)
		if err != nil {
			return nil, err
		}
		ip.metrics = m
	}

	return ip, nil
}

// Unwrap returns the underlying Provider.
func (p *InstrumentedProvider) Unwrap() crypto.Provider {
	return p.provider
}

// Name returns the underlying provider's name.
func (p *InstrumentedProvider) Name() string {
	return p.provider.Name()
}

// Connect initialises the underlying provider's connection.
func (p *InstrumentedProvider) Connect(ctx context.Context) error {
	if !p.opts.enableTraces {
		start := time.Now()
		err := p.provider.Connect(ctx)
		p.recordOperation(ctx, "connect", start, err)
		return err
	}

	ctx, span := p.tracer.Start(ctx, "crypto.Connect",
		trace.WithAttributes(p.commonAttributes()...))
	defer span.End()

	start := time.Now()
	err := p.provider.Connect(ctx)
	p.recordOperation(ctx, "connect", start, err)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return err
}

// Encrypt encrypts plaintext, recording a span and metrics when enabled.
func (p *InstrumentedProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if !p.opts.enableTraces {
		start := time.Now()
		ct, err := p.provider.Encrypt(ctx, plaintext)
		p.recordOperation(ctx, "encrypt", start, err)
		return ct, err
	}

	ctx, span := p.tracer.Start(ctx, "crypto.Encrypt",
		trace.WithAttributes(p.commonAttributes()...))
	defer span.End()

	start := time.Now()
	ct, err := p.provider.Encrypt(ctx, plaintext)
	p.recordOperation(ctx, "encrypt", start, err)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return ct, err
}

// Decrypt decrypts ciphertext, recording a span and metrics when enabled.
func (p *InstrumentedProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if !p.opts.enableTraces {
		start := time.Now()
		pt, err := p.provider.Decrypt(ctx, ciphertext)
		p.recordOperation(ctx, "decrypt", start, err)
		return pt, err
	}

	ctx, span := p.tracer.Start(ctx, "crypto.Decrypt",
		trace.WithAttributes(p.commonAttributes()...))
	defer span.End()

	start := time.Now()
	pt, err := p.provider.Decrypt(ctx, ciphertext)
	p.recordOperation(ctx, "decrypt", start, err)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return pt, err
}

// HealthCheck reports whether the provider is usable, recording a span when enabled.
func (p *InstrumentedProvider) HealthCheck(ctx context.Context) error {
	if !p.opts.enableTraces {
		return p.provider.HealthCheck(ctx)
	}

	ctx, span := p.tracer.Start(ctx, "crypto.HealthCheck",
		trace.WithAttributes(p.commonAttributes()...))
	defer span.End()

	err := p.provider.HealthCheck(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return err
}

// Close zeroes key material and releases resources.
func (p *InstrumentedProvider) Close() error {
	return p.provider.Close()
}

// commonAttributes returns the per-provider span attributes.
// The returned slice has len == cap so callers can append without aliasing.
func (p *InstrumentedProvider) commonAttributes() []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 1)
	attrs = append(attrs, attribute.String("provider", p.provider.Name()))
	return attrs[:len(attrs):len(attrs)]
}

// recordOperation records latency, operation count, and error count metrics.
func (p *InstrumentedProvider) recordOperation(ctx context.Context, op string, start time.Time, err error) {
	if !p.opts.enableMetrics {
		return
	}

	latency := time.Since(start).Seconds()
	attrs := []attribute.KeyValue{
		attribute.String("operation", op),
		attribute.String("provider", p.provider.Name()),
	}

	p.metrics.operationCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	p.metrics.operationLatency.Record(ctx, latency, metric.WithAttributes(attrs...))

	if err != nil {
		errorAttrs := append(attrs, attribute.String("error_type", errorType(err)))
		p.metrics.errorCount.Add(ctx, 1, metric.WithAttributes(errorAttrs...))
	}
}

// errorType classifies an error for the error_type metric attribute.
func errorType(err error) string {
	if errors.Is(err, crypto.ErrProviderClosed) {
		return "provider_closed"
	}
	if errors.Is(err, crypto.ErrKeyNotFound) {
		return "key_not_found"
	}
	if errors.Is(err, crypto.ErrDecryptionFailed) {
		return "decryption_failed"
	}
	return "internal"
}
