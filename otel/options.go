package otel

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type options struct {
	tracerName    string
	meterName     string
	enableTraces  bool
	enableMetrics bool
	tracer        trace.Tracer
	meter         metric.Meter
}

func defaultOptions() options {
	return options{
		tracerName:    "github.com/rbaliyan/config-crypto",
		meterName:     "github.com/rbaliyan/config-crypto",
		enableTraces:  false,
		enableMetrics: false,
	}
}

// Option configures the instrumented provider.
type Option func(*options)

// WithTracesEnabled enables or disables tracing (disabled by default).
func WithTracesEnabled(enabled bool) Option {
	return func(o *options) { o.enableTraces = enabled }
}

// WithMetricsEnabled enables or disables metrics (disabled by default).
func WithMetricsEnabled(enabled bool) Option {
	return func(o *options) { o.enableMetrics = enabled }
}

// WithTracerName sets the OpenTelemetry tracer name.
// Default: "github.com/rbaliyan/config-crypto".
func WithTracerName(name string) Option {
	return func(o *options) { o.tracerName = name }
}

// WithMeterName sets the OpenTelemetry meter name.
// Default: "github.com/rbaliyan/config-crypto".
func WithMeterName(name string) Option {
	return func(o *options) { o.meterName = name }
}

// WithTracer sets a custom tracer, overriding the global tracer provider.
func WithTracer(t trace.Tracer) Option {
	return func(o *options) { o.tracer = t }
}

// WithMeter sets a custom meter, overriding the global meter provider.
func WithMeter(m metric.Meter) Option {
	return func(o *options) { o.meter = m }
}
