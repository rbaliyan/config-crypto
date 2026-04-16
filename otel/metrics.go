package otel

import "go.opentelemetry.io/otel/metric"

type providerMetrics struct {
	operationCount   metric.Int64Counter
	errorCount       metric.Int64Counter
	operationLatency metric.Float64Histogram
}

func initMetrics(meter metric.Meter) (*providerMetrics, error) {
	m := &providerMetrics{}
	var err error

	m.operationCount, err = meter.Int64Counter(
		"crypto.operations.total",
		metric.WithDescription("Total number of crypto provider operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	m.errorCount, err = meter.Int64Counter(
		"crypto.errors.total",
		metric.WithDescription("Total number of crypto provider operation errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	m.operationLatency, err = meter.Float64Histogram(
		"crypto.operation.duration",
		metric.WithDescription("Duration of crypto provider operations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}
