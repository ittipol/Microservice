package factory

import (
	"context"
	"runtime"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

type MetricFactory interface {
	Lock()
	Unlock()
	RecordDuration(context context.Context, incr float64)
}

type metricFactory struct {
	Mutex sync.RWMutex

	duration metric.Float64Histogram
}

func NewMetricFactory(meter metric.Meter) MetricFactory {

	duration, err := meter.Float64Histogram(
		"task.duration",
		metric.WithDescription("The duration of task execution."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 5, 10),
	)

	if err != nil {
		return &metricFactory{}
	}

	return &metricFactory{
		duration: duration,
	}
}

func (m *metricFactory) RecordDuration(context context.Context, incr float64) {
	m.duration.Record(context, incr)
}

func (m *metricFactory) Lock() {
	m.Mutex.Lock()
}

func (m *metricFactory) Unlock() {
	m.Mutex.Unlock()
}

func memoryHeapUsage(meter metric.Meter) {
	if _, err := meter.Int64ObservableGauge(
		"memory.heap",
		metric.WithDescription(
			"Memory usage of the allocated heap objects.",
		),
		metric.WithUnit("By"), // bytes
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			o.Observe(int64(m.HeapAlloc))
			return nil
		}),
	); err != nil {
		panic(err)
	}
}
