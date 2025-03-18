package metrics

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func NewConsoleExporter() (sdkmetric.Exporter, error) {
	return stdoutmetric.New()
}

func NewOTLPExporter(ctx context.Context, otlpEndpoint string) (sdkmetric.Exporter, error) {

	insecureOpt := otlpmetrichttp.WithInsecure()
	endpointOpt := otlpmetrichttp.WithEndpoint(otlpEndpoint)

	return otlpmetrichttp.New(ctx, insecureOpt, endpointOpt)
}

func NewOtlpGrpcExporter(ctx context.Context, otlpEndpoint string) (sdkmetric.Exporter, error) {
	insecureOpt := otlpmetricgrpc.WithInsecure()
	endpointOpt := otlpmetricgrpc.WithEndpoint(otlpEndpoint)

	return otlpmetricgrpc.New(ctx, insecureOpt, endpointOpt)
}

func NewMetricProvider(exp sdkmetric.Exporter) *sdkmetric.MeterProvider {
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			// The service name used to display traces in backends
			semconv.ServiceName("go-app-metrics"), // job name
		),
	)

	if err != nil {
		panic(err)
	}

	return sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
			// Default is 1m. Set to 3s for demonstrative purposes.
			sdkmetric.WithInterval(15*time.Second))),
		sdkmetric.WithResource(r),
	)
}
