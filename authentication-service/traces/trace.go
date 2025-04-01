package traces

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Console Exporter, only for testing
func NewConsoleExporter() (sdktrace.SpanExporter, error) {
	return stdouttrace.New()
}

// OTLP Exporter
func NewOTLPExporter(ctx context.Context, otlpEndpoint string) (sdktrace.SpanExporter, error) {
	// Change default HTTPS -> HTTP
	insecureOpt := otlptracehttp.WithInsecure()

	// Update default OTLP reciver endpoint
	endpointOpt := otlptracehttp.WithEndpoint(otlpEndpoint)

	return otlptracehttp.New(ctx, insecureOpt, endpointOpt)
}

func NewOtlpGrpcExporter(ctx context.Context, otlpEndpoint string) (sdktrace.SpanExporter, error) {

	// Change default HTTPS -> HTTP
	insecureOpt := otlptracegrpc.WithInsecure()

	endpointOpt := otlptracegrpc.WithEndpoint(otlpEndpoint)

	return otlptracegrpc.New(ctx, insecureOpt, endpointOpt)
}

// Jaeger Exporter
// func NewJaegerExporter(ctx context.Context, jaegerEndpoint string) (*jaeger.Exporter, error) {
// 	// http://jaeger:14268/api/traces
// 	return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerEndpoint)))
// }

// TracerProvider is an OpenTelemetry TracerProvider.
// It provides Tracers to instrumentation so it can trace operational flow through a system.
func NewTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("authentication-service-traces"),
		),
	)

	if err != nil {
		panic(err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}
