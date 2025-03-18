package logs

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func NewConsoleExporter() (sdklog.Exporter, error) {
	return stdoutlog.New()
}

func NewOTLPExporter(ctx context.Context, otlpEndpoint string) (sdklog.Exporter, error) {
	insecureOpt := otlploghttp.WithInsecure()
	endpointOpt := otlploghttp.WithEndpoint(otlpEndpoint)

	return otlploghttp.New(ctx, insecureOpt, endpointOpt)
}

func NewOtlpGrpcExporter(ctx context.Context, otlpEndpoint string) (sdklog.Exporter, error) {
	insecureOpt := otlploggrpc.WithInsecure()
	endpointOpt := otlploggrpc.WithEndpoint(otlpEndpoint)

	return otlploggrpc.New(ctx, insecureOpt, endpointOpt)
}

func NewLogProvider(exp sdklog.Exporter) *sdklog.LoggerProvider {

	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			// The service name used to display traces in backends
			semconv.ServiceName("go-app-event-logs"),
		),
	)

	if err != nil {
		panic(err)
	}

	return sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		sdklog.WithResource(r),
	)
}
