package factory

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type TracerFactory interface {
	// Start(ctx context.Context, spanName string) (context context.Context, spanEnd func())
	RecordError(err error)
	SetStatus(code codes.Code, description string)
	SetAttributes(kv ...attribute.KeyValue)
	SpanEnd()
	GetContext() context.Context
	GetTraceId() string
}

type tracerFactory struct {
	context context.Context
	span    trace.Span
}

func NewTracerFactory(tracer trace.Tracer, ctx context.Context, spanName string) TracerFactory {

	var context context.Context
	var span trace.Span

	if tracer != nil {
		context, span = tracer.Start(ctx, spanName)
	}

	return &tracerFactory{
		context: context,
		span:    span,
	}
}

// func (m tracerFactory) Start(ctx context.Context, spanName string) (context context.Context, spanEnd func()) {

// 	var span trace.Span

// 	fmt.Println(":::: Trace ---")
// 	// fmt.Printf("%v", m.tracer)
// 	fmt.Println()

// 	if m.tracer != nil {
// 		context, span = m.tracer.Start(ctx, spanName)

// 		m.span = span
// 	}

// 	spanEnd = func() {
// 		fmt.Println("&&&&&&&&&&&&&&&&&&&&&&&&&&& END")
// 		// fmt.Printf("%v", span)
// 		fmt.Println()
// 		fmt.Println("---")

// 		if span != nil {
// 			fmt.Println("Call END...")
// 			fmt.Println("---")
// 			span.End()
// 		}
// 	}

// 	return context, spanEnd
// }

func (m tracerFactory) RecordError(err error) {
	if m.span != nil {
		m.span.RecordError(err)
	}
}

func (m tracerFactory) SetStatus(code codes.Code, description string) {
	if m.span != nil {
		m.span.SetStatus(code, description)
	}
}

func (m tracerFactory) SetAttributes(kv ...attribute.KeyValue) {
	fmt.Println("Call SetAttributes...")
	fmt.Printf("%v", m.span)
	fmt.Println("---")
	if m.span != nil {
		fmt.Println("::: SetAttributes...")
		m.span.SetAttributes(kv...)
	}
}

func (m tracerFactory) SpanEnd() {
	if m.span != nil {
		m.span.End()
	}
}

func (m tracerFactory) GetContext() context.Context {
	return m.context
}

func (m tracerFactory) GetTraceId() (traceId string) {

	traceId = ""

	if m.span != nil {
		traceId = m.span.SpanContext().TraceID().String()
	}

	return
}
