package loggerhandler

import (
	"authentication-service/factory"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type loggerHandler struct {
	logger *slog.Logger
	tracer trace.Tracer
}

func NewLoggerHandler(logger *slog.Logger, tracer trace.Tracer) LoggerHandler {
	return &loggerHandler{logger, tracer}
}

func (h loggerHandler) Debug(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /debug")
	defer mainSpan.SpanEnd()

	h.logger.Debug("Debug message")

	return c.String(http.StatusOK, "Debug")
}

func (h loggerHandler) Info(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /info")
	defer mainSpan.SpanEnd()

	h.logger.Info("Info message")

	return c.String(http.StatusOK, "Info")
}

func (h loggerHandler) Warn(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /warn")
	defer mainSpan.SpanEnd()

	h.logger.Warn("Warn message")

	return c.String(http.StatusOK, "Warn")
}

func (h loggerHandler) Error(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /error")
	defer mainSpan.SpanEnd()

	h.logger.Error("Error message")

	return c.String(http.StatusOK, "Error")
}

func (h loggerHandler) Trace(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /trace")
	defer mainSpan.SpanEnd()

	fmt.Println("Trace called!!!")

	// n := rand.Intn(2000) + 1 // ms
	// time.Sleep(time.Duration(n) * time.Millisecond)

	h.logger.Info("HTTP GET /trace [logger]")

	return c.String(http.StatusOK, "HTTP GET /trace, OK")
}

func (h loggerHandler) Time(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /time")
	defer mainSpan.SpanEnd()

	timeValue := c.Param("time")

	ms, err := strconv.Atoi(timeValue)

	if err != nil {
		h.logger.Error(fmt.Sprintf("Cannot convert string to int, [%v]", timeValue))

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	time.Sleep(time.Duration(ms) * time.Millisecond)

	h.logger.Info(fmt.Sprintf("HTTP GET /time, OK : time %v ms"), timeValue)

	return c.String(http.StatusOK, fmt.Sprintf("HTTP GET /time, OK : time %v ms", timeValue))
}
