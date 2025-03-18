package userhandler

import (
	"authentication-service/appUtils"
	"authentication-service/factory"
	"authentication-service/logs"
	"authentication-service/services/usersrv"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type userHandler struct {
	userService usersrv.UserService
	validate    appUtils.ValidatorUtil
	tracer      trace.Tracer
}

func NewUserHandler(userService usersrv.UserService, validate appUtils.ValidatorUtil, tracer trace.Tracer) UserHandler {
	return &userHandler{userService, validate, tracer}
}

func (h userHandler) Register(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP POST /register")
	defer mainSpan.SpanEnd()

	logs.Info(fmt.Sprintf("%s: %s", "Trace ID", mainSpan.GetTraceId()))

	json_map := make(map[string]interface{})
	if err := json.NewDecoder(c.Request().Body).Decode(&json_map); err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	req := registerRequest{
		Email:    json_map["email"].(string),
		Password: json_map["password"].(string),
		Name:     json_map["name"].(string),
	}

	if err := h.validate.ValidatePayload(req); err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	err := h.userService.Register(mainSpan.GetContext(), req.Email, req.Password, req.Name)
	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	return c.NoContent(http.StatusOK)
}

func (h userHandler) Profile(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP GET /profile")
	defer mainSpan.SpanEnd()

	logs.Info(fmt.Sprintf("%s: %s", "Trace ID", mainSpan.GetTraceId()))

	headers := map[string]string{
		"Authorization": c.Request().Header.Get("Authorization"),
	}

	res, err := h.userService.Profile(mainSpan.GetContext(), headers)
	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		// return c.JSON(http.StatusInternalServerError, map[string]interface{}{
		// 	"message": "unexpected error",
		// })
		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	return c.JSON(http.StatusOK, res)
}
