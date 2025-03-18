package authhandler

import (
	"authentication-service/appUtils"
	"authentication-service/factory"
	"authentication-service/logs"
	"authentication-service/services/authsrv"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type authHandler struct {
	authService authsrv.AuthService
	validate    appUtils.ValidatorUtil
	tracer      trace.Tracer
}

func NewAuthHandler(authService authsrv.AuthService, validate appUtils.ValidatorUtil, tracer trace.Tracer) AuthHandler {
	return &authHandler{authService, validate, tracer}
}

func (h authHandler) Login(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP POST /login")
	defer mainSpan.SpanEnd()

	logs.Info(fmt.Sprintf("%s: %s", "Trace ID", mainSpan.GetTraceId()))

	json_map := make(map[string]interface{})
	if err := json.NewDecoder(c.Request().Body).Decode(&json_map); err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	req := loginRequest{
		Email:    json_map["email"].(string),
		Password: json_map["password"].(string),
	}

	if err := h.validate.ValidatePayload(req); err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	res, err := h.authService.Login(mainSpan.GetContext(), req.Email, req.Password)
	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	// cookie := new(http.Cookie)
	// cookie.Name = "refresh-token"
	// cookie.Value = res.RefreshToken
	// cookie.HttpOnly = true
	// cookie.Secure = true
	// cookie.SameSite = http.SameSiteLaxMode
	// cookie.Expires = time.Now().Add(30 * time.Minute)
	// c.SetCookie(cookie)

	return c.JSON(http.StatusOK, res)
}

func (h authHandler) Refresh(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP POST /refresh")
	defer mainSpan.SpanEnd()

	logs.Info(fmt.Sprintf("%s: %s", "Trace ID", mainSpan.GetTraceId()))

	// Get refresh token from Header
	// To prevent CSRF do not get refresh token from cookie
	// Browser (client) will send all cookie to website (server) automatically
	headers := map[string]string{
		"Authorization": c.Request().Header.Get("Authorization"),
	}

	res, err := h.authService.Refresh(mainSpan.GetContext(), headers)
	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	return c.JSON(http.StatusOK, res)
}

func (h authHandler) Verify(c echo.Context) error {

	mainSpan := factory.NewTracerFactory(h.tracer, c.Request().Context(), "HTTP POST /verify")
	defer mainSpan.SpanEnd()

	logs.Info(fmt.Sprintf("%s: %s", "Trace ID", mainSpan.GetTraceId()))

	headers := map[string]string{
		"Authorization": c.Request().Header.Get("Authorization"),
	}

	err := h.authService.Verify(mainSpan.GetContext(), headers)

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
	}

	return c.String(http.StatusOK, "Valid Token")
}
