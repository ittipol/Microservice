package loggerhandler

import "github.com/labstack/echo/v4"

type LoggerHandler interface {
	Debug(c echo.Context) error
	Info(c echo.Context) error
	Warn(c echo.Context) error
	Error(c echo.Context) error
	Trace(c echo.Context) error
	Time(c echo.Context) error
	ErrorStatus(c echo.Context) error
}
