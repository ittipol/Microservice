package userhandler

import (
	"github.com/labstack/echo/v4"
)

type registerRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
	Name     string `validate:"required"`
}

type UserHandler interface {
	Register(c echo.Context) error
	Profile(c echo.Context) error
}
