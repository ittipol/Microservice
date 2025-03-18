package authhandler

import (
	"github.com/labstack/echo/v4"
)

type loginRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

type AuthHandler interface {
	Login(c echo.Context) error
	Refresh(c echo.Context) error
	Verify(c echo.Context) error
}
