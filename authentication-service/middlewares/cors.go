package middlewares

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

var allowedOrigins = []string{
	"http://abc:3000",
}

func CORS(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		headers := map[string]string{
			"Origin": c.Request().Header.Get("Origin"),
		}

		origin, ok := headers["Origin"]

		if matched := contains(allowedOrigins, origin); ok && matched {
			fmt.Printf("Origin: %v \n\n", origin)
			c.Response().Header().Set(echo.HeaderAccessControlAllowOrigin, origin)
		}

		c.Response().Header().Set(echo.HeaderAccessControlAllowCredentials, "false")
		c.Response().Header().Set(echo.HeaderAccessControlAllowMethods, "GET, POST, PUT, DELETE, OPTIONS")
		c.Response().Header().Set(echo.HeaderAccessControlAllowHeaders, "Content-Type, Accept, Authorization")

		return next(c)
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
