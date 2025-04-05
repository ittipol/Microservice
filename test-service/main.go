package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

func main() {

	version := os.Getenv("VERSION")

	e := echo.New()
	// Debug mode
	e.Debug = true

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!!!!!!")
	})

	e.GET("/version", func(c echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("Service version: %v", version))
	})

	e.GET("/header", func(c echo.Context) error {

		// header := c.Request().Header.Get("Authorization")

		headers := c.Request().Header

		for i, v := range headers {
			fmt.Printf("%v --> %v\n", i, v)
		}

		return c.String(http.StatusOK, fmt.Sprintf("Headers: %v", headers))
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", 5055)))

}
