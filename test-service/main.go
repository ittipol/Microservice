package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {

	e := echo.New()
	// Debug mode
	e.Debug = true

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!!!!!!")
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", 3000)))

}
