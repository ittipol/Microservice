package main

import (
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
}

func main() {

	e := echo.New()
	// Debug mode
	e.Debug = true

	registerServices(e)
}

func registerServices(e *echo.Echo) {

	e.POST("/*", func(c echo.Context) error {
		return nil
	})

}
