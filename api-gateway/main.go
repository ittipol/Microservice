package main

import (
	"api-gateway/appUtils"
	"api-gateway/handlers/proxyhandler"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

type services struct {
	Name        string
	Enable      bool
	RoutePrefix string
	URL         string
}

type configuration struct {
	Services []services
}

var Config *configuration

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %v", err))
	}

	err := viper.Unmarshal(&Config)
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %v", err))
	}
}

func main() {

	appPort := os.Getenv("APP_PORT")

	if appPort == "" {
		appPort = "8088"
	}

	fmt.Println(appPort)

	jwtAccessTokenSecretKey, _ := base64.StdEncoding.DecodeString("uDnF3+6uGj+tyvqRrzfCqc1czsKOnW8m+xv7lnOBDzuIGIkjphTa6aGjuQbbMQ79EAI22YU7bTfhTQzyqKMgBQ==")
	jwtRefreshTokenSecretKey, _ := base64.StdEncoding.DecodeString("0Cf7yuCqusHqFW2N5eWZ88dy4bukCK19/jFdNIP1XvHR7zEiCDa04yf4JUqCX5TMRFaELd4ERLMcIFUB8aMXjg==")

	appJwt := appUtils.NewJwtUtil([]byte(jwtAccessTokenSecretKey), []byte(jwtRefreshTokenSecretKey))

	e := echo.New()
	// Debug mode
	e.Debug = true

	fmt.Println("++++")

	proxy(e, Config.Services, appJwt)

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// for _, value := range Config.Services {
	// 	fmt.Println(value.Name)
	// 	fmt.Println(value.RoutePrefix)
	// 	fmt.Println(value.URL)

	// 	if !value.enable {
	// 		continue
	// 	}

	// 	destUrl, _ := url.Parse(value.URL)

	// 	proxyHandler := proxyhandler.NewProxyHandler(destUrl, appJwt)

	// 	e.Any(fmt.Sprintf("%v/*", value.RoutePrefix), proxyHandler.ProxyRequest(destUrl, value.RoutePrefix))
	// }

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", appPort)))
}

func proxy(e *echo.Echo, services []services, appJwt appUtils.JwtUtil) {

	for _, value := range services {

		if !value.Enable {
			continue
		}

		fmt.Println(value.Name)
		fmt.Println(value.RoutePrefix)
		fmt.Println(value.URL)

		destUrl, _ := url.Parse(value.URL)

		proxyHandler := proxyhandler.NewProxyHandler(destUrl, appJwt)

		e.Any(fmt.Sprintf("%v/*", value.RoutePrefix), proxyHandler.ProxyRequest(destUrl, value.RoutePrefix))
	}

}
