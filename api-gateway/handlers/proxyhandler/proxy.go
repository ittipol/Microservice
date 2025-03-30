package proxyhandler

import (
	"net/url"

	"github.com/labstack/echo/v4"
)

type ProxyHandler interface {
	ProxyRequest(url *url.URL, routePrefix string) echo.HandlerFunc
}
