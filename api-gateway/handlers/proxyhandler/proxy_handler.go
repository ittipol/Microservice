package proxyhandler

import (
	"api-gateway/appUtils"
	"api-gateway/helpers"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type proxyHandler struct {
	proxy    *httputil.ReverseProxy
	jwtToken appUtils.JwtUtil
}

func NewProxyHandler(destUrl *url.URL, jwtToken appUtils.JwtUtil) ProxyHandler {

	proxy := httputil.NewSingleHostReverseProxy(destUrl)

	proxy.ModifyResponse = func(response *http.Response) error {
		dumpedResponse, err := httputil.DumpResponse(response, false)
		if err != nil {
			return err
		}
		log.Println("Response: \r\n", string(dumpedResponse))
		return nil
	}

	return &proxyHandler{
		proxy:    proxy,
		jwtToken: jwtToken,
	}
}

func (h *proxyHandler) ProxyRequest(url *url.URL, routePrefix string) echo.HandlerFunc {

	return func(c echo.Context) error {

		// id, err := verifyJwt(c, h.jwtToken)

		// if err != nil {
		// 	return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		// }

		r := c.Request()
		w := c.Response().Writer

		log.Printf("> URL ===> %v | %v | %v\n", url.Host, url.Scheme, r.Header.Get("Host"))

		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		// r.Header.Set("Userid", fmt.Sprintf("%v", id))
		r.Host = url.Host

		log.Println(r.URL.Path)

		path := r.URL.Path
		r.URL.Path = strings.TrimLeft(path, routePrefix)

		log.Printf("> ProxyRequest, Client: %v | %v | %v | %v\n", r.RemoteAddr, r.Method, r.URL, r.Proto)
		h.proxy.ServeHTTP(w, r)

		return nil
	}
}

func verifyJwt(c echo.Context, jwtUtil appUtils.JwtUtil) (int, error) {

	// jwt auth
	authorization := c.Request().Header.Get("Authorization")

	token, err := helpers.GetBearerToken(authorization)

	if err != nil {
		return 0, echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}

	jwtToken, err := jwtUtil.Validate(token, appUtils.AccessTokenSecretKey)

	fmt.Printf("Token Valid: %v \n", jwtToken.Valid)

	if err != nil {
		return 0, echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		fmt.Printf("Res: %v \n", claims)
	}

	id := int(claims["id"].(float64))

	return id, nil
}
