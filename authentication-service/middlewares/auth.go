package middlewares

import (
	"authentication-service/appUtils"
	"authentication-service/helpers"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"github.com/spf13/viper"
)

func AuthorizeJWT(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		fmt.Printf("[Middleware] AuthorizeJWT\n\n")

		headers := map[string]string{
			"Authorization": c.Request().Header.Get("Authorization"),
		}

		fmt.Printf("Headers: %v\n\n", headers)
		value, err := helpers.GetHeader(headers, "Authorization")

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}

		tokenString, err := helpers.GetBearerToken(value)

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}

		appJwt := appUtils.NewJwtUtil(
			[]byte(viper.GetString("app.jwt_access_token_secret")),
			[]byte(viper.GetString("app.jwt_refresh_token_secret")),
		)
		token, err := appJwt.Validate(tokenString, appUtils.AccessTokenSecretKey)

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return echo.NewHTTPError(http.StatusUnauthorized, "Please provide valid credentials")
		}

		c.Response().Header().Set("Userid", fmt.Sprintf("%v", claims["id"]))

		return next(c)
	}
}
