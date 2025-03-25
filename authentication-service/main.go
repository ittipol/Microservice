package main

import (
	"authentication-service/appUtils"
	"authentication-service/database"
	"authentication-service/factory"
	"authentication-service/handlers/authhandler"
	"authentication-service/handlers/loggerhandler"
	"authentication-service/handlers/userhandler"
	"authentication-service/logs"
	"authentication-service/metrics"
	"authentication-service/middlewares"
	"authentication-service/repositories"
	"authentication-service/services/authsrv"
	"authentication-service/services/usersrv"
	"authentication-service/traces"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"math/rand"
	"time"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	"gorm.io/gorm"
)

// func init() {
// 	viper.SetConfigName("config")
// 	viper.SetConfigType("yaml")
// 	viper.AddConfigPath(".")
// 	viper.AutomaticEnv()
// 	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

// 	if err := viper.ReadInConfig(); err != nil {
// 		panic(fmt.Errorf("Fatal error config file: %s \n", err))
// 	}
// }

func main() {

	ctx := context.Background()

	initTimeZone()

	version := os.Getenv("VERSION")
	appPort := os.Getenv("APP_PORT")
	appDsnPath := os.Getenv("APP_DSN_PATH")
	appSecretPath := os.Getenv("APP_SECRET_PATH")
	otlpEndpoint := os.Getenv("APP_OTEL_COL_ENDPOINT")

	fmt.Println("APP_VERSION:", version)
	fmt.Println("APP_PORT:", appPort)
	fmt.Println("APP_DSN_PATH:", appDsnPath)
	fmt.Println("APP_SECRET_PATH:", appSecretPath)
	fmt.Println("APP_OTEL_COL_ENDPOINT:", otlpEndpoint)

	// ---- Vault

	// config := vault.DefaultConfig()
	// config.Address = "http://127.0.0.1:8200"

	// client, err := vault.NewClient(config)
	// if err != nil {
	// 	log.Fatalf("unable to initialize Vault client: %v", err)
	// }

	// // Authenticate
	// // Root Token
	// client.SetToken()

	// secret, err := client.KVv1("key").Get(context.Background(), "jwt-secret-key")
	// if err != nil {
	// 	log.Fatalf("unable to read secret: %v", err)
	// }

	// fmt.Printf("%v", secret.Data)

	// panic("")

	// ----

	result, err := loadJson(appDsnPath)

	if err != nil {
		panic(err)
	}

	db := initDbConnection(result["db_connection"].(string))

	db.Migrator().AutoMigrate(repositories.User{})

	// ========================================================================

	result, err = loadJson(appSecretPath)

	if err != nil {
		panic(err)
	}

	appValidator := appUtils.NewValidatorUtil()

	jwtAccessTokenSecretKey, err := base64.StdEncoding.DecodeString(result["jwt-access-token-secret"].(string))

	if err != nil {
		panic(err)
	}

	jwtRefreshTokenSecretKey, err := base64.StdEncoding.DecodeString(result["jwt-refresh-token-secret"].(string))

	if err != nil {
		panic(err)
	}

	appJwt := appUtils.NewJwtUtil([]byte(jwtAccessTokenSecretKey), []byte(jwtRefreshTokenSecretKey))

	fmt.Println(result["jwt-access-token-secret"].(string))
	fmt.Printf("%v, %v", []byte(jwtAccessTokenSecretKey), len([]byte(jwtAccessTokenSecretKey)))
	fmt.Println()
	fmt.Println(result["jwt-refresh-token-secret"].(string))
	fmt.Printf("%v, %v", []byte(jwtRefreshTokenSecretKey), len([]byte(jwtRefreshTokenSecretKey)))
	fmt.Println()

	// Trace ========================================================================

	// traceExporter, err := traces.NewConsoleExporter()
	traceExporter, err := traces.NewOtlpGrpcExporter(ctx, otlpEndpoint)

	if err != nil {
		panic(err)
	}

	// Create a new tracer provider with a batch span processor and the given exporter
	traceProvider := traces.NewTraceProvider(traceExporter)

	// Handle shutdown properly so nothing leaks
	defer func() {
		if err := traceProvider.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown Trace Provider: %s", err)
		}
	}()

	otel.SetTracerProvider(traceProvider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tracer := traceProvider.Tracer("example/go-observability")

	// Log ========================================================================

	logExporter, err := logs.NewOtlpGrpcExporter(ctx, otlpEndpoint)

	if err != nil {
		panic(err)
	}

	loggerProvider := logs.NewLogProvider(logExporter)

	defer func() {
		if err := loggerProvider.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown Logger Provider: %s", err)
		}
	}()

	// Set the logger provider globally
	global.SetLoggerProvider(loggerProvider)

	// Instantiate a new slog logger
	logger := otelslog.NewLogger("example/go-observability")

	// Metric ========================================================================

	// metricExporter, err := metrics.NewConsoleExporter()
	metricExporter, err := metrics.NewOtlpGrpcExporter(ctx, otlpEndpoint)

	if err != nil {
		panic(err)
	}

	metricProvider := metrics.NewMetricProvider(metricExporter)

	defer func() {
		if err := metricProvider.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown Meter Provider: %s", err)
		}
	}()

	otel.SetMeterProvider(metricProvider)

	meter := metricProvider.Meter("example/go-observability")

	// ========================================================================

	userRepository := repositories.NewUserRepository(db, tracer)

	authService := authsrv.NewAuthService(userRepository, appJwt, tracer)
	userService := usersrv.NewUserService(userRepository, appJwt, tracer)

	authHandler := authhandler.NewAuthHandler(authService, appValidator, tracer)
	userHandler := userhandler.NewUserHandler(userService, appValidator, tracer)
	loggerHandler := loggerhandler.NewLoggerHandler(logger, tracer)

	// ========================================================================

	meterFactory := factory.NewMetricFactory(meter)

	// ========================================================================

	e := echo.New()
	// Debug mode
	e.Debug = true

	//-------------------
	// Custom middleware
	//-------------------
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			start := time.Now()

			if err := next(c); err != nil {
				c.Error(err)
			}

			meterFactory.Lock()
			defer meterFactory.Unlock()

			// Stop the timer
			duration := time.Since(start)

			fmt.Printf("Request URL: %s - Method: %s - Duration: %s\n", c.Request().URL, c.Request().Method, duration.String())

			status := strconv.Itoa(c.Response().Status)
			path := c.Path()

			fmt.Printf("%v\n", path)
			fmt.Printf("%v\n", c.Request().Method)
			fmt.Printf("%v\n", status)

			if path == "" {
				path = "undefined"
			}

			meterFactory.RecordDuration(c.Request().Context(), duration.Seconds())

			return nil
		}
	})

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set(echo.HeaderServer, "Echo/3.0")
			return next(c)
		}
	})

	e.POST("/login", authHandler.Login)
	e.POST("/register", userHandler.Register)
	e.POST("/verify", authHandler.Verify)
	e.GET("/user/profile", userHandler.Profile, middlewares.AuthorizeJWT)

	// ==== Group ====================================
	tokenGroup := e.Group("/token", middlewares.RefreshTokenAuthorizeJWT)
	tokenGroup.POST("/refresh", authHandler.Refresh)
	// ================================================

	e.GET("/debug", loggerHandler.Debug)
	e.GET("/info", loggerHandler.Info)
	e.GET("/warn", loggerHandler.Warn)
	e.GET("/error", loggerHandler.Error)
	e.GET("/trace", loggerHandler.Trace)
	e.GET("/time/:time", loggerHandler.Time)

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!!!!!!")
	})

	e.GET("/version", func(c echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("Service version: %v", version))
	})

	e.GET("/test", func(c echo.Context) error {

		n := rand.Intn(2000) + 200 // ms
		// fmt.Printf("Sleeping %d seconds...\n", n)
		time.Sleep(time.Duration(n) * time.Millisecond)

		return c.String(http.StatusInternalServerError, fmt.Sprintf("Sleeping %d milliseconds...\n", n))
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", appPort)))

	// ========================================================================
}

func initTimeZone() {
	// LoadLocation looks for the IANA Time Zone database
	// List of tz database time zones
	// https: //en.wikipedia.org/wiki/List_of_tz_database_time_zones
	location, err := time.LoadLocation("Asia/Bangkok")
	if err != nil {
		panic(err)
	}

	// init system time zone
	time.Local = location

	// timeInUTC := time.Date(2018, 8, 30, 12, 0, 0, 0, time.UTC)
	// fmt.Println(timeInUTC.In(location))
}

func initDbConnection(dsn string) *gorm.DB {
	return database.GetDbConnection(dsn)
}

// func initDbConnection(username string, password string, host string, port int, db string) *gorm.DB {
// 	return database.GetDbConnection(
// 		username,
// 		password,
// 		host,
// 		port,
// 		db,
// 		false,
// 	)
// }

func loadJson(path string) (map[string]interface{}, error) {
	jsonFile, err := os.Open(path)

	if err != nil {
		return nil, err
	}
	fmt.Println(fmt.Sprintf("Successfully Opened secret [json]: %v", path))

	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)

	fmt.Printf("$v", result)

	return result, nil
}
