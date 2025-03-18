package main

import (
	"authentication-service/database"
	"authentication-service/logs"
	"authentication-service/metrics"
	"authentication-service/traces"
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	vault "github.com/hashicorp/vault/api"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"gorm.io/gorm"
)

var db *gorm.DB

type User struct {
	ID           int `gorm:"primaryKey;autoIncrement"`
	Password     string
	Email        string `gorm:"unique;size:100"`
	Name         string `gorm:"size:100"`
	RefreshToken string
}

var mutex sync.RWMutex
var mutexMiddleware sync.RWMutex

func main2() {

	ctx := context.Background()

	otlpEndpoint := "opentelemetry-collector.otelcol.svc:4317"

	config := vault.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}

	// Authenticate
	// Root Token
	// client.SetToken()

	// client.RawRequest()

	// secretData := map[string]interface{}{
	// 	"password": "Hashi123",
	// }

	// secret, err := client.KVv1("database").Get(context.Background(), "creds/sql-create-user-role")
	secret, err := client.KVv1("database").Get(context.Background(), "creds/sql-all-access-role")
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}

	// fmt.Printf("%v", secret.Data)

	username, ok := secret.Data["username"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["username"], secret.Data["username"])
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["password"], secret.Data["password"])
	}

	// fmt.Println(value)

	// host := "postgres.postgres.svc"

	db = initDbConnection2(username, password, "localhost", 5432, "postgresdb")

	db.Migrator().AutoMigrate(User{})

	createUser("bbb@mail.com", "password", "name1")
	fmt.Println("+++++++++++++++++++++++++++")
	user, err := getUserByEmail("aaa@mail.com")

	if err != nil {
		panic(err)
	}

	fmt.Println(user.Email)

	panic("error!!!")

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
	// ========================================================================

	runCount, err := meter.Int64Counter("api.counter", metric.WithDescription("The number of times the iteration ran"), metric.WithUnit("{call}"))
	if err != nil {
		log.Fatal(err)
	}

	histogram, err := meter.Float64Histogram(
		"task.duration",
		metric.WithDescription("The duration of task execution."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.1, 0.25, 0.5, 0.75, 1, 1.5, 2),
	)
	if err != nil {
		log.Fatal(err)
	}

	// memoryHeapUsage(meter)

	// ========================================================================

	app := fiber.New()

	app.Use(func(c fiber.Ctx) error {
		// mutexMiddleware.Lock()
		// defer mutexMiddleware.Unlock()

		start := time.Now()

		fmt.Printf("::: Start: %v\n", start)

		err := c.Next()

		// mutexMiddleware.Lock()
		// defer mutexMiddleware.Unlock()

		fmt.Println("::: Middleware used")

		duration := time.Since(start)
		histogram.Record(c.Context(), duration.Seconds())

		fmt.Printf("::: Duration: %s\n", duration.String())
		fmt.Printf("::: Duration (second): %v\n", duration.Seconds())

		return err
	})

	// Define a route for the GET method on the root path '/'
	app.Get("/", func(c fiber.Ctx) error {
		_, span := tracer.Start(c.Context(), "HTTP POST /fiber")
		defer span.End()

		span.AddEvent("Acquiring lock")
		mutex.Lock()
		span.AddEvent("Got lock, doing work...")
		// do stuff
		number := rand.Intn(1)

		n := rand.Intn(1000) + 1 // ms
		// fmt.Printf("Sleeping %d seconds...\n", n)
		time.Sleep(time.Duration(n) * time.Millisecond)

		fmt.Println("++++++++++++++++++++++++++++++++++++++++")
		fmt.Printf("::: Random number: %d\n", n)
		span.AddEvent("Unlocking")
		mutex.Unlock()

		// Attributes represent additional key-value descriptors that can be bound
		// to a metric observer or recorder.
		// attribute = label
		// ex. api_counter_total{attrA="chocolate", attrB="raspberry", attrC="vanilla", job="go-app-metrics"}
		commonAttrs := []attribute.KeyValue{
			attribute.String("attrA", "chocolate"),
			attribute.String("attrB", "raspberry"),
			attribute.String("attrC", "vanilla"),
		}

		runCount.Add(ctx, 1, metric.WithAttributes(commonAttrs...))

		if number == 0 {
			c.Status(http.StatusInternalServerError)
			span.SetStatus(codes.Error, "Operation failed!!!")
		} else {
			c.Status(http.StatusOK)
			span.SetStatus(codes.Ok, "Operation succeeded!!!")
		}

		c.Status(http.StatusOK)
		// Send a string response to the client
		return c.SendString(fmt.Sprintf("Hello, World 👋! (%d ms)", n))
	})

	app.Get("/log", func(c fiber.Ctx) error {
		logger.Info("Write log......")

		return c.SendString("Write log...")
	})

	// Start the server on port 3000
	log.Fatal(app.Listen(":3000"))
}

func initDbConnection2(username string, password string, host string, port int, db string) *gorm.DB {
	return database.CreateAndGetDbConnection(
		username,
		password,
		host,
		port,
		db,
		false,
	)
}

func createUser(email string, hashedPassword string, name string) (id int, err error) {

	user := User{
		Email:    email,
		Password: hashedPassword,
		Name:     name,
	}

	// sqlStr := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
	// 	return tx.Create(&user)
	// })

	err = db.Create(&user).Error

	return id, err
}

func getUserByEmail(email string) (user User, err error) {
	err = db.Where("email = @email", sql.Named("email", email)).First(&user).Error
	return user, err
}
