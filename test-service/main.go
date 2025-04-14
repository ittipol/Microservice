package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"test-service/database"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func main() {

	version := os.Getenv("VERSION")

	var c Config
	c.loadConfig("config.yaml")

	rdb := initRedisConnection(c.RedisConfig)

	e := echo.New()
	// Debug mode
	e.Debug = true

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Test service, OK")
	})

	e.GET("/version", func(c echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("Service version: %v", version))
	})

	e.GET("/cache/create", func(c echo.Context) error {

		id := c.Request().Header.Get("id")

		value := rand.Intn(10000)
		key := fmt.Sprintf("user:%s:random_value", id)

		err := rdb.Set(context.Background(), key, value, 10*time.Minute).Err()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
		}
		return c.String(http.StatusOK, fmt.Sprintf("Cache success, %v", key))
	})

	e.GET("/cache/set", func(c echo.Context) error {

		key := "cache_test"

		err := rdb.Set(context.Background(), key, "test", 10*time.Minute).Err()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
		return c.String(http.StatusOK, fmt.Sprintf("Cache set, %v", key))
	})

	e.GET("/cache/get", func(c echo.Context) error {

		key := "cache_test"

		cmd := rdb.Get(context.Background(), key)

		value := cmd.Val()

		fmt.Printf("Value: %s\n", value)

		if cmd.Err() != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, cmd.Err())
		}

		return c.String(http.StatusOK, fmt.Sprintf("Cache get, %v | %v", key, value))
	})

	e.GET("/cache/delete", func(c echo.Context) error {

		key := "cache_test"

		cmd := rdb.Del(context.Background(), key)

		if cmd.Err() != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, cmd.Err())
		}

		return c.String(http.StatusOK, fmt.Sprintf("Cache delete, %v", key))
	})

	e.GET("/cache/hash/set", func(c echo.Context) error {

		key := "cache_hash_test"

		cmd := rdb.HSet(context.Background(), key, "value1", "user1")
		rdb.HSet(context.Background(), key, "value2", "user2")
		rdb.HSet(context.Background(), key, "value3", "user3")
		// cmdExp := rdb.HExpire(context.Background(), key, time.Minute*5, "value1", "value2", "value3")
		// cmd := rdb.HSetNX(context.Background(), key, "f1", "v2")

		fmt.Printf("cmd: %v\n", cmd)
		// fmt.Printf("cmdExp: %v\n", cmdExp)
		// fmt.Printf("cmdExp [Error]: %v\n", cmdExp.Err())

		if cmd.Err() != nil {
			fmt.Printf("err: %v\n", cmd.Err())
		}

		return c.String(http.StatusOK, fmt.Sprintf("Cache hash set, %v", key))
	})

	e.GET("/header", func(c echo.Context) error {

		// header := c.Request().Header.Get("Authorization")

		headers := c.Request().Header

		for i, v := range headers {
			fmt.Printf("%v --> %v\n", i, v)
		}

		return c.String(http.StatusOK, fmt.Sprintf("Headers: %v", headers))
	})

	e.GET("/body", func(c echo.Context) error {

		json_map := make(map[string]interface{})
		if err := json.NewDecoder(c.Request().Body).Decode(&json_map); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		return c.String(http.StatusOK, fmt.Sprintf("body: %v", json_map))
	})

	// =========================

	e.GET("/start-flow", func(c echo.Context) error {

		return c.String(http.StatusOK, "Success")
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", c.AppPort)))
}

func initRedisConnection(redisConfig RedisConfig) *redis.Client {

	password, err := base64.StdEncoding.DecodeString(redisConfig.Password)

	if err != nil {
		panic(err)
	}

	return database.GetRedisConnection(
		redisConfig.Username,
		string(password),
		redisConfig.Host,
		redisConfig.Port,
		redisConfig.Database,
	)
}
