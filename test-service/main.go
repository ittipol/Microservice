package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
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
	// rdb := initRedisClusterConnection()

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

		// id := c.Request().Header.Get("id")
		fmt.Println("call /cache/create")

		id := "1"

		value := rand.Intn(10000)
		key := fmt.Sprintf("user:%s:random_value", id)

		err := rdb.Set(context.Background(), key, value, 10*time.Minute).Err()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
		return c.String(http.StatusOK, fmt.Sprintf("Cache success, %v", key))
	})

	e.GET("/cache/set", func(c echo.Context) error {

		key := "cache_test"

		fmt.Println("call /cache/set")

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

		start := time.Now()

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

		duration := time.Since(start)

		return c.String(http.StatusOK, fmt.Sprintf("Cache hash set, %v, time: [%s]", key, duration.String()))
	})

	e.GET("/cache/hash/exist", func(c echo.Context) error {

		key := "cache_hash_test"

		cmd := rdb.HExists(context.Background(), key, "value1")

		fmt.Printf("cmd: %v\n", cmd)

		if cmd.Err() != nil {
			fmt.Printf("err: %v\n", cmd.Err())
		}

		return c.String(http.StatusOK, fmt.Sprintf("Cache hash set, %v | %v", key, cmd.Val()))
	})

	e.GET("/cache/hash/test/:n", func(c echo.Context) error {

		key := "data_list"

		n := c.Param("n")

		number, err := strconv.Atoi(n)

		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
		}

		if number > 100000 {
			return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
		}

		rdb.Del(context.Background(), key)

		start := time.Now()

		for i := 1; i <= number; i++ {
			rdb.HSet(context.Background(), key, fmt.Sprintf("%018d", i), "1")
			fmt.Printf("%018d\n", i)
		}

		duration := time.Since(start)

		return c.String(http.StatusOK, fmt.Sprintf("/cache/hash/test, time: [%s]", duration.String()))
	})

	e.GET("/cache/set/test/:n", func(c echo.Context) error {

		key := "data_set"

		n := c.Param("n")

		number, err := strconv.Atoi(n)

		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
		}

		if number > 100000 {
			return echo.NewHTTPError(http.StatusInternalServerError, "Unexpected error")
		}

		rdb.Del(context.Background(), key)

		start := time.Now()

		for i := 1; i <= number; i++ {
			err := rdb.SAdd(context.Background(), key, fmt.Sprintf("%018d", i))
			fmt.Printf("%018d\n", i)

			if err != nil {
				fmt.Printf("%v\n", err)
			}
		}

		duration := time.Since(start)

		return c.String(http.StatusOK, fmt.Sprintf("/cache/set/test, time: [%s]", duration.String()))
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

	e.GET("/get-content", func(c echo.Context) error {

		// id := c.Request().Header.Get("id")

		// check draft is expired
		// true
		// return error

		if true {
			// Draft not found or expired
			return echo.NewHTTPError(http.StatusInternalServerError, "error")
		}

		// check user verify value in cache

		key := "user_verify:<user_id>"

		cmd := rdb.HExists(context.Background(), key, "verify_pin")

		// not found -> return error
		if cmd.Err() != nil {
			fmt.Printf("err: %v\n", cmd.Err())
			return echo.NewHTTPError(http.StatusInternalServerError, cmd.Err())
		}

		if !cmd.Val() {
			return echo.NewHTTPError(http.StatusInternalServerError, "User has been not verify")
		}

		// found -> do next process

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

func initRedisClusterConnection() *redis.ClusterClient {
	return database.GetRedisClusterConnection()
}
