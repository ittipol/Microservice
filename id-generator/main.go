package main

import (
	"fmt"
	"id-generator/database"
	"id-generator/helpers"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

var wg sync.WaitGroup
var mu sync.Mutex
var c Config

func init() {
	c.loadConfig("config.yaml")

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Error getting hostname: %v", err)
	}
	fmt.Printf("Machine hostname: %s\n", hostname)
}

func main() {

	// var c Config
	// c.loadConfig("config.yaml")

	// db := initDbConnection("")

	// Test generate an ID
	// func1()
	// func2()

	nodeId := os.Getenv("NODE_ID")
	fmt.Println("Node ID:", nodeId)

	nodeIdNumber, err := strconv.ParseInt(nodeId, 10, 64)

	if err != nil {
		fmt.Printf("Error converting string to int64: %v\n", err)
		return
	}

	node, err := helpers.NewSnowflakeGenerator(nodeIdNumber, "2025-07-27 16:43:07") // use specific time (starting point for timestamp)
	// node, err := helpers.NewSnowflakeGenerator(1023, "") // use current time as custom epoch
	if err != nil {
		log.Fatalln(err)
	}

	e := echo.New()
	// Debug mode
	e.Debug = true

	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "Service is running")
	})

	e.GET("/test", func(c echo.Context) error {
		nodeId := os.Getenv("NODE_ID")
		fmt.Println("Node ID:", nodeId)
		return c.String(http.StatusOK, "Test")
	})

	e.GET("/generate", func(c echo.Context) error {

		id, err := node.GenerateID()
		if err != nil {
			fmt.Println(err)
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		binaryString := strconv.FormatInt(id, 2)

		fmt.Printf("\n:: Generated ID value (base10): %d | length: %d\n", id, len(strconv.FormatInt(id, 10)))
		fmt.Printf(":: Binary representation [bit length: %d/64 bits]: %s\n", len(binaryString), binaryString)

		// insert id to user table
		//

		return c.String(http.StatusOK, strconv.FormatInt(id, 10))
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%v", c.AppPort)))
}

func func2() {

	// Specific time
	// t := time.Date(2025, time.January, 1, 12, 30, 0, 0, time.UTC)

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			mu.Lock()
			defer mu.Unlock()

			// gen timestamp
			// timestamp := time.Now().UnixMilli()
			timestamp := time.Now().UnixMicro()

			fmt.Printf("\ntimestamp = %d\n", timestamp)
			fmt.Printf("\nid (base62) = %s\n\n", helpers.ConvertToBase62(int(timestamp)))
		}(i)
	}

	wg.Wait()
}

func func1() {

	fmt.Printf("\n\n=======================================================================================\n\n")

	// InitTimeZone()

	node, err := helpers.NewSnowflakeGenerator(1023, "2025-07-27 16:43:07") // use specific time (starting point for timestamp)
	// node, err := helpers.NewSnowflakeGenerator(1023, "") // use current time as custom epoch
	if err != nil {
		log.Fatalln(err)
	}

	// Generate a 64 bit id
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {

			defer wg.Done()

			sleepTimeMs := rand.Intn(15000) + 2000
			sleepDuration := time.Duration(sleepTimeMs) * time.Millisecond
			fmt.Printf("\nSleeping for %d milliseconds...\n", sleepTimeMs)
			time.Sleep(sleepDuration)

			fmt.Printf("\n\n======== Value [%v] =======================================================================================\n\n", i)

			id, err := node.GenerateID()
			if err != nil {
				fmt.Println(err)
				return
			}

			binaryString := strconv.FormatInt(id, 2)

			fmt.Printf("\n:: Generated ID value (base10): %d\n", id)
			fmt.Printf(":: Binary representation [bit length: %d/64 bits]: %s\n", len(binaryString), binaryString)

			// insert id to user table
			//

		}(i)
	}

	wg.Wait()
}

// func InitTimeZone() {
// 	// LoadLocation looks for the IANA Time Zone database
// 	// List of tz database time zones
// 	// https: //en.wikipedia.org/wiki/List_of_tz_database_time_zones
// 	location, err := time.LoadLocation("Asia/Bangkok")
// 	if err != nil {
// 		panic(err)
// 	}

// 	// init system time zone
// 	time.Local = location

// 	// timeInUTC := time.Date(2018, 8, 30, 12, 0, 0, 0, time.UTC)
// 	// fmt.Println(timeInUTC.In(location))
// }

func initDbConnection(dsn string) *gorm.DB {
	return database.GetDbConnection(dsn)
}
