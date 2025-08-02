package main

import (
	"fmt"
	"id-generator/database"
	"id-generator/helpers"
	"log"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"
)

var wg sync.WaitGroup
var mu sync.Mutex

func main() {

	// db := initDbConnection("")

	func1()
	// func2()
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

	node, err := helpers.NewIDGenerator(1023, "2025-07-27 16:43:07") // use specific time (starting point for timestamp)
	// node, err := helpers.NewIDGenerator(1023, "") // use current time as custom epoch
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
