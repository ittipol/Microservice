package main

import (
	"fmt"
	"id-generator/helpers"
	"log"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

// var mu sync.Mutex
var wg sync.WaitGroup

func main() {

	fmt.Printf("\n\n=======================================================================================\n\n")

	// InitTimeZone()

	node, err := helpers.NewIDGenerator(1023, "2025-07-27 16:43:07")
	// node, err := helpers.NewIDGenerator(1023, "") // use current time as custom epoch
	if err != nil {
		log.Fatalln(err)
	}

	// Generate a 64 bit id
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func(i int) {

			defer wg.Done()

			sleepTimeMs := rand.Intn(10000) + 5000
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

			fmt.Printf("\n:: Generated ID value: %d\n", id)
			fmt.Printf(":: Binary representation [%v]: %s\n", len(binaryString), binaryString)

			// insert id to user table
			//

		}(i)
	}

	wg.Wait()
}

func Base10(value int64) string {
	return strconv.FormatInt(value, 10)
}

func BinaryToDecimal(binary string) (int, error) {
	decimalValue := 0
	base := 1 // Represents 2^0, 2^1, 2^2, ...

	for i := len(binary) - 1; i >= 0; i-- {
		digit := string(binary[i])
		if digit == "1" {
			decimalValue += base
		} else if digit != "0" {
			return 0, fmt.Errorf("invalid binary digit: %s", digit)
		}
		base *= 2
	}
	return decimalValue, nil
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

// func initDbConnection(dsn string) *gorm.DB {
// 	return database.GetDbConnection(dsn)
// }
