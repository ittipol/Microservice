package database

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

func GetRedisConnection(dsn string) *redis.Client {
	// redis://<user>:<pass>@localhost:6379/<db>

	// dsn := fmt.Sprintf("redis://%v:%v@%v:%v/%v", username, password, host, port, db)

	fmt.Println(dsn)

	opt, err := redis.ParseURL(dsn)
	if err != nil {
		panic(err)
	} else {
		println("Redis started...")
	}

	return redis.NewClient(opt)
}
