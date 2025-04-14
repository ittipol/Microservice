package database

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

func GetRedisConnection(username string, password string, host string, port int, db int) *redis.Client {
	// redis://<user>:<pass>@localhost:6379/<db>

	dsn := fmt.Sprintf("redis://%v:%v@%v:%v/%v", username, password, host, port, db)
	println(dsn)
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		panic(err)
	} else {
		println("Redis started...")
	}

	return redis.NewClient(opt)
}
