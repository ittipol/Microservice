package database

import (
	"context"
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
	}

	rdb := redis.NewClient(opt)

	cmd := rdb.Ping(context.Background())

	if cmd.Err() != nil {
		panic(cmd.Err())
	}

	println("Redis started...")

	return rdb
}

func GetRedisClusterConnection() *redis.ClusterClient {

	clusterAddrs := []string{
		"redis-0.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		"redis-1.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		"redis-2.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		"redis-3.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		"redis-4.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		"redis-5.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
	}

	// clusterAddrs := []string{
	// 	"localhost:7000",
	// 	"localhost:7001",
	// 	"localhost:7002",
	// 	"localhost:7003",
	// 	"localhost:7004",
	// 	"localhost:7005",
	// }

	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: clusterAddrs,

		// To route commands by latency or randomly, enable one of the following.
		//RouteByLatency: true,
		//RouteRandomly: true,
	})

	err := rdb.ForEachShard(context.Background(), func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	if err != nil {
		panic(err)
	}

	// rdb2 := redis.NewClusterClient(&redis.ClusterOptions{
	// 	NewClient: func(opt *redis.Options) *redis.Client {

	// 		return redis.NewClient(opt)
	// 	},
	// })

	println("Redis cluster started...")

	return rdb
}
