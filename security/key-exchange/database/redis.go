package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func GetRedisConnection(username string, password string, host string, port int, db int) *redis.Client {
	// redis://<user>:<pass>@localhost:6379/<db>
	// rediss://production-address:9091

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
		"vnode1-sit.ecache.krungsri.net:7010",
		// "redis-1.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		// "redis-2.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		// "redis-3.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		// "redis-4.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
		// "redis-5.redis-headless-svc-stateful.redis.svc.cluster.local:6379",
	}

	// clusterAddrs := []string{
	// 	"localhost:7000",
	// 	"localhost:7001",
	// 	"localhost:7002",
	// 	"localhost:7003",
	// 	"localhost:7004",
	// 	"localhost:7005",
	// }

	// rdb := redis.NewClusterClient(&redis.ClusterOptions{
	// 	Addrs:     clusterAddrs,
	// 	Username:  "appkma",
	// 	Password:  "nmnBnZoXUFd7AjCi4P_QyBWqHVC7Uv",
	// 	TLSConfig: &tls.Config{},

	// 	// To route commands by latency or randomly, enable one of the following.
	// 	RouteByLatency: true,
	// 	RouteRandomly:  true,
	// })

	// err := rdb.ForEachShard(context.Background(), func(ctx context.Context, shard *redis.Client) error {
	// 	return shard.Ping(ctx).Err()
	// })
	// if err != nil {
	// 	panic(err)
	// }

	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:       clusterAddrs,
		DialTimeout: time.Second * 30,
		NewClient: func(opt *redis.Options) *redis.Client {
			user, pass := userPassForAddr(opt.Addr)
			opt.Username = user
			opt.Password = pass
			opt.DB = 0
			// opt.Addr = "vnode1-sit.ecache.krungsri.net:7010"

			return redis.NewClient(opt)
		},
	})

	// err := rdb.ForEachShard(context.Background(), func(ctx context.Context, shard *redis.Client) error {
	// 	return shard.Ping(ctx).Err()
	// })

	cms := rdb.Ping(context.Background())

	if cms.Err() != nil {
		panic(cms.Err())
	}

	println("Redis cluster started...")

	return rdb
}

func userPassForAddr(addr string) (string, string) {
	return "appkma", "nmnBnZoXUFd7AjCi4P_QyBWqHVC7Uv"
}
