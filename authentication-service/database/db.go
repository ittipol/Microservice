package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type sqlLogger struct {
	logger.Interface
}

func (sqlLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	sql, _ := fc()

	fmt.Printf("%v \n===============================\n", sql)
}

func CreateAndGetDbConnection(username string, password string, host string, port int, db string, dryRun bool) *gorm.DB {

	dsn := fmt.Sprintf("host=%v port=%v user=%v password=%v dbname=%v sslmode=disable TimeZone=Asia/Bangkok", host, port, username, password, db)

	return GetDbConnection(dsn)
}

func GetDbConnection(dsn string) *gorm.DB {

	fmt.Println(dsn)

	// conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
	// 	Logger: &sqlLogger{},
	// 	DryRun: dryRun,
	// })

	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("[conn] failed to connect database")
	}

	sqlDB, err := conn.DB()

	if err != nil {
		panic("[sqlDB] failed to connect database")
	}

	// OpenDB may just validate its arguments without creating a connection to the database
	// To verify that the data source name is valid call Ping()
	if err = sqlDB.Ping(); err != nil {
		panic("[Ping] failed to connect database")
	} else {
		fmt.Println("[Ping] Database Connected")
	}

	fmt.Println("::: Use connection pool: to avoid the overhead of opening and closing database connection all the time")
	fmt.Println("::: A connection Pool keeps these connections ready to go making working with databases much faster")

	// Connection Pool: avoid the overhead of opening and closing database connection all the time
	// A connection Pool keeps these connections ready to go making working with databases much faster

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxIdleConns(10)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(100)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Hour)

	return conn
}

// func GetPostgresdbConnection() *gorm.DB {

// 	conn, err := gorm.Open(postgres.New(postgres.Config{
// 		DSN:                  "host=localhost user=admin password=password dbname=postgresdb port=5432 sslmode=disable TimeZone=Asia/Shanghai", // data source name, refer https://github.com/jackc/pgx
// 		PreferSimpleProtocol: true,                                                                                                             // disables implicit prepared statement usage. By default pgx automatically uses the extended protocol
// 	}), &gorm.Config{})

// 	if err != nil {
// 		panic("failed to connect database")
// 	}

// 	fmt.Println("Database Connected")

// 	return conn
// }
