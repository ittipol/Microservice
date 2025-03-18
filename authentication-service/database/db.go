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
		panic("failed to connect database")
	}

	fmt.Println("Database Connected")

	return conn
}
