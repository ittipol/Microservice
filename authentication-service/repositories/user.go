package repositories

import "context"

type User struct {
	ID       int `gorm:"primaryKey;autoIncrement"`
	Password string
	Email    string `gorm:"unique;size:100"`
	Name     string `gorm:"size:100"`
	// RefreshToken string
}

type UserRepository interface {
	GetUserById(ctx context.Context, id int) (user User, err error)
	GetUserByEmail(ctx context.Context, email string) (user User, err error)
	GetLatestRefreshToken(ctx context.Context, id int, refreshToken string) (token string, err error)
	SaveRefreshToken(ctx context.Context, id int, refreshToken string) error
	CreateUser(ctx context.Context, email string, hashedPassword string, name string) (id int, err error)
}
