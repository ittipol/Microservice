package repositories

type User struct {
	ID       int64 `gorm:"primaryKey"`
	Password string
	Email    string `gorm:"unique;size:100"`
	Name     string `gorm:"size:100"`
}
