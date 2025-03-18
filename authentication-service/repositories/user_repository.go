package repositories

import (
	"authentication-service/factory"
	"context"
	"database/sql"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
)

type userRepository struct {
	db     *gorm.DB
	tracer trace.Tracer
}

func NewUserRepository(db *gorm.DB, tracer trace.Tracer) UserRepository {
	return &userRepository{db, tracer}
}

func (r userRepository) GetUserById(ctx context.Context, id int) (user User, err error) {

	mainSpan := factory.NewTracerFactory(r.tracer, ctx, fmt.Sprintf("[%s] %d", "GetUserById", id))
	defer mainSpan.SpanEnd()

	sqlStr := r.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Where("id = @id", sql.Named("id", id)).First(&user)
	})

	mainSpan.SetAttributes(attribute.String("SQL", sqlStr))
	mainSpan.SetAttributes(attribute.String("ID", fmt.Sprintf("%d", id)))

	err = r.db.Where("id = @id", sql.Named("id", id)).First(&user).Error
	return user, err
}

func (r userRepository) GetUserByEmail(ctx context.Context, email string) (user User, err error) {

	mainSpan := factory.NewTracerFactory(r.tracer, ctx, fmt.Sprintf("[%s] %s", "GetUserByEmail", email))
	defer mainSpan.SpanEnd()

	sqlStr := r.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Where("email = @email", sql.Named("email", email)).First(&user)
	})

	mainSpan.SetAttributes(attribute.String("SQL", sqlStr))
	mainSpan.SetAttributes(attribute.String("Email", email))

	err = r.db.Where("email = @email", sql.Named("email", email)).First(&user).Error
	return user, err
}

func (r userRepository) GetUserByRefreshToken(ctx context.Context, id int, refreshToken string) (user User, err error) {

	mainSpan := factory.NewTracerFactory(r.tracer, ctx, fmt.Sprintf("[%s] %d", "GetUserByRefreshToken", id))
	defer mainSpan.SpanEnd()

	sqlStr := r.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Where(&User{ID: id, RefreshToken: refreshToken}).First(&user)
	})

	mainSpan.SetAttributes(attribute.String("SQL", sqlStr), attribute.String("ID", fmt.Sprintf("%d", id)), attribute.String("refresh_token", refreshToken))

	err = r.db.Where(&User{ID: id, RefreshToken: refreshToken}).First(&user).Error
	return user, err
}

func (r userRepository) SaveRefreshToken(ctx context.Context, id int, refreshToken string) error {

	mainSpan := factory.NewTracerFactory(r.tracer, ctx, fmt.Sprintf("[%s] %d", "SaveRefreshToken", id))
	defer mainSpan.SpanEnd()

	sqlStr := r.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Model(&User{}).Where("id = @id", sql.Named("id", id)).Update("refresh_token", refreshToken)
	})

	mainSpan.SetAttributes(attribute.String("SQL", sqlStr), attribute.String("ID", fmt.Sprintf("%d", id)), attribute.String("refresh_token", refreshToken))

	return r.db.Model(&User{}).Where("id = @id", sql.Named("id", id)).Update("refresh_token", refreshToken).Error
}

func (r userRepository) CreateUser(ctx context.Context, email string, hashedPassword string, name string) (id int, err error) {

	mainSpan := factory.NewTracerFactory(r.tracer, ctx, "CreateUser")
	defer mainSpan.SpanEnd()

	user := User{
		Email:    email,
		Password: hashedPassword,
		Name:     name,
	}

	sqlStr := r.db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Create(&user)
	})

	mainSpan.SetAttributes(attribute.String("SQL", sqlStr))
	mainSpan.SetAttributes(attribute.String("Email", email))
	mainSpan.SetAttributes(attribute.String("Hashed Password", hashedPassword))
	mainSpan.SetAttributes(attribute.String("Name", name))

	err = r.db.Create(&user).Error

	return id, err
}
