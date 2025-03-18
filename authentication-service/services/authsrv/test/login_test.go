package authsrv_test

import (
	"authentication-service/appUtils"
	"authentication-service/repositories"
	"authentication-service/services/authsrv"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginService(t *testing.T) {

	ctx := context.Background()

	jwtAccessTokenSecretKey, err := base64.StdEncoding.DecodeString("9PxBAw5rk3JqIQkV50VjX7Ek45YnmKoVmqutTs+GcH02Zs+d71tQEJJ0hMrUqsTnV71DYpGT4KQ40xrjATku2Q==")

	if err != nil {
		panic(err)
	}

	jwtRefreshTokenSecretKey, err := base64.StdEncoding.DecodeString("Wfkw+jBBVDuWYeQP1zPzKoBjRI6sSf6XeDmbgek0QLIVDeL1lLYy07g2zmfywf5IZRT6tLvBPFjHt8xm8czQaQ==")

	if err != nil {
		panic(err)
	}

	appJwt := appUtils.NewJwtUtil([]byte(jwtAccessTokenSecretKey), []byte(jwtRefreshTokenSecretKey))

	t.Run("Login success", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("GetUserByEmail", "m1@email.com").Return(repositories.User{
			ID:       1,
			Email:    "m1@email.com",
			Password: "$2a$12$ErV8S.A18n1nHftm5ph1Z./KhW/Kx41IVrliRSf1XuInN6TyPIAtC",
			Name:     "Mock 1",
		}, nil)

		userRepo.On("GetUserByEmail", "m1@email.com").Return(repositories.User{
			ID:       1,
			Email:    "m1@email.com",
			Password: "$2a$12$ErV8S.A18n1nHftm5ph1Z./KhW/Kx41IVrliRSf1XuInN6TyPIAtC",
			Name:     "Mock 1",
		}, nil)

		userRepo.On("SaveRefreshToken", 1).Return(nil)

		s := authsrv.NewAuthService(userRepo, appJwt, nil)

		res, err := s.Login(ctx, "m1@email.com", "1234")

		assert.Equal(t, nil, err)
		assert.NotEmpty(t, res.AccessToken)
		assert.NotEmpty(t, res.RefreshToken)
	})

	t.Run("Login fail user not found", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("GetUserByEmail", "m2@email.com").Return(repositories.User{}, errors.New("User not found"))

		s := authsrv.NewAuthService(userRepo, appJwt, nil)

		res, err := s.Login(ctx, "m2@email.com", "1234")

		assert.Empty(t, res)
		assert.EqualError(t, err, "Invalid username or password")
	})

	t.Run("Login fail save refresh token error", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("GetUserByEmail", "m1@email.com").Return(repositories.User{
			ID:       1,
			Email:    "m1@email.com",
			Password: "$2a$12$ErV8S.A18n1nHftm5ph1Z./KhW/Kx41IVrliRSf1XuInN6TyPIAtC",
			Name:     "Mock 1",
		}, nil)

		userRepo.On("SaveRefreshToken", 1).Return(errors.New("Save refresh token error"))

		s := authsrv.NewAuthService(userRepo, appJwt, nil)

		res, err := s.Login(ctx, "m1@email.com", "1234")

		assert.Empty(t, res)
		assert.EqualError(t, err, "Unexpected Error")
	})
}
