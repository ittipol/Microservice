package usersrv_test

import (
	"authentication-service/appUtils"
	"authentication-service/errs"
	"authentication-service/repositories"
	"authentication-service/services/usersrv"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProfileService(t *testing.T) {
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

	t.Run("User profile exist", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("GetUserById", 1).Return(repositories.User{
			ID:       1,
			Email:    "m1@email.com",
			Password: "$2a$12$ErV8S.A18n1nHftm5ph1Z./KhW/Kx41IVrliRSf1XuInN6TyPIAtC",
			Name:     "Mock 1",
		}, nil)

		accessToken, _, err := appJwt.GenToken(1)

		if err != nil {
			panic(err)
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %v", accessToken),
		}

		s := usersrv.NewUserService(userRepo, appJwt, nil)

		res, err := s.Profile(ctx, headers)

		assert.Equal(t, nil, err)
		assert.Equal(t, "Mock 1", res.Name)
	})

	t.Run("User profile not exist", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("GetUserById", 2).Return(repositories.User{}, errors.New("Not Found"))

		accessToken, _, err := appJwt.GenToken(2)

		if err != nil {
			panic(err)
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %v", accessToken),
		}

		s := usersrv.NewUserService(userRepo, appJwt, nil)

		res, err := s.Profile(ctx, headers)

		appErr, _ := errs.ParseError(err)

		assert.Empty(t, res)
		assert.EqualError(t, err, "User not found")
		assert.Equal(t, http.StatusNotFound, appErr.Code)
	})
}
