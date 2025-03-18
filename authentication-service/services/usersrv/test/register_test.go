package usersrv_test

import (
	"authentication-service/repositories"
	"authentication-service/services/usersrv"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegisterService(t *testing.T) {
	ctx := context.Background()

	t.Run("Create user success", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("CreateUser", "m1@email.com").Return(1, nil)

		s := usersrv.NewUserService(userRepo, nil, nil)

		err := s.Register(ctx, "m1@email.com", "", "")

		assert.Equal(t, nil, err)
	})

	t.Run("Create user fail", func(t *testing.T) {

		userRepo := repositories.NewUserRepositoryMock()

		userRepo.On("CreateUser", "m2@email.com").Return(0, errors.New("Not Found"))

		s := usersrv.NewUserService(userRepo, nil, nil)

		err := s.Register(ctx, "m2@email.com", "", "")

		assert.EqualError(t, err, "Unexpected Error")
	})
}
