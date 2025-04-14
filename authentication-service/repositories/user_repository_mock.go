package repositories

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type userRepositoryMock struct {
	mock.Mock
}

func NewUserRepositoryMock() *userRepositoryMock {
	return &userRepositoryMock{}
}

func (m *userRepositoryMock) GetUserById(ctx context.Context, id int) (User, error) {
	args := m.Called(id)

	// Return mock data
	return args.Get(0).(User), args.Error(1)
}

func (m *userRepositoryMock) GetUserByEmail(ctx context.Context, email string) (User, error) {
	args := m.Called(email)

	return args.Get(0).(User), args.Error(1)
}

func (m *userRepositoryMock) GetLatestRefreshToken(ctx context.Context, id int, refreshToken string) (token string, err error) {
	args := m.Called(id)

	return args.Get(0).(string), args.Error(1)
}

func (m *userRepositoryMock) SaveRefreshToken(ctx context.Context, id int, refreshToken string) error {
	args := m.Called(id)

	return args.Error(0)
}

func (m *userRepositoryMock) CreateUser(ctx context.Context, email string, hashedPassword string, name string) (int, error) {
	args := m.Called(email)

	return args.Get(0).(int), args.Error(1)
}
