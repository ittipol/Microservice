package usersrv

import "context"

type profileResponse struct {
	Name string `json:"name"`
}

type UserService interface {
	Register(ctx context.Context, email string, password string, name string) error
	Profile(ctx context.Context, headers map[string]string) (res profileResponse, err error)
}
