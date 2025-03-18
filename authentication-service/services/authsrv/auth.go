package authsrv

import "context"

type authResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthService interface {
	Login(ctx context.Context, email string, password string) (res authResponse, err error)
	Refresh(ctx context.Context, headers map[string]string) (res authResponse, err error)
	Verify(ctx context.Context, headers map[string]string) error
}
