package appUtils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SecretKeyType int

const (
	AccessTokenSecretKey SecretKeyType = iota
	RefreshTokenSecretKey
)

type accessTokenClaims struct {
	ID int `json:"id"`
	jwt.RegisteredClaims
}

type refreshTokenClaims struct {
	ID int `json:"id"`
	jwt.RegisteredClaims
}

type JwtUtil interface {
	GenToken(id int) (accessToken string, refreshToken string, err error)
	Validate(tokenString string, secretKeyType SecretKeyType) (token *jwt.Token, err error)
}

type jwtUtil struct {
	accessTokenSecret  []byte
	refreshTokenSecret []byte
}

func NewJwtUtil(accessTokenSecret []byte, refreshTokenSecret []byte) JwtUtil {
	return &jwtUtil{accessTokenSecret, refreshTokenSecret}
}

func (obj jwtUtil) GenToken(id int) (accessToken string, refreshToken string, err error) {

	now := time.Now()

	// Gen access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims{
		id,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	// Sign and get the complete encoded token as a string using the secret
	accessToken, err = token.SignedString(obj.accessTokenSecret)

	if err != nil {
		return
	}

	// Gen refresh token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims{
		id,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	// Sign and get the complete encoded token as a string using the secret
	refreshToken, err = token.SignedString(obj.refreshTokenSecret)

	// fmt.Printf("A_KEY: %v \n", obj.accessTokenSecret)
	// fmt.Printf("R_KEY: %v \n", obj.refreshTokenSecret)

	return
}

func (obj jwtUtil) Validate(tokenString string, secretKeyType SecretKeyType) (token *jwt.Token, err error) {

	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		switch secretKeyType {
		case RefreshTokenSecretKey:
			return obj.refreshTokenSecret, nil
		default:
			return obj.accessTokenSecret, nil
		}
	})

	return
}
