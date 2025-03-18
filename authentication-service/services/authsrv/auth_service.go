package authsrv

import (
	"authentication-service/appUtils"
	"authentication-service/errs"
	"authentication-service/factory"
	"authentication-service/helpers"
	"authentication-service/logs"
	"authentication-service/repositories"
	"context"
	"fmt"

	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	userRepository repositories.UserRepository
	jwtToken       appUtils.JwtUtil
	tracer         trace.Tracer
}

func NewAuthService(userRepository repositories.UserRepository, jwtToken appUtils.JwtUtil, tracer trace.Tracer) AuthService {
	return &authService{userRepository, jwtToken, tracer}
}

func (s authService) Login(ctx context.Context, email string, password string) (res authResponse, err error) {

	mainSpan := factory.NewTracerFactory(s.tracer, ctx, "Login service")
	defer mainSpan.SpanEnd()

	user, err := s.userRepository.GetUserByEmail(mainSpan.GetContext(), email)

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return res, errs.NewNotFoundError("Invalid username or password")
	}

	spanCompareHash := factory.NewTracerFactory(s.tracer, mainSpan.GetContext(), "CompareHashAndPassword")
	// Check password matching
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	spanCompareHash.SpanEnd()

	if err != nil {
		logs.Error(err)

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return res, errs.NewNotFoundError("Invalid username or password")
	}

	spanGenToken := factory.NewTracerFactory(s.tracer, mainSpan.GetContext(), fmt.Sprintf("[%s] ID: %d", "GenToken", user.ID))
	accessToken, refreshToken, err := s.jwtToken.GenToken(user.ID)
	spanGenToken.SpanEnd()

	if err != nil {
		logs.Error(err)

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return res, errs.NewUnexpectedError()
	}

	// Save latest refresh token into database
	err = s.userRepository.SaveRefreshToken(mainSpan.GetContext(), user.ID, refreshToken)

	if err != nil {
		logs.Error(err)

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return res, errs.NewUnexpectedError()
	}

	res = authResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return
}

func (s authService) Refresh(ctx context.Context, headers map[string]string) (res authResponse, err error) {

	mainSpan := factory.NewTracerFactory(s.tracer, ctx, "Refresh service")
	defer mainSpan.SpanEnd()

	value, _ := helpers.GetHeader(headers, "Authorization")

	tokenString, _ := helpers.GetBearerToken(value)

	token, err := s.jwtToken.Validate(tokenString, appUtils.RefreshTokenSecretKey)

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return res, errs.NewUnexpectedError()
	}

	claims, _ := token.Claims.(jwt.MapClaims)

	id := int(claims["id"].(float64))

	// Check it's latest refresh token in database
	user, err := s.userRepository.GetUserByRefreshToken(mainSpan.GetContext(), id, tokenString)

	if err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return res, errs.NewUnexpectedError()
	}

	// Gen new token
	accessToken, refreshToken, err := s.jwtToken.GenToken(user.ID)

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return res, errs.NewUnexpectedError()
	}

	// Save new refresh token into database
	s.userRepository.SaveRefreshToken(mainSpan.GetContext(), user.ID, refreshToken)

	if err != nil {
		logs.Error(err)
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return res, errs.NewUnexpectedError()
	}

	res = authResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return res, nil
}

func (s authService) Verify(ctx context.Context, headers map[string]string) error {

	mainSpan := factory.NewTracerFactory(s.tracer, ctx, "Verify service")
	defer mainSpan.SpanEnd()

	value, err := helpers.GetHeader(headers, "Authorization")

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return errs.NewBadRequestError()
	}

	tokenString, err := helpers.GetBearerToken(value)

	if err != nil {
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return errs.NewBadRequestError()
	}

	token, err := s.jwtToken.Validate(tokenString, appUtils.AccessTokenSecretKey)

	fmt.Printf("Token Valid: %v \n", token.Valid)

	if err != nil {
		logs.Error(fmt.Sprintf("Error: %v \n", err.Error()))
		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())
		return errs.NewError(http.StatusOK, "Invalid Token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Printf("Res: %v \n", claims)
	}

	return nil
}
