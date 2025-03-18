package usersrv

import (
	"authentication-service/appUtils"
	"authentication-service/errs"
	"authentication-service/factory"
	"authentication-service/helpers"
	"authentication-service/logs"
	"authentication-service/repositories"
	"context"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	userRepository repositories.UserRepository
	jwtToken       appUtils.JwtUtil
	tracer         trace.Tracer
}

func NewUserService(userRepository repositories.UserRepository, jwtToken appUtils.JwtUtil, tracer trace.Tracer) UserService {
	return &userService{userRepository, jwtToken, tracer}
}

func (s userService) Register(ctx context.Context, email string, password string, name string) error {

	mainSpan := factory.NewTracerFactory(s.tracer, ctx, "Register service")
	defer mainSpan.SpanEnd()

	// hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)

	if err != nil {
		logs.Error(err)

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return errs.NewUnauthorizedError()
	}

	_, err = s.userRepository.CreateUser(mainSpan.GetContext(), email, string(hashedPassword), name)

	if err != nil {
		logs.Error(err)

		mainSpan.RecordError(err)
		mainSpan.SetStatus(codes.Error, codes.Error.String())

		return errs.NewUnexpectedError()
	}

	return nil
}

func (s userService) Profile(ctx context.Context, headers map[string]string) (res profileResponse, err error) {

	mainSpan := factory.NewTracerFactory(s.tracer, ctx, "Profile service")
	defer mainSpan.SpanEnd()

	value, _ := helpers.GetHeader(headers, "Authorization")

	tokenString, _ := helpers.GetBearerToken(value)

	token, _ := s.jwtToken.Validate(tokenString, appUtils.AccessTokenSecretKey)

	claims, _ := token.Claims.(jwt.MapClaims)

	id := int(claims["id"].(float64))

	user, err := s.userRepository.GetUserById(mainSpan.GetContext(), id)

	if err != nil {
		return res, errs.NewNotFoundError("User not found")
	}

	res.Name = user.Name

	return res, err
}
