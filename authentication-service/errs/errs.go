package errs

import "net/http"

type ErrorType int

const (
	None ErrorType = iota
	CustomerError
	DefaultError
)

type appError struct {
	Code    int
	Message string
}

func NewError(code int, message string) error {
	return &appError{
		Code:    code,
		Message: message,
	}
}

func NewNotFoundError(message string) error {
	return &appError{
		Code:    http.StatusNotFound,
		Message: message,
	}
}

func NewBadRequestError() error {
	return &appError{
		Code:    http.StatusBadRequest,
		Message: "Bad Request",
	}
}

func NewUnexpectedError() error {
	return &appError{
		Code:    http.StatusInternalServerError,
		Message: "Unexpected Error",
	}
}

func NewUnauthorizedError() error {
	return &appError{
		Code:    http.StatusUnauthorized,
		Message: "Unauthorized",
	}
}

func (err appError) Error() string {
	return err.Message
}

func IsCustomError(err error) bool {
	_, ok := err.(*appError)
	return ok
}

func ParseError(err error) (appErr appError, errType ErrorType) {

	switch v := err.(type) {
	case *appError:
		return appError{
			Code:    v.Code,
			Message: v.Message,
		}, CustomerError
	case error:
		return appError{
			Message: v.Error(),
		}, DefaultError
	}

	return appError{}, None
}
