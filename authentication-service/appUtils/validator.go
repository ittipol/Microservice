package appUtils

import (
	"authentication-service/errs"

	"github.com/go-playground/validator/v10"
)

type ValidatorUtil interface {
	ValidatePayload(req interface{}) error
}

type validatorUtil struct {
}

func NewValidatorUtil() ValidatorUtil {
	return &validatorUtil{}
}

func (obj validatorUtil) ValidatePayload(req interface{}) error {
	validate := validator.New()

	if err := validate.Struct(req); err != nil {
		return errs.NewBadRequestError()
	}

	return nil
}
