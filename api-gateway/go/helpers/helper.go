package helpers

import (
	"errors"
	"reflect"
	"strings"
)

func GetVarType(any interface{}) reflect.Type {
	return reflect.TypeOf(any)
}

func GetHeader(headers map[string]string, key string) (value string, err error) {

	value, ok := headers[key]
	if !ok {
		return "", errors.New("Key not found")
	}

	return value, nil
}

func GetBearerToken(bearerToken string) (token string, err error) {

	parts := strings.Split(bearerToken, " ")
	if len(parts) < 2 {
		return "", errors.New("Token not found")
	}

	return parts[1], nil
}
