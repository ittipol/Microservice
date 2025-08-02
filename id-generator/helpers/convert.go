package helpers

import (
	"fmt"
	"strconv"
)

const base62Digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func Base10(value int64) string {
	return strconv.FormatInt(value, 10)
}

func BinaryToDecimal(binary string) (int, error) {
	decimalValue := 0
	base := 1 // Represents 2^0, 2^1, 2^2, ...

	for i := len(binary) - 1; i >= 0; i-- {
		digit := string(binary[i])
		if digit == "1" {
			decimalValue += base
		} else if digit != "0" {
			return 0, fmt.Errorf("invalid binary digit: %s", digit)
		}
		base *= 2
	}
	return decimalValue, nil
}

func ConvertToBase62(number int) string {
	base62 := ""
	for number > 0 {
		remainder := number % 62
		base62 = string(base62Digits[remainder]) + base62
		number /= 62
	}
	return base62
}
