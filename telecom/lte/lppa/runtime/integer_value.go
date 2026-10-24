// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/integer_value.go; SHA-256 987a88384cabb635af617552fd3c2cc29fe17c2d380392927cefdb52af6b8d04.
package runtime

import (
	"fmt"
	"math/big"
)

// ParseBigIntDecimal parses canonical base-10 ASN.1 INTEGER text.
func ParseBigIntDecimal(text string) (*big.Int, error) {
	if text == "" {
		return nil, fmt.Errorf("integer value is empty")
	}
	digits := text
	if digits[0] == '-' {
		digits = digits[1:]
		if digits == "" || digits == "0" {
			return nil, fmt.Errorf("integer value %q is not canonical", text)
		}
	}
	if digits == "" || len(digits) > 1 && digits[0] == '0' {
		return nil, fmt.Errorf("integer value %q is not canonical", text)
	}
	for index := range digits {
		if digits[index] < '0' || digits[index] > '9' {
			return nil, fmt.Errorf("integer value %q is not a base-10 integer", text)
		}
	}
	integer, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, fmt.Errorf("integer value %q is invalid", text)
	}
	return integer, nil
}

// MustParseBigIntDecimal is ParseBigIntDecimal for generated static values.
func MustParseBigIntDecimal(text string) *big.Int {
	value, err := ParseBigIntDecimal(text)
	if err != nil {
		panic(err)
	}
	return value
}
