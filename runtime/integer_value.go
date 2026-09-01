package runtime

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// CloneBigInt returns a private copy of value. A nil value represents zero.
func CloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(value)
}

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

// MarshalBigIntJSON emits an exact decimal JSON string.
func MarshalBigIntJSON(value *big.Int) ([]byte, error) {
	return json.Marshal(CloneBigInt(value).String())
}

// UnmarshalBigIntJSON accepts an exact decimal JSON string or number.
func UnmarshalBigIntJSON(data []byte) (*big.Int, error) {
	var text string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return nil, fmt.Errorf("decoding integer value: %w", err)
		}
	} else {
		text = string(data)
	}
	return ParseBigIntDecimal(text)
}
