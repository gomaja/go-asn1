// Package ber provides BER/DER encoding and decoding primitives.
package ber

import (
	"errors"
	"fmt"
)

var (
	ErrTruncated        = errors.New("ber: unexpected end of data")
	ErrInvalidTag       = errors.New("ber: invalid tag encoding")
	ErrInvalidLength    = errors.New("ber: invalid length encoding")
	ErrIndefiniteLength = errors.New("ber: indefinite length not allowed in DER")
	ErrExtraData        = errors.New("ber: trailing data after value")
	ErrInvalidValue     = errors.New("ber: invalid value encoding")
	ErrUnsupported      = errors.New("ber: unsupported encoding")
)

// DecodeError provides context about where a decode failure occurred.
type DecodeError struct {
	Offset   int
	TypeName string
	Field    string
	Cause    error
}

func (e *DecodeError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("ber: decode %s.%s at offset %d: %v", e.TypeName, e.Field, e.Offset, e.Cause)
	}
	if e.TypeName != "" {
		return fmt.Sprintf("ber: decode %s at offset %d: %v", e.TypeName, e.Offset, e.Cause)
	}
	return fmt.Sprintf("ber: decode at offset %d: %v", e.Offset, e.Cause)
}

func (e *DecodeError) Unwrap() error {
	return e.Cause
}
