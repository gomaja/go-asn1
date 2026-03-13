// Package per implements PER (Packed Encoding Rules) codec primitives
// for ASN.1 UPER and APER encoding/decoding.
package per

import "errors"

var (
	ErrBufferOverflow     = errors.New("per: buffer overflow")
	ErrInvalidValue       = errors.New("per: value out of range")
	ErrConstraintViolation = errors.New("per: constraint violation")
	ErrTruncated          = errors.New("per: data truncated")
)
