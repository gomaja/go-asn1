// Package per implements PER (Packed Encoding Rules) codec primitives
// for ASN.1 UPER and APER encoding/decoding.
//
// Extension-addition bitmaps requiring 16K or more bits use the fragmented
// normally small length form of ITU-T X.691 (02/2021) 11.9.3.8. That form is
// not implemented. Encoders and decoders return
// ErrUnsupportedFragmentedNormallySmallLength instead of emitting or accepting
// an incomplete bitmap.
package per

import "errors"

var (
	ErrBufferOverflow      = errors.New("per: buffer overflow")
	ErrInvalidValue        = errors.New("per: value out of range")
	ErrConstraintViolation = errors.New("per: constraint violation")
	ErrTruncated           = errors.New("per: data truncated")
	ErrExtraData           = errors.New("per: trailing data after value")
	// ErrResourceLimit reports an operational decode limit in DecodeOptions,
	// not an X.691 rule.
	ErrResourceLimit = errors.New("per: decode resource limit exceeded")
	// ErrUnsupportedFragmentedNormallySmallLength reports a normally small
	// length requiring interleaved bitmap fragments under X.691 (02/2021)
	// 11.9.3.8. The current codec supports lengths through 16,383.
	ErrUnsupportedFragmentedNormallySmallLength = errors.New("per: fragmented normally small length is unsupported (ITU-T X.691 (02/2021) 11.9.3.8)")
)
