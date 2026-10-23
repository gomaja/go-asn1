// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/errors.go; SHA-256 7f53dd4088bbd654dba03198d738614c5561414f8bedf6a5d7d46e4374c39191.
package aper

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
