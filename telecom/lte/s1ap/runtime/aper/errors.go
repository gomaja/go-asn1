// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/errors.go; SHA-256 eac96f272a1acd5f45b9c759e783ee1a96f56599b07e1ecdc9dd71f6f1c86fb9.
package aper

import "errors"

var (
	ErrSyntax              = errors.New("aper: transfer syntax error")
	ErrLimit               = errors.New("aper: resource limit exceeded")
	ErrInvalidOptions      = errors.New("aper: invalid options")
	ErrBufferOverflow      = errors.New("per: buffer overflow")
	ErrInvalidValue        = errors.New("per: value out of range")
	ErrConstraintViolation = errors.New("per: constraint violation")
	ErrTruncated           = errors.New("per: data truncated")
	ErrExtraData           = errors.New("per: trailing data after value")
	// ErrResourceLimit reports an operational decode limit in decodeSettings,
	// not an X.691 rule.
	ErrResourceLimit = errors.New("per: decode resource limit exceeded")
	// ErrUnsupportedFragmentedNormallySmallLength reports a normally small
	// length requiring interleaved bitmap fragments under X.691 (02/2021)
	// 11.9.3.8. The current codec supports lengths through 16,383.
	ErrUnsupportedFragmentedNormallySmallLength = errors.New("per: fragmented normally small length is unsupported (ITU-T X.691 (02/2021) 11.9.3.8)")
)
