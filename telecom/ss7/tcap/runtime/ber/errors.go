// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/errors.go; SHA-256 05d517412eb049ea262303f5b03a4b10252116a8d8775c51755343ab99b4f1f4.
package ber

import (
	"errors"
	"fmt"
)

var (
	ErrTruncated  = errors.New("ber: unexpected end of data")
	ErrInvalidTag = errors.New("ber: invalid tag encoding")
	// ErrUnexpectedElement means a complete BER element is not admitted at this
	// position, or a required element is absent. X.680 (02/2021) §§25.1,
	// 25.11, 29.1–29.3 define component and CHOICE membership; X.690 (02/2021)
	// §§8.1.2, 8.9, 8.18.1 encode their tags and constructed contents.
	ErrUnexpectedElement = errors.New("ber: unexpected or missing element")
	ErrInvalidLength     = errors.New("ber: invalid length encoding")
	ErrIndefiniteLength  = errors.New("ber: indefinite length not allowed in DER")
	ErrExtraData         = errors.New("ber: trailing data after value")
	ErrInvalidValue      = errors.New("ber: invalid value encoding")
	ErrUnsupported       = errors.New("ber: unsupported encoding")
	ErrResourceLimit     = errors.New("ber: resource limit exceeded")
)

// DecodeError provides context about where a decode failure occurred.
type DecodeError struct {
	Offset   int
	TypeName string
	Field    string
	Cause    error
}

// Error describes the field, byte offset and underlying decode cause.
func (e *DecodeError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("ber: decode %s.%s at offset %d: %v", e.TypeName, e.Field, e.Offset, e.Cause)
	}
	if e.TypeName != "" {
		return fmt.Sprintf("ber: decode %s at offset %d: %v", e.TypeName, e.Offset, e.Cause)
	}
	return fmt.Sprintf("ber: decode at offset %d: %v", e.Offset, e.Cause)
}

// Unwrap returns the underlying decode cause.
func (e *DecodeError) Unwrap() error {
	return e.Cause
}

// ElementError locates a whole-tree BER validation failure without changing
// its diagnostic text or cause. Offset is the failing TLV's identifier offset
// relative to the input passed to ValidateBERElement. ChildIndexes are
// zero-based child positions, from the root's children to the failing TLV;
// the root itself has an empty ancestry. EOC markers are not children.
// A missing EOC or invalid concatenated string locates its enclosing TLV.
// Generated codecs can translate these positions to ASN.1 component names
// and collection indexes. This diagnostic API imposes no new wire rules.
type ElementError struct {
	offset       int
	childIndexes []int
	cause        error
}

// Error returns the underlying BER validation diagnostic text.
func (e *ElementError) Error() string { return e.cause.Error() }

// Unwrap returns the underlying BER validation cause.
func (e *ElementError) Unwrap() error { return e.cause }

// Offset returns the identifier offset of the failing TLV.
func (e *ElementError) Offset() int { return e.offset }

// ChildIndexes returns an independent copy of the failing TLV's ancestry.
func (e *ElementError) ChildIndexes() []int {
	return append([]int(nil), e.childIndexes...)
}
