// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/decode_error.go; SHA-256 8909cdccff4fb321479796d150da68fefbb6eb04228bbd495b49fddaf1bb522a.
package aper

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrorKind distinguishes source-value, transfer-syntax, and operational errors.
type ErrorKind uint8

const (
	InvalidValue ErrorKind = iota + 1
	Syntax
	Limit
	InvalidOptions
)

// DecodeError identifies the innermost failing source rule and original input.
// Wrapping a DecodeError adds path context without changing its wire spans.
type DecodeError struct {
	Kind     ErrorKind
	Location Location
	Rule     SourceRule
	Err      error
}

func (e *DecodeError) Error() string {
	if e.Location.Path == "" {
		if e.Rule.Document == "" {
			return fmt.Sprint(e.Err)
		}
		return fmt.Sprintf("%s %s: %v", e.Rule.Document, e.Rule.Clause, e.Err)
	}
	return fmt.Sprintf("%s %s at %s: %v", e.Rule.Document, e.Rule.Clause, e.Location.Path, e.Err)
}
func (e *DecodeError) Unwrap() error { return e.Err }
func (e *DecodeError) Is(target error) bool {
	switch e.Kind {
	case Syntax:
		return target == ErrSyntax
	case Limit:
		return target == ErrLimit
	case InvalidOptions:
		return target == ErrInvalidOptions
	case InvalidValue:
		return target == ErrInvalidValue
	}
	return false
}

func (bb *BitBuffer) syntaxError(start int, clause, message string, cause error) error {
	if cause == nil {
		cause = ErrInvalidValue
	}
	location := Location{}
	if start >= 0 && bb.BitPos() >= start {
		location.Spans, location.HasWireLocation = originalRange(bb, uint64(start), uint64(bb.BitPos()))
	}
	if message == "" {
		return &DecodeError{Kind: Syntax, Location: location, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: clause}, Err: cause}
	}
	return &DecodeError{Kind: Syntax, Location: location, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: clause}, Err: fmt.Errorf("%w: %s", cause, message)}
}

// WithDecodePath adds generated ancestor context without changing the failing rule.
func (e *DecodeError) WithDecodePath(path string) error {
	copyError := *e
	copyError.Location = e.Location
	copyError.Location.Path = Path(path)
	return &copyError
}

// decodeFailure wraps only a failing return; successful hot scalar decoders
// need no deferred locator. The deepest rule and original span remain owned
// by the decoder that first refused the field.
func (bb *BitBuffer) decodeFailure(start int, clause string, err error) error {
	bb.locateDecodeFailure(start, clause, &err)
	return err
}

// locateDecodeFailure preserves the innermost rule and original-input span.
// Each caller names the clause that defines its field, before reading it.
func (bb *BitBuffer) locateDecodeFailure(start int, clause string, failure *error) {
	if *failure == nil {
		return
	}
	var located *DecodeError
	if errors.As(*failure, &located) {
		return
	}
	if errors.Is(*failure, ErrResourceLimit) {
		wrapped := bb.syntaxError(start, clause, "", *failure).(*DecodeError)
		wrapped.Kind = Limit
		wrapped.Err = *failure
		*failure = wrapped
		return
	}
	wrapped := bb.syntaxError(start, clause, "", *failure).(*DecodeError)
	wrapped.Err = *failure
	*failure = wrapped
}

// X.691 (02/2021) §11.5.7 selects the constrained whole-number field width.
func constrainedWholeClause(lb, ub int64) string {
	if lb > ub {
		return "§11.5.2"
	}
	difference := uint64(ub) - uint64(lb)
	switch {
	case difference < 255:
		return "§11.5.7.1"
	case difference == 255:
		return "§11.5.7.2"
	case difference < 65536:
		return "§11.5.7.3"
	default:
		return "§11.5.7.4"
	}
}
func bitStringClause(lb, ub int64, constrained, extensible bool) string {
	if extensible {
		return "§16.6"
	}
	if constrained && lb == ub && ub < 65536 {
		if ub <= 16 {
			return "§16.9"
		}
		return "§16.10"
	}
	return "§16.11"
}
func octetStringClause(lb, ub int64, constrained, extensible bool) string {
	if extensible {
		return "§17.3"
	}
	if constrained && lb == ub && ub < 65536 {
		if ub <= 2 {
			return "§17.6"
		}
		return "§17.7"
	}
	return "§17.8"
}

func integerClause(lb, ub *int64, extensible bool) string {
	if extensible {
		return "§13.1"
	}
	if lb != nil && ub != nil {
		return "§13.2.2"
	}
	if lb != nil {
		return "§13.2.3"
	}
	return "§13.2.4"
}
func integerBigClause(lb, ub *big.Int, extensible bool) string {
	if extensible {
		return "§13.1"
	}
	if lb != nil && ub != nil {
		return "§13.2.2"
	}
	if lb != nil {
		return "§13.2.3"
	}
	return "§13.2.4"
}
