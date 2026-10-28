// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ms_datatypes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// berPathError preserves codec causes and offsets while carrying an ASN.1 path
// across nested packages. X.680 (02/2021) §§25, 27–29 define the components;
// path formatting and error chaining are diagnostic contracts of this codec.
// A type's outer TLV has an empty path; only enclosing components or
// collection elements contribute segments. A cause without a path also
// denotes the root. Type labels remain message context, outside the path.
type berPathError struct {
	segment string
	phase   string
	cause   error
}

// Error formats the codec phase, ASN.1 path and underlying cause.
func (e *berPathError) Error() string {
	cause := berErrorCause(e.cause)
	if path := e.ASN1BERPath(); path != "" {
		return fmt.Sprintf("%s %s: %v", e.phase, path, cause)
	}
	return cause.Error()
}

// berErrorCause removes only path decorators and transparent element locations
// from the formatted view. The original chain is retained for Unwrap/Is/As.
func berErrorCause(cause error) error {
	for cause != nil {
		switch cause.(type) {
		case interface{ ASN1BERPath() string }, *ber.ElementError:
			next := errors.Unwrap(cause)
			if next == nil {
				return cause
			}
			cause = next
		default:
			return cause
		}
	}
	return nil
}

// Unwrap returns the underlying codec error.
func (e *berPathError) Unwrap() error { return e.cause }

// ASN1BERPath returns the nested component and collection-element path.
func (e *berPathError) ASN1BERPath() string {
	var parts []string
	for current := error(e); current != nil; {
		switch value := current.(type) {
		case *berPathError:
			if value.segment != "" {
				parts = append(parts, value.segment)
			}
			current = value.cause
		case interface{ ASN1BERPath() string }:
			if path := value.ASN1BERPath(); path != "" {
				parts = append(parts, path)
			}
			current = nil
		case *ber.DecodeError:
			if value.Field != "" {
				parts = append(parts, value.Field)
			}
			current = nil
		default:
			current = errors.Unwrap(current)
		}
	}
	return strings.Join(parts, ".")
}

func qualifyBERError(err error, segment, phase string, qualifyConstraint bool) error {
	if err == nil {
		return nil
	}
	if _, hasPath := err.(interface{ ASN1BERPath() string }); !hasPath {
		var constraintErr *ber.ValidationError
		if errors.As(err, &constraintErr) {
			// BER checks already receive their full path through child options. DER
			// has no tolerance options: qualify a copy at each generated boundary.
			if !qualifyConstraint || segment == "" {
				return err
			}
			qualified := *constraintErr
			if qualified.Path == "" {
				qualified.Path = segment
			} else {
				qualified.Path = fmt.Sprintf("%s.%s", segment, qualified.Path)
			}
			return &qualified
		}
	}
	return &berPathError{segment: segment, phase: phase, cause: err}
}
