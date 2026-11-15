// Code generated from ASN.1. DO NOT EDIT.

package tcap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
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

// Error formats the codec phase, component path and underlying cause; a root failure uses the cause text alone.
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

// Unwrap returns the underlying codec cause.
func (e *berPathError) Unwrap() error { return e.cause }

// ASN1BERPath returns the dot-separated component and collection path, or an empty string at the root or for a zero value.
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

// berDiagnosticError retains fmt's wrapper and text suffix while using the
// same source path as a validation finding or generated path decorator.
func berDiagnosticError(assignment, pattern string, args ...any) error {
	var cause error
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			cause = err
			break
		}
	}
	path := ""
	var finding *ber.ValidationError
	if errors.As(cause, &finding) {
		path = finding.Path
	} else {
		var located interface{ ASN1BERPath() string }
		if errors.As(cause, &located) {
			path = located.ASN1BERPath()
		}
	}
	prefix := pattern
	argumentPrefix := pattern == "%s: %w" && len(args) > 1
	if argumentPrefix {
		prefix, _ = args[0].(string)
	}
	phase, _, _ := strings.Cut(prefix, " ")
	if path == "" {
		path = assignment
	}
	if argumentPrefix {
		args[0] = phase + " " + path
	} else if _, suffix, ok := strings.Cut(pattern, ":"); ok {
		pattern = phase + " " + path + ":" + suffix
	}
	return fmt.Errorf(pattern, args...)
}

func qualifyBERError(err error, segment, phase string, qualifyConstraint bool, componentSource ...string) error {
	if err == nil {
		return nil
	}
	if _, hasPath := err.(interface{ ASN1BERPath() string }); !hasPath {
		var constraintErr *ber.ValidationError
		if errors.As(err, &constraintErr) {
			// Ordinary BER paths already carry their full constraint path in options.
			// Strict builder paths and DER qualify copies at reference boundaries.
			if !qualifyConstraint || segment == "" {
				return err
			}
			qualified := *constraintErr
			// A standalone assignment label gives way to its containing component.
			// The containing assignment declares this component (X.680 §16).
			if _, assignment, ok := strings.Cut(qualified.Source, "."); ok && assignment == qualified.Path {
				qualified.Path = segment
				if len(componentSource) > 0 {
					qualified.Source = componentSource[0]
				}
			} else if qualified.Path == "" {
				qualified.Path = segment
				if len(componentSource) > 0 {
					qualified.Source = componentSource[0]
				}
			} else {
				qualified.Path = segment + "." + qualified.Path
			}
			return &qualified
		}
	}
	return &berPathError{segment: segment, phase: phase, cause: err}
}
