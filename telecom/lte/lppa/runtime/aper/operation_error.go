// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/operation_error.go; SHA-256 394a00ec14f70ee509edfde5349d36cbbf8c8044e5cc8521402b4ffed75e091d.
package aper

import "errors"

// OperationError attaches source context and the owned in-memory error identity.
// A nested located error keeps its category and original wire spans.
func OperationError(err error, path Path) error {
	if path == "" {
		path = "Value"
	}
	if err == nil {
		return nil
	}
	var located *DecodeError
	if errors.As(err, &located) {
		if located.Location.Path != "" && located.Location.Path != "open type" && located.Location.Path != "top-level value" {
			return err
		}
		copyError := *located
		copyError.Location.Path = path
		return &copyError
	}
	kind := InvalidValue
	if errors.Is(err, ErrInvalidOptions) {
		kind = InvalidOptions
	} else if errors.Is(err, ErrResourceLimit) || errors.Is(err, ErrLimit) {
		kind = Limit
	}
	return &DecodeError{Kind: kind, Location: Location{Path: path}, Err: err}
}
