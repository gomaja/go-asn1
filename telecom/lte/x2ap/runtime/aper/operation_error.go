// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/operation_error.go; SHA-256 ae19cd6fc0445c5ee0e2be2164c46141a81058a86343ac2c67cad79ebdb94215.
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
		if located.Location.Path != "" {
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
