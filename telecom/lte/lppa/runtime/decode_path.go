// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/decode_path.go; SHA-256 eb14ddf5d44a4e16cf9096af114d6d94060ee92ca7d777c24722066d51468ac9.
package runtime

import (
	"errors"
	"strings"
)

// DecodePathError records the generated ASN.1 field path at which decoding
// failed while preserving the underlying codec error.
type DecodePathError struct {
	Path string
	Err  error
}

func (e *DecodePathError) Error() string {
	return "decoding " + e.Path + ": " + e.Err.Error()
}

func (e *DecodePathError) Unwrap() error {
	return e.Err
}

// WrapDecodePath prepends one generated ASN.1 type, field, or index segment to
// a decode error.
func WrapDecodePath(err error, segment string) error {
	if err == nil {
		return nil
	}
	if pathErr, ok := err.(*DecodePathError); ok {
		if strings.HasPrefix(pathErr.Path, segment+"[") {
			return pathErr
		}
		separator := "."
		if strings.HasPrefix(pathErr.Path, "[") {
			separator = ""
		}
		return &DecodePathError{Path: segment + separator + pathErr.Path, Err: withLocatedPath(pathErr.Err, segment+separator+pathErr.Path)}
	}
	// Procedure/table context may sit between the parent and a previously
	// located field. Preserve that inner path while retaining the context.
	var nested *DecodePathError
	if errors.As(err, &nested) {
		path := nested.Path
		if !strings.HasPrefix(path, segment+"[") {
			separator := "."
			if strings.HasPrefix(path, "[") {
				separator = ""
			}
			path = segment + separator + path
		}
		return &DecodePathError{Path: path, Err: withLocatedPath(err, path)}
	}
	return &DecodePathError{Path: segment, Err: withLocatedPath(err, segment)}
}

// A runtime-owned located error keeps its source identity while ancestors add paths.
func withLocatedPath(err error, path string) error {
	var located interface{ WithDecodePath(string) error }
	if errors.As(err, &located) {
		return &locatedPathContext{Err: err, located: located.WithDecodePath(path)}
	}
	return err
}

// Keep intermediate error messages while exposing the qualified owned location.
type locatedPathContext struct {
	Err     error
	located error
}

func (e *locatedPathContext) Error() string      { return e.Err.Error() }
func (e *locatedPathContext) Unwrap() error      { return e.Err }
func (e *locatedPathContext) As(target any) bool { return errors.As(e.located, target) }
