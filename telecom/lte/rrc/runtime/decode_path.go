// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/decode_path.go; SHA-256 bd44776781516e76f6dc66a0355be48d9d799ae1d088e50f78915bfbc2a004c4.
package runtime

import "strings"

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
		return &DecodePathError{Path: segment + separator + pathErr.Path, Err: pathErr.Err}
	}
	return &DecodePathError{Path: segment, Err: err}
}
