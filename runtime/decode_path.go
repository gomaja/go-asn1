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
		if pathErr.Path == segment || strings.HasPrefix(pathErr.Path, segment+".") || strings.HasPrefix(pathErr.Path, segment+"[") {
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
