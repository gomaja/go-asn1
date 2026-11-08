// Code generated from formal ASN.1 objects and values. DO NOT EDIT.

package gsm0902_v4_19_1

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// SourceRef identifies the formal source assignment, not procedure policy.
type SourceRef struct{ Document, Edition, Clause, Module, Assignment, SHA256 string }
type TypeRef struct{ ModuleOID, ASN1Name, GoPackage, GoName string }

// NoParameter denotes an absent source type field. It has no NULL codec.
type NoParameter struct{}

// ErrorValue preserves carrying-component presence independently of source type.
type ErrorValue[P any] struct{ Parameter *P }
type errorBinding[P, I, C any] struct {
	code      C
	info      func() I
	parameter ValueCodec[P]
}

// Code returns the bound local error code, or zero for a zero binding.
func (d errorBinding[P, I, C]) Code() C { return d.code }

// Info returns a detached metadata snapshot, or zero metadata for a zero binding.
func (d errorBinding[P, I, C]) Info() I {
	if d.info == nil {
		var zero I
		return zero
	}
	return d.info()
}

// Parameter returns the parameter codec and whether it is valid; an absent parameter has no valid codec.
func (d errorBinding[P, I, C]) Parameter() (ValueCodec[P], bool) {
	return d.parameter, d.parameter.valid()
}
func decodeErrorParameter[P any](data []byte, present bool, codec ValueCodec[P], opts ...ber.DecodeOption) (*ErrorValue[P], error) {
	if !present {
		if len(data) != 0 {
			return nil, fmt.Errorf("%w: absent parameter has bytes", ber.ErrInvalidBinding)
		}
		return &ErrorValue[P]{}, nil
	}
	if !codec.valid() {
		return nil, fmt.Errorf("%w: source error has no PARAMETER", ber.ErrInvalidBinding)
	}
	v, err := codec.DecodeBER(data, opts...)
	if err != nil {
		return nil, err
	}
	return &ErrorValue[P]{Parameter: &v}, nil
}
func encodeErrorParameter[P any](value *ErrorValue[P], codec ValueCodec[P], opts ...ber.EncodeOption) ([]byte, bool, error) {
	if value.Parameter == nil {
		return nil, false, nil
	}
	if !codec.valid() {
		return nil, false, fmt.Errorf("%w: source error has no PARAMETER", ber.ErrInvalidBinding)
	}
	data, err := codec.EncodeBER(*value.Parameter, opts...)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
func adaptValueCodec[T any](codec interface {
	DecodeBER([]byte, ...ber.DecodeOption) (T, error)
	EncodeBER(T, ...ber.EncodeOption) ([]byte, error)
	EncodeDER(T) ([]byte, error)
}) ValueCodec[T] {
	return ValueCodec[T]{decode: codec.DecodeBER, encode: codec.EncodeBER, der: codec.EncodeDER}
}

func apiBool(v bool) *bool { return &v }
