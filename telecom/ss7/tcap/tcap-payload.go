// Code generated from ASN.1. DO NOT EDIT.

package tcap

import (
	"bytes"
	"fmt"
	rt "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	ber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"reflect"
)

// PayloadLimits bounds the separate, explicit foreign-value decoding operation.
// Zero fields select the BER runtime defaults; negative fields are invalid.
type PayloadLimits struct {
	MaxDepth    int
	MaxElements int
	MaxWork     int
}

// PayloadEncoding selects the encoding supplied by a foreign schema's codec.
type PayloadEncoding uint8

const (
	PayloadBER PayloadEncoding = iota
	PayloadDER
)

// PayloadCodec binds one foreign schema without exchanging runtime objects.
// DecodeBER must consume all bytes and apply the supplied ceilings and source
// constraints. EncodeDER must enforce DER under that schema, including IMPLICIT
// types, SET ordering, and DEFAULT omission that a generic scan cannot infer.
type PayloadCodec[T any] interface {
	DecodeBER(data []byte, limits PayloadLimits) (T, error)
	EncodeBER(value T) ([]byte, error)
	EncodeDER(value T) ([]byte, error)
}

func nilPayloadCodec[T any](codec PayloadCodec[T]) bool {
	if codec == nil {
		return true
	}
	value := reflect.ValueOf(codec)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// DecodePayload validates one complete BER element before invoking the binding.
// Generic BER accepts the noncanonical forms that an explicit repair may need:
// ITU-T X.690 (02/2021) sections 8.1.3 and 8.7. The enclosing TCAP entry point
// currently accepts these forms too; enforcement of the Q.773 (06/1997)
// section 4.1.1 encoding profile is separate conformance work.
// The binding receives an owned copy, leaving the raw payload unchanged.
func DecodePayload[T any](value rt.RawValue, codec PayloadCodec[T], limits PayloadLimits) (T, error) {
	var zero T
	if nilPayloadCodec(codec) {
		return zero, fmt.Errorf("nil payload codec")
	}
	if limits.MaxDepth < 0 || limits.MaxElements < 0 || limits.MaxWork < 0 {
		return zero, fmt.Errorf("negative payload decode limit")
	}
	defaults := ber.DefaultDecodeLimits()
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxElements == 0 {
		limits.MaxElements = defaults.MaxElements
	}
	if limits.MaxWork == 0 {
		limits.MaxWork = defaults.MaxWork
	}
	if err := ber.ValidateBERElement(value.Bytes, ber.WithDecodeLimits(ber.DecodeLimits{
		MaxDepth: limits.MaxDepth, MaxElements: limits.MaxElements, MaxWork: limits.MaxWork,
	})); err != nil {
		return zero, fmt.Errorf("validating payload: %w", err)
	}
	return codec.DecodeBER(bytes.Clone(value.Bytes), limits)
}

// EncodePayload checks one complete codec output and owns the returned bytes.
// DER checking covers generic X.690 (02/2021) sections 10 and 11 restrictions;
// the foreign codec remains responsible for schema-dependent DER semantics.
func EncodePayload[T any](value T, codec PayloadCodec[T], rule PayloadEncoding) (rt.RawValue, error) {
	if nilPayloadCodec(codec) {
		return rt.RawValue{}, fmt.Errorf("nil payload codec")
	}
	var encoded []byte
	var err error
	switch rule {
	case PayloadBER:
		encoded, err = codec.EncodeBER(value)
	case PayloadDER:
		encoded, err = codec.EncodeDER(value)
	default:
		return rt.RawValue{}, fmt.Errorf("invalid payload encoding %d", rule)
	}
	if err != nil {
		return rt.RawValue{}, err
	}
	if rule == PayloadDER {
		err = ber.ValidateDEREncodedElement(encoded)
	} else {
		err = ber.ValidateBEREncodedElement(encoded)
	}
	if err != nil {
		return rt.RawValue{}, fmt.Errorf("validating encoded payload: %w", err)
	}
	identifier, _, err := ber.DecodeTag(encoded)
	if err != nil {
		return rt.RawValue{}, err
	}
	return rt.RawValue{Class: int(identifier.Class), Tag: identifier.Number, Constructed: identifier.Constructed, Bytes: bytes.Clone(encoded)}, nil
}

// validateCanonicalPayload refuses opaque bytes needing canonical repair.
// Generic DER checks cannot establish foreign-schema DER conformance; a typed
// PayloadCodec.EncodeDER supplies that additional contract. X.690 (02/2021)
// sections 10 and 11; Q.773 (06/1997) section 4.1.1.
func validateCanonicalPayload(data []byte) error {
	if err := ber.ValidateDERElement(data); err != nil {
		return fmt.Errorf("canonical payload requires a typed DER binding: %w", err)
	}
	return nil
}
