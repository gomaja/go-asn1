// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/oid.go; SHA-256 5875b30026a712a734e4449305957df2d601065425583dd471f0d18577d600dd.
package aper

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
)

// EncodeObjectIdentifierAligned writes an OBJECT IDENTIFIER in aligned PER.
func EncodeObjectIdentifierAligned(bb *BitBuffer, oid runtime.ObjectIdentifier) error {
	contents, err := oidContents(oid)
	if err != nil {
		return err
	}
	return EncodeOctetStringAligned(bb, contents, 0, 0, false)
}

// DecodeObjectIdentifierAligned reads an OBJECT IDENTIFIER in aligned PER.
func DecodeObjectIdentifierAligned(bb *BitBuffer) (runtime.ObjectIdentifier, error) {
	contents, err := DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.ObjectIdentifier{}, fmt.Errorf("object identifier: %w", err)
	}
	return decodeOIDContents(contents)
}

// oidContents produces the X.690 §8.19 contents octets for oid.
//
// encodeOIDValueChecked returns those contents directly (no tag, no length),
// which is exactly what PER wraps. An OID needs at least two arcs, since the
// first two are combined into a single subidentifier; rejecting a shorter one
// here keeps a malformed value from being encoded as something a decoder
// would silently read back as a different OID.
func oidContents(oid runtime.ObjectIdentifier) ([]byte, error) {
	contents, err := encodeOIDValueChecked(oid)
	if err != nil {
		return nil, fmt.Errorf("object identifier: %w", err)
	}
	return contents, nil
}

func decodeOIDContents(contents []byte) (runtime.ObjectIdentifier, error) {
	oid, err := decodeOIDValue(contents)
	if err != nil {
		return runtime.ObjectIdentifier{}, fmt.Errorf("object identifier: %w", err)
	}
	return oid, nil
}

// These contents helpers preserve the published OID diagnostics when moving
// X.690 (02/2021) §8.19 contents into the owned APER runtime.
var errOIDTruncated = errors.New("ber: data truncated")
var errOIDInvalidValue = errors.New("ber: value out of range")

func encodeOIDValueChecked(oid runtime.ObjectIdentifier) ([]byte, error) {
	if oid.IsZero() {
		return nil, runtime.ErrInvalidOID
	}
	return oid.Bytes(), nil
}
func decodeOIDValue(value []byte) (runtime.ObjectIdentifier, error) {
	oid, err := runtime.ObjectIdentifierFromEncoded(string(value))
	if err == nil {
		return oid, nil
	}
	if errors.Is(err, runtime.ErrTruncatedOID) {
		return oid, fmt.Errorf("%w: %v", errOIDTruncated, err)
	}
	return oid, fmt.Errorf("%w: %v", errOIDInvalidValue, err)
}
