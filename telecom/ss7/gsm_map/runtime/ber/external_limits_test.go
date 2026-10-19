// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external_limits_test.go; SHA-256 e5214e9057358096407e0e9825fe0b5860fd534332e442cb61e239b8fee6824a.
package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestExternalRaisedLimitReachesIndirectBigInteger(t *testing.T) {
	integer := append([]byte{1}, bytes.Repeat([]byte{0}, 16<<20)...)
	children := append(mustEncode(t)(EncodeObjectIdentifier(runtime.MustObjectIdentifierFromArcs(1, 2))), mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagInteger}, integer))...)
	children = append(children, mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, []byte{'A'}))...)
	wire := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagExternal, Constructed: true}, children))
	if _, _, err := DecodeExternal(wire); err == nil {
		t.Fatal("default work limit accepted oversized EXTERNAL")
	}
	value, n, err := DecodeExternal(wire, WithDecodeLimits(DecodeLimits{MaxWork: 20 << 20}))
	if err != nil || n != len(wire) || value.IndirectReference == nil || value.IndirectReference.BitLen() != len(integer)*8-7 {
		t.Fatalf("raised limit: n=%d indirect=%v error=%v", n, value.IndirectReference != nil, err)
	}
}

func TestExternalEditedRawChildDoesNotUseDecodeLimit(t *testing.T) {
	inner := mustEncode(t)(EncodeOctetString(bytes.Repeat([]byte{'A'}, (16<<20)+1)))
	value := runtime.External{DirectReference: runtime.MustObjectIdentifierFromArcs(1, 2), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: rawExternalLimitValue(inner)}
	wire, err := EncodeExternal(value)
	if err != nil {
		t.Fatalf("encode caller value: %v", err)
	}
	decoded, n, err := DecodeExternal(wire, WithDecodeLimits(DecodeLimits{MaxWork: 20 << 20}))
	if err != nil || n != len(wire) {
		t.Fatalf("decode raised limit: n=%d error=%v", n, err)
	}
	decoded.SingleASN1Type.Bytes[len(decoded.SingleASN1Type.Bytes)-1] = 'B'
	edited, err := EncodeExternal(decoded)
	if err != nil {
		t.Fatalf("encode edited value: %v", err)
	}
	if bytes.Equal(edited, wire) {
		t.Fatal("edited encoding reused original wire")
	}
	check, _, err := DecodeExternal(edited, WithDecodeLimits(DecodeLimits{MaxWork: 20 << 20}))
	if err != nil || check.SingleASN1Type.Bytes[len(check.SingleASN1Type.Bytes)-1] != 'B' {
		t.Fatalf("edited wire: error=%v", err)
	}
}

func TestExternalDEREncodeValidatesBeyondDecodeDepth(t *testing.T) {
	inner := EncodeNull()
	for range 129 {
		inner = mustEncode(t)(EncodeSequence(inner))
	}
	value := runtime.External{DirectReference: runtime.MustObjectIdentifierFromArcs(1, 2), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: rawExternalLimitValue(inner)}
	if _, err := EncodeExternalDER(value); err != nil {
		t.Fatalf("encode canonical deep child: %v", err)
	}
}

func TestExternalDEREncodeValidatesBeyondDecodeWorkLimit(t *testing.T) {
	// X.690 (02/2021) §8.18 has no size ceiling for EXTERNAL.
	inner := mustEncode(t)(EncodeOctetString(bytes.Repeat([]byte{'A'}, (16<<20)+1)))
	value := runtime.External{DirectReference: runtime.MustObjectIdentifierFromArcs(1, 2), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: rawExternalLimitValue(inner)}
	wire, err := EncodeExternalDER(value)
	if err != nil {
		t.Fatalf("encode canonical large child: %v", err)
	}
	if err := ValidateDEREncodedElement(wire); err != nil {
		t.Fatalf("validate encoded EXTERNAL: %v", err)
	}
}

func TestDEREncodedEmbeddedPDVBeyondDecodeWorkLimit(t *testing.T) {
	// X.690 (02/2021) §8.17 and X.680 (02/2021) §36.5:
	// fixed identification [5] and a primitive [2] data-value.
	data := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, bytes.Repeat([]byte{'A'}, (16<<20)+1)))
	value := append([]byte{0xa0, 0x02, 0x85, 0x00}, data...)
	wire := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagEmbeddedPDV, Constructed: true}, value))
	if err := ValidateDEREncodedElement(wire); err != nil {
		t.Fatalf("validate canonical large EMBEDDED PDV: %v", err)
	}
}

// Synthetic inputs may intentionally have malformed framing; retain their identifier metadata.
func rawExternalLimitValue(data []byte) runtime.RawValue {
	identifier, _, _ := DecodeTag(data)
	return runtime.RawValue{Class: int(identifier.Class), Tag: identifier.Number, Constructed: identifier.Constructed, Bytes: data}
}
