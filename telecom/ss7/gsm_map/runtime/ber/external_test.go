// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external_test.go; SHA-256 1e03bc668230073dcf923af90081c9f87499598ed5987d5182ac78246d257ca7.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestExternalBitLengthRejectsHostIntOverflow(t *testing.T) {
	if _, err := externalBitLength(math.MaxInt/8+1, 0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("overflow error = %v, want ErrInvalidValue", err)
	}
	if got, err := externalBitLength(math.MaxInt/8, 7); err != nil || got != math.MaxInt/8*8-7 {
		t.Fatalf("boundary bit length = %d, error %v", got, err)
	}
	if got, err := externalBitLength(math.MaxInt/8+1, 1); err != nil || got != math.MaxInt {
		t.Fatalf("maximum representable bit length = %d, error %v", got, err)
	}
}

// X.690 (02/2021) §8.18.1.
func TestExternalAlternatives(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		encoding   runtime.ExternalEncoding
	}{
		{"single ASN1", "281306042b0601040201050703414243a00302012a", runtime.ExternalSingleASN1Type},
		{"octet aligned", "281206042b060104020105070341424381024142", runtime.ExternalOctetAligned},
		{"arbitrary", "281206042b0601040201050703414243820200aa", runtime.ExternalArbitrary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, n, err := DecodeExternal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(wire) || got.Encoding != tc.encoding || !got.DirectReference.Equal(runtime.MustObjectIdentifierFromArcs(1, 3, 6, 1, 4)) || got.IndirectReference.Cmp(big.NewInt(5)) != 0 || got.DataValueDescriptor == nil || *got.DataValueDescriptor != "ABC" {
				t.Fatalf("decoded=%+v consumed=%d", got, n)
			}
			encoded, err := EncodeExternal(got)
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("round trip %x -> %x: %v", wire, encoded, err)
			}
			got.IndirectReference.SetInt64(6)
			changed, err := EncodeExternal(got)
			if err != nil || bytes.Equal(changed, wire) {
				t.Fatalf("field edit did not reencode: %x: %v", changed, err)
			}
		})
	}
}

// X.690 (02/2021) §§8.18.1, 8.23.10: single-ASN1-type is open
// content, but its universal UTF8String encoding still needs validation.
func TestExternalOpaqueUTF8Encoding(t *testing.T) {
	value := runtime.External{IndirectReference: big.NewInt(1), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: runtime.RawValue{Class: 0, Tag: 12, Bytes: []byte{0x0c, 1, 0xff}}}
	if _, err := EncodeExternal(value); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("strict encoding: %v", err)
	}
	var reports ViolationLog
	if _, err := EncodeExternal(value, WithTolerance(&reports)); err != nil || len(reports.Snapshot()) != 1 {
		t.Fatalf("tolerant encoding: %v reports=%+v", err, reports.Snapshot())
	}
	wire := []byte{0x28, 8, 2, 1, 1, 0xa0, 3, 0x0c, 1, 0xff}
	decoded, n, err := DecodeExternal(wire)
	if err != nil || n != len(wire) {
		t.Fatalf("decode: %v size=%d", err, n)
	}
	if _, err := EncodeExternal(decoded); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("strict retained encoding: %v", err)
	}
	reports.Reset()
	got, err := EncodeExternal(decoded, WithTolerance(&reports))
	if err != nil || !bytes.Equal(got, wire) || len(reports.Snapshot()) != 1 {
		t.Fatalf("tolerant retained encoding: %x %v reports=%+v", got, err, reports.Snapshot())
	}
}

func TestExternalRejectsMalformedChoice(t *testing.T) {
	for _, wire := range [][]byte{
		{0x28, 0x00},
		{0x28, 0x05, 0x80, 0x03, 0x02, 0x01, 0x2a},
		{0x28, 0x05, 0xa0, 0x03, 0x02, 0x02, 0x00},
		{0x28, 0x03, 0x83, 0x01, 0x00},
		{0x28, 0x03, 0x81, 0x01, 0xff}, // X.690 §8.18.4: identification is required.
		{0x28, 0x08, 0x07, 0x03, 'A', 'B', 'C', 0x81, 0x01, 0xff},
	} {
		if _, _, err := DecodeExternal(wire); err == nil {
			t.Fatalf("accepted malformed EXTERNAL %x", wire)
		}
	}
}

func TestExternalIdentificationForms(t *testing.T) {
	for _, wire := range []string{
		"280606012a810141",       // direct reference only
		"2806020101810141",       // indirect reference only
		"280906012a020101810141", // both references
	} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		v, n, err := DecodeExternal(data)
		if err != nil || n != len(data) {
			t.Fatalf("decode %s: n=%d err=%v", wire, n, err)
		}
		encoded, err := EncodeExternal(v)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("BER round trip %s: %x %v", wire, encoded, err)
		}
		encoded, err = EncodeExternalDER(v)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("DER round trip %s: %x %v", wire, encoded, err)
		}
	}
	invalid := runtime.External{Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{0xff}}
	if wire, err := EncodeExternal(invalid); err == nil {
		t.Fatalf("BER encoded reference-free EXTERNAL: %x", wire)
	}
	if wire, err := EncodeExternalDER(invalid); err == nil {
		t.Fatalf("DER encoded reference-free EXTERNAL: %x", wire)
	}
	if err := ValidateDERElement([]byte{0x28, 0x03, 0x81, 0x01, 0xff}); err == nil {
		t.Fatal("DER accepted reference-free EXTERNAL")
	}
}

func FuzzDecodeExternalSemanticRoundTrip(f *testing.F) {
	for _, wire := range [][]byte{
		{0x28, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x2a},
		{0x28, 0x06, 0x06, 0x01, 0x2a, 0x81, 0x01, 0xff},
		{0x28, 0x04, 0x82, 0x02, 0x05, 0xa0},
		{0x28, 0x00},
	} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, n, err := DecodeExternal(wire)
		if err != nil {
			return
		}
		if n <= 0 || n > len(wire) || decoded.Encoding < runtime.ExternalSingleASN1Type || decoded.Encoding > runtime.ExternalArbitrary {
			t.Fatalf("invalid decoded EXTERNAL: n=%d encoding=%d", n, decoded.Encoding)
		}
		encoded, err := EncodeExternal(decoded)
		if err != nil || !bytes.Equal(encoded, wire[:n]) {
			t.Fatalf("EXTERNAL changed bytes %x -> %x: %v", wire[:n], encoded, err)
		}
	})
}
