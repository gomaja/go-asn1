package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
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

// X.690 (02/2021) §8.18.1 and Q.773 (06/1997) Annex A.
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
			if n != len(wire) || got.Encoding != tc.encoding || !got.DirectReference.Equal(runtime.ObjectIdentifier{1, 3, 6, 1, 4}) || got.IndirectReference.Cmp(big.NewInt(5)) != 0 || got.DataValueDescriptor == nil || *got.DataValueDescriptor != "ABC" {
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
