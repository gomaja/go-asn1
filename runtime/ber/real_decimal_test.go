package ber

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestDecodeRealDecimalForms(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		base     int
		mantissa string
		exponent string
	}{
		{name: "NR1", contents: "\x01+00125", base: 10, mantissa: "125", exponent: "0"},
		{name: "NR2 no integral digits", contents: "\x02.1250", base: 10, mantissa: "125", exponent: "-3"},
		{name: "NR2 comma", contents: "\x02-12,50", base: 10, mantissa: "-125", exponent: "-1"},
		{name: "NR3", contents: "\x03-12.50E+3", base: 10, mantissa: "-125", exponent: "2"},
		{name: "NR3 lowercase", contents: "\x03+001.250e-2", base: 10, mantissa: "125", exponent: "-4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, []byte(test.contents))
			got, consumed, err := DecodeReal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(wire) {
				t.Fatalf("consumed %d, want %d", consumed, len(wire))
			}
			assertReal(t, got, runtime.RealFinite, test.base, test.mantissa, test.exponent)
			implicit, err := DecodeRealValue([]byte(test.contents))
			if err != nil {
				t.Fatal(err)
			}
			assertReal(t, implicit, runtime.RealFinite, test.base, test.mantissa, test.exponent)
		})
	}
}

func TestDecodeRealBinaryArbitraryWidth(t *testing.T) {
	exponent := new(big.Int).Lsh(big.NewInt(1), 520)
	exponentBytes := EncodeBigIntValue(exponent)
	contents := append([]byte{0x83, byte(len(exponentBytes))}, exponentBytes...)
	contents = append(contents, 0x01, 0x00, 0x00, 0x00, 0x00)
	got, err := DecodeRealValue(contents)
	if err != nil {
		t.Fatal(err)
	}
	wantExponent := new(big.Int).Add(exponent, big.NewInt(32))
	assertReal(t, got, runtime.RealFinite, 2, "1", wantExponent.String())

	encoded, err := EncodeReal(got)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, _, err := DecodeReal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	assertReal(t, roundTrip, runtime.RealFinite, 2, "1", wantExponent.String())
}

func TestDecodeRealAcceptsBERValueWithoutDERRepresentation(t *testing.T) {
	exponentBytes := append([]byte{0x30}, make([]byte, 254)...)
	contents := append([]byte{0xeb, byte(len(exponentBytes))}, exponentBytes...)
	contents = append(contents, 0x30)

	decoded, err := DecodeRealValue(contents)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Base != 2 || decoded.Exponent == nil || len(EncodeBigIntValue(decoded.Exponent)) != 256 {
		t.Fatalf("decoded REAL = %#v, want a base-2 exponent requiring 256 octets", decoded)
	}

	// X.690 (02/2021) 8.5.4 permits base-16 BER, while 11.3.1 requires
	// base-2 DER. This valid BER value has no representable DER exponent.
	if _, err := EncodeReal(decoded); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("EncodeReal error = %v, want ErrInvalidValue", err)
	}
}

func TestDecodeRealBinaryBasesAndScaleFactor(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
		mantissa string
		exponent string
	}{
		{name: "base 8", contents: []byte{0x90, 0x02, 0x03}, mantissa: "3", exponent: "6"},
		{name: "base 16", contents: []byte{0xa0, 0xff, 0x05}, mantissa: "5", exponent: "-4"},
		{name: "scale factor", contents: []byte{0x8c, 0x00, 0x03}, mantissa: "3", exponent: "3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeRealValue(test.contents)
			if err != nil {
				t.Fatal(err)
			}
			assertReal(t, got, runtime.RealFinite, 2, test.mantissa, test.exponent)
		})
	}
}

func TestEncodeRealRejectsExponentLongerThanWireLimit(t *testing.T) {
	exponent := new(big.Int).Lsh(big.NewInt(1), 2040)
	value, err := runtime.NewReal(2, big.NewInt(1), exponent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeReal(value); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("oversized exponent error = %v, want ErrInvalidValue", err)
	}
}

func TestDecodeRealRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
	}{
		{name: "reserved decimal form", contents: []byte{0x04, '1'}},
		{name: "empty NR1", contents: []byte{0x01}},
		{name: "NR1 fraction", contents: []byte{0x01, '1', '.', '0'}},
		{name: "NR2 exponent", contents: []byte{0x02, '1', '.', '0', 'E', '1'}},
		{name: "NR2 no digits", contents: []byte{0x02, '.'}},
		{name: "NR3 no exponent digits", contents: []byte{0x03, '1', '.', 'E', '+'}},
		{name: "decimal zero", contents: []byte{0x01, '0'}},
		{name: "special trailing data", contents: []byte{0x40, 0x00}},
		{name: "reserved special", contents: []byte{0x44}},
		{name: "reserved binary base", contents: []byte{0xb0, 0x00, 0x01}},
		{name: "long exponent missing length", contents: []byte{0x83}},
		{name: "zero exponent length", contents: []byte{0x83, 0x00, 0x01}},
		{name: "nonminimal long exponent", contents: []byte{0x83, 0x02, 0x00, 0x7f, 0x01}},
		{name: "missing mantissa", contents: []byte{0x80, 0x00}},
		{name: "zero mantissa", contents: []byte{0x80, 0x00, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRealValue(test.contents); !errors.Is(err, ErrInvalidValue) && !errors.Is(err, ErrTruncated) {
				t.Fatalf("DecodeRealValue(%x) error = %v", test.contents, err)
			}
		})
	}

	constructed := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal, Constructed: true}, nil)
	if _, _, err := DecodeReal(constructed); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("constructed REAL error = %v, want ErrInvalidTag", err)
	}
}

func TestEncodeRealCanonicalDER(t *testing.T) {
	decimal, err := runtime.NewReal(10, big.NewInt(-12500), big.NewInt(-3))
	if err != nil {
		t.Fatal(err)
	}
	decimalWire, err := EncodeReal(decimal)
	if err != nil {
		t.Fatal(err)
	}
	wantDecimal := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, []byte("\x03-125.E-1"))
	if !bytes.Equal(decimalWire, wantDecimal) {
		t.Fatalf("decimal DER = %x, want %x", decimalWire, wantDecimal)
	}
	if err := ValidateDERElement(decimalWire); err != nil {
		t.Fatalf("canonical decimal DER rejected: %v", err)
	}

	binary, err := runtime.NewReal(2, big.NewInt(-40), big.NewInt(-5))
	if err != nil {
		t.Fatal(err)
	}
	binaryWire, err := EncodeReal(binary)
	if err != nil {
		t.Fatal(err)
	}
	wantBinary := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, []byte{0xc0, 0xfe, 0x05})
	if !bytes.Equal(binaryWire, wantBinary) {
		t.Fatalf("binary DER = %x, want %x", binaryWire, wantBinary)
	}
	if err := ValidateDERElement(binaryWire); err != nil {
		t.Fatalf("canonical binary DER rejected: %v", err)
	}
}

func TestValidateDERRejectsNonCanonicalReal(t *testing.T) {
	tests := [][]byte{
		{0x01, '1'},
		{0x02, '1', '.', '0'},
		{0x03, '+', '1', '.', 'E', '+', '0'},
		{0x03, '0', '1', '.', 'E', '+', '0'},
		{0x03, '1', '0', '.', 'E', '+', '0'},
		{0x03, '1', '.', '0', 'E', '+', '0'},
		{0x03, '1', '.', 'E', '0'},
		{0x03, '1', '.', 'E', '+', '1'},
		{0x90, 0x00, 0x01},
		{0x84, 0x00, 0x01},
		{0x81, 0x00, 0x00, 0x01},
		{0x80, 0x00, 0x02},
		{0x80, 0x00, 0x00, 0x01},
	}
	for _, contents := range tests {
		wire := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
		if err := ValidateDERElement(wire); err == nil {
			t.Errorf("ValidateDERElement(%x) accepted non-canonical REAL", wire)
		}
	}
}

func FuzzDecodeRealValueNoPanic(f *testing.F) {
	for _, seed := range [][]byte{{}, {0x01, '1'}, {0x03, '1', '.', 'E', '+', '0'}, {0x80, 0x00, 0x01}, {0x83, 0x01, 0x00, 0x01}, {0x40}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		decoded, err := DecodeRealValue(value)
		if err != nil {
			return
		}
		wire, err := EncodeReal(decoded)
		if err != nil {
			// X.690 (02/2021) 8.5.4 permits base-8/base-16 BER values whose
			// canonical base-2 exponent cannot fit the 255-octet DER limit.
			if !errors.Is(err, ErrInvalidValue) || decoded.Kind != runtime.RealFinite || decoded.Base != 2 ||
				decoded.Exponent == nil || len(EncodeBigIntValue(decoded.Exponent)) <= 255 {
				t.Fatalf("decoded REAL cannot be re-encoded: %v", err)
			}
			return
		}
		if _, consumed, err := DecodeReal(wire); err != nil || consumed != len(wire) {
			t.Fatalf("canonical re-decode = consumed %d error %v", consumed, err)
		}
	})
}

func assertReal(t *testing.T, got runtime.Real, kind runtime.RealKind, base int, mantissa, exponent string) {
	t.Helper()
	if got.Kind != kind || got.Base != base || got.Mantissa == nil || got.Exponent == nil || got.Mantissa.String() != mantissa || got.Exponent.String() != exponent {
		t.Fatalf("REAL = %#v, want kind=%v base=%d mantissa=%s exponent=%s", got, kind, base, mantissa, exponent)
	}
}
