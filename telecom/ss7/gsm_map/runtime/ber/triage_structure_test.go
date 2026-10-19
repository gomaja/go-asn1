// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/triage_structure_test.go; SHA-256 7acf6515a1f8483d0fdca9a1bed00d716754957284376e0caf90ae926253e53f.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func structureWire(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// X.690 (02/2021) §§8.1.5, 8.2, 8.3, 8.6, 8.8, 8.19, 8.20.
func TestBERUniversalContentsMatrix(t *testing.T) {
	for _, s := range []string{
		"0100", "0102ffff", "050101", "0600", "060180", "06028000", "06022a81", "0d00", "0d0181", "0d028000",
		"0300", "030108", "030208ff", "030101", "0200", "02020001", "0a00", "0a02ffff", "2101ff", "2500", "26012a", "1000", "1100",
		"230404020000", "2308030204f0030200ff", "230a2304030204f003020000", "23062304030204f0030100",
		"24020300", "2480040000000000", "300401020000", "30800501010000", "3003060180",
	} {
		t.Run(s, func(t *testing.T) {
			wire := structureWire(t, s)
			original := bytes.Clone(wire)
			if err := ValidateBERElement(wire); err == nil {
				t.Fatal("accepted malformed BER")
			}
			if !bytes.Equal(wire, original) {
				t.Fatal("validator changed input")
			}
		})
	}
	for _, s := range []string{
		"010100", "010101", "010180", "0500", "06012a", "0603698837", "060b8180808080808080808000", "0d0100",
		"030100", "03020431", "020100", "0a01ff", "2300", "23800000", "2308030200aa030204bf",
		"23802380030200aa0000030204bf0000", "2480040200000000", "2c0404026869", "30050101010500", "308005000000",
	} {
		t.Run(s, func(t *testing.T) {
			if err := ValidateBERElement(structureWire(t, s)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, s := range []string{"010101", "03020431", "01810101", "23800000"} {
		wire := structureWire(t, s)
		if err := ValidateBERElement(wire); err != nil {
			t.Fatal(err)
		}
		if err := ValidateDERElement(wire); err == nil {
			t.Fatalf("DER accepted %s", s)
		}
	}
	for _, s := range []string{"", "05", "0501", "060281", "30800500"} {
		if err := ValidateBERElement(structureWire(t, s)); !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"05000500", "308000000000"} {
		if err := ValidateBERElement(structureWire(t, s)); !errors.Is(err, ErrExtraData) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestBEREOCValueContexts(t *testing.T) {
	for _, s := range []string{"0000", "000101", "00800000", "2000", "1f0000"} {
		wire := structureWire(t, s)
		if _, _, _, err := DecodeTLV(wire); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("DecodeTLV %s: %v", s, err)
		}
		if _, err := DecodeSequenceChildren(wire); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("children %s: %v", s, err)
		}
	}
	for _, s := range []string{"3080008000000000", "308020000000", "3080058000000000"} {
		if _, _, _, err := DecodeTLV(structureWire(t, s)); err == nil {
			t.Errorf("accepted invalid indefinite contents %s", s)
		}
	}
	for _, s := range []string{"308000000000", "308030800500000000000000"} {
		wire := structureWire(t, s)
		_, n, _, err := DecodeTLV(wire)
		if err != nil || n != len(wire)-2 {
			t.Fatalf("prefix %s: %d, %v", s, n, err)
		}
		if _, err := DecodeSequenceChildren(wire); !errors.Is(err, ErrInvalidTag) {
			t.Fatalf("children %s: %v", s, err)
		}
	}
	wire := structureWire(t, "308030800402000000000000")
	if _, n, _, err := DecodeTLV(wire); err != nil || n != len(wire) {
		t.Fatalf("nested valid EOC: %d, %v", n, err)
	}
}

func FuzzBERStructureAndStrings(f *testing.F) {
	for _, s := range []string{"", "0000", "30800000", "03020431", "2380030200aa030204bf0000", "2480040200000000", "060b8180808080808080808000"} {
		f.Add(structureWire(f, s))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		original := bytes.Clone(wire)
		opts := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 8, MaxElements: 32, MaxWork: 4096})}
		err := ValidateBERElement(wire, opts...)
		_, n, _, tlvErr := DecodeTLV(wire, opts...)
		if err == nil && (tlvErr != nil || n != len(wire)) {
			t.Fatalf("valid value disagrees with prefix: %v %d", tlvErr, n)
		}
		_, _ = DecodeSequenceChildren(wire, opts...)
		bits, unused, _, bitErr := DecodeBitString(wire, opts...)
		if bitErr == nil && unused > 0 && (len(bits) == 0 || bits[len(bits)-1]&byte((1<<unused)-1) != 0) {
			t.Fatal("dirty abstract padding")
		}
		_, _, _ = DecodeOctetString(wire, opts...)
		_, _, _ = DecodeString(wire, 12, opts...)

		external, consumed, externalErr := DecodeExternal(wire, opts...)
		if externalErr == nil {
			reencoded, err := EncodeExternal(external)
			if err != nil || consumed <= 0 || consumed > len(wire) || !bytes.Equal(reencoded, wire[:consumed]) {
				t.Fatalf("EXTERNAL replay: %v", err)
			}
		}
		if !bytes.Equal(wire, original) {
			t.Fatal("decoder changed input")
		}
	})
}
