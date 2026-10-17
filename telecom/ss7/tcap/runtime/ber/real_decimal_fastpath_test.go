// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/real_decimal_fastpath_test.go; SHA-256 c62f87f5524881d52e544a899eb4f2868240c03bde51c9bfb081cd27c66706d8.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func FuzzDecimalRealCanonicalForm(f *testing.F) {
	for _, value := range []string{"\x031.E+0", "\x03-17.E-2", "\x0310.E+0", "\x01+00125", "\x02.1250", "\x031.E12345678901234567890"} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) == 0 || len(contents) > 8192 || contents[0]&0xc0 != 0 {
			return
		}
		decoded, err := decodeRealContents(contents)
		if err != nil {
			return
		}
		canonical, err := EncodeRealValue(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := canonicalDecimalRealContents(contents), bytes.Equal(contents, canonical); got != want {
			t.Fatalf("canonical(%x) = %v, encoder = %x", contents, got, canonical)
		}
		wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDERElement(wire); (err == nil) != bytes.Equal(contents, canonical) {
			t.Fatalf("DER validation = %v; received %x, canonical %x", err, contents, canonical)
		}
	})
}
