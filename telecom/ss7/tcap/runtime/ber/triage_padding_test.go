// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/triage_padding_test.go; SHA-256 b2e71e624febcecd45f5caa7a1af6a4e1316611f29299a25e88ed594a109fe89.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"testing"
)

func TestBERExternalPaddingReplay(t *testing.T) {
	for _, s := range []string{"2809060330303082020431", "28800603303030a2800302043100000000"} {
		wire := structureWire(t, s)
		original := bytes.Clone(wire)
		v, n, err := DecodeExternal(wire)
		if err != nil || n != len(wire) || v.Arbitrary.BitLength != 4 || !bytes.Equal(v.Arbitrary.Bytes, []byte{0x30}) {
			t.Fatalf("external: %+v %d %v", v, n, err)
		}
		out, err := EncodeExternal(v)
		if err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("replay %x: %v", out, err)
		}
		if !bytes.Equal(wire, original) {
			t.Fatal("external changed input")
		}
		fresh := runtime.External{DirectReference: v.DirectReference, Encoding: v.Encoding, Arbitrary: v.Arbitrary}
		for _, encode := range []func(runtime.External) ([]byte, error){func(value runtime.External) ([]byte, error) { return EncodeExternal(value) }, EncodeExternalDER} {
			out, err := encode(fresh)
			if err != nil || !bytes.Equal(out, structureWire(t, "2809060330303082020430")) {
				t.Fatalf("fresh: %x %v", out, err)
			}
		}
		if err := ValidateDERElement(wire); err == nil {
			t.Fatal("DER accepted dirty implicit bits")
		}
		v.Arbitrary.Bytes[0] = 0x40
		out, err = EncodeExternal(v)
		if err != nil || !bytes.Equal(out, structureWire(t, "2809060330303082020440")) {
			t.Fatalf("edit: %x %v", out, err)
		}
	}
}
