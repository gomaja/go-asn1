// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/triage_padding_test.go; SHA-256 6e7e562378969baeff66c66c57ec3df6f707d1afa1dc12b7ea679dd09a37cd90.
package ber

import (
	"bytes"
	"sync"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// X.690 (02/2021) §§8.6.2.1–8.6.2.3; only DER (§11.2.1) requires zero padding.
func TestBERPaddingAbstractValue(t *testing.T) {
	for unused := 1; unused <= 7; unused++ {
		contents := []byte{byte(unused), 0xff}
		original := bytes.Clone(contents)
		want := byte(0xff << unused)
		got, u, err := DecodeBitStringValue(contents)
		if err != nil || u != unused || len(got) != 1 || got[0] != want {
			t.Fatalf("value %d: %x/%d %v", unused, got, u, err)
		}
		if !bytes.Equal(contents, original) {
			t.Fatal("value decoder changed input")
		}
		for _, s := range []string{"0302", "23040302", "23800302"} {
			wire := append(structureWire(t, s), contents...)
			if s == "23800302" {
				wire = append(wire, 0, 0)
			}
			original := bytes.Clone(wire)
			opts := TrackBERForm(nil)
			got, u, n, err := DecodeBitString(wire, opts...)
			if err != nil || n != len(wire) || u != unused || len(got) != 1 || got[0] != want {
				t.Fatalf("TLV: %x/%d %v", got, u, err)
			}
			if !BERNeedsPreservation(opts) {
				t.Fatal("dirty/segmented form lost")
			}
			if !bytes.Equal(wire, original) {
				t.Fatal("TLV decoder changed input")
			}
		}
		opts := TrackBERForm(nil)
		got, u, err = DecodeImplicitBitStringValue(false, contents, opts...)
		if err != nil || u != unused || got[0] != want || !BERNeedsPreservation(opts) {
			t.Fatalf("implicit: %x/%d %v", got, u, err)
		}
	}
	opts := TrackBERForm(nil)
	if _, _, _, err := DecodeBitString([]byte{3, 2, 4, 0x30}, opts...); err != nil || BERNeedsPreservation(opts) {
		t.Fatalf("clean padding: %v", err)
	}
	opts = TrackBERForm(nil)
	if err := ValidateBERElement([]byte{3, 2, 4, 0x31}, opts...); err != nil || !BERNeedsPreservation(opts) {
		t.Fatalf("validator form: %v", err)
	}
}

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

func TestBERCleanPaddingSharedInput(t *testing.T) {
	wire := []byte{3, 2, 4, 0x30}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if _, _, _, err := DecodeBitString(wire); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}
