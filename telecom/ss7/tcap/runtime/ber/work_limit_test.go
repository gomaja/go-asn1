// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/work_limit_test.go; SHA-256 bfdff6d0074ac8e41e832cc2bb9734a15f59bc464935e8389ca95f459da64382.
package ber

import (
	"bytes"
	"errors"
	"testing"
)

func nestedOctets(tb interface {
	Helper()
	Fatalf(string, ...any)
}, depth int, leaf []byte) []byte {
	tb.Helper()
	wire, err := EncodeOctetString(leaf)
	if err != nil {
		tb.Fatalf("encode nested octets: %v", err)
	}
	for range depth {
		wire = append(append([]byte{0x24, 0x80}, wire...), 0, 0)
	}
	return wire
}

func TestDERDepthLimit(t *testing.T) {
	wire := EncodeNull()
	for range 129 {
		wire = mustEncode(t)(EncodeSequence(wire))
	}
	if err := ValidateDERElement(wire); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("ValidateDERElement depth error = %v", err)
	}
}

func TestValidateBERElementLimits(t *testing.T) {
	tooMany := mustEncode(t)(EncodeSequence(bytes.Repeat(EncodeNull(), 4)))
	if err := ValidateBERElement(tooMany, WithDecodeLimits(DecodeLimits{MaxElements: 4})); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("element limit error = %v", err)
	}
	if err := ValidateBERElement(tooMany, WithDecodeLimits(DecodeLimits{MaxElements: 5})); err != nil {
		t.Fatalf("raised element limit: %v", err)
	}
	if err := ValidateBERElement(tooMany, WithDecodeLimits(DecodeLimits{MaxWork: len(tooMany) - 1})); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("work limit error = %v", err)
	}
	for _, invalid := range [][]byte{{}, {0, 0}, {0x30, 0x80, 0x05, 0x00}, {0x30, 0x02, 0x05, 0x00, 0x05, 0x00}} {
		if err := ValidateBERElement(invalid); err == nil {
			t.Fatalf("accepted malformed BER %x", invalid)
		}
	}
}

func FuzzValidateBERElement(f *testing.F) {
	for _, wire := range [][]byte{
		EncodeNull(), nestedOctets(f, 65, []byte{'A'}), {0x30, 0x80, 0x05, 0x00, 0, 0},
		{}, {0, 0}, {0x30, 0x80, 0x05, 0x00},
		{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff},
		{0x30, 0x80, 0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0, 0},
	} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if err := ValidateBERElement(wire); err != nil {
			return
		}
		_, n, _, err := DecodeTLV(wire)
		if err != nil || n != len(wire) {
			t.Fatalf("validated BER rejected by DecodeTLV: %x n=%d err=%v", wire, n, err)
		}
	})
}
