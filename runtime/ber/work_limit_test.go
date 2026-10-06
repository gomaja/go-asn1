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

func TestConstructedBERWorkLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  []byte
		limit DecodeLimits
	}{
		{"depth", nestedOctets(t, 65, []byte{1}), DecodeLimits{MaxDepth: 64}},
		{"elements", append(append([]byte{0x24, 0x80}, bytes.Repeat([]byte{0x04, 0x00}, 100001)...), 0, 0), DecodeLimits{MaxElements: 100000}},
		{"total work", nestedOctets(t, 60, bytes.Repeat([]byte{0x5a}, 300000)), DecodeLimits{MaxWork: 16 << 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeOctetString(tc.wire, WithDecodeLimits(tc.limit)); !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("DecodeOctetString error = %v, want bounded failure", err)
			}
		})
	}
}

func TestBERDecodeLimitsCanBeRaised(t *testing.T) {
	wire := nestedOctets(t, 65, []byte{'A'}) // 263 bytes, X.690 §§8.1.3, 8.7.
	if len(wire) != 263 {
		t.Fatalf("wire size = %d", len(wire))
	}
	for _, limits := range []DecodeLimits{{}, {MaxDepth: 65}} {
		value, n, err := DecodeOctetString(wire, WithDecodeLimits(limits))
		if err != nil || n != len(wire) || !bytes.Equal(value, []byte{'A'}) {
			t.Fatalf("limits=%+v: value=%x n=%d error=%v", limits, value, n, err)
		}
	}
	if _, _, err := DecodeOctetString(wire, WithDecodeLimits(DecodeLimits{MaxDepth: 64})); !errors.Is(err, ErrResourceLimit) || !bytes.Contains([]byte(err.Error()), []byte("depth")) {
		t.Fatalf("explicit depth 64 error = %v", err)
	}
	if _, _, _, err := DecodeTLV(wire, WithDecodeLimits(DecodeLimits{MaxDepth: 65})); err != nil {
		t.Fatalf("DecodeTLV raised depth: %v", err)
	}
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

func BenchmarkConstructedBEROctetString(b *testing.B) {
	wire := nestedOctets(b, 32, bytes.Repeat([]byte{0x5a}, 4096))
	b.SetBytes(int64(len(wire)))
	for range b.N {
		if _, _, err := DecodeOctetString(wire); err != nil {
			b.Fatal(err)
		}
	}
}
