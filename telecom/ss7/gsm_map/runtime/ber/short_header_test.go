// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/short_header_test.go; SHA-256 e8fe444087e28aff07e59e3c9f66cf1a98a0fc061d3bb76f41b3312b319cda64.
package ber

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestShortTLVUsesOneOwnedAllocation(t *testing.T) {
	for _, length := range []int{0, 1, 127} {
		value := bytes.Repeat([]byte{0xa5}, length)
		var retained []byte
		allocations := testing.AllocsPerRun(1000, func() {
			var err error
			retained, err = EncodeOctetString(value)
			if err != nil {
				t.Fatal(err)
			}
		})
		t.Logf("contents=%d allocations=%.0f", length, allocations)
		if allocations > 1 {
			t.Errorf("short TLV allocated %.0f objects, want at most one", allocations)
		}
		if len(retained) != length+2 || retained[0] != 4 || retained[1] != byte(length) {
			t.Fatalf("unexpected short TLV header: %x", retained)
		}
	}
}

func TestShortTLVIdentifierAndLengthOctets(t *testing.T) {
	// ITU-T X.690 (02/2021) §§8.1.2.2, 8.1.2.5, 8.1.3.4:
	// enumerate each literal low-tag identifier octet and short length.
	for identifier := range 256 {
		if identifier&31 == 31 {
			continue
		}
		wireTag := tag.Tag{Class: tag.Class(identifier >> 6), Number: identifier & 31, Constructed: identifier&32 != 0}
		for length := range 128 {
			value := bytes.Repeat([]byte{0xa5}, length)
			got, err := EncodeTLV(wireTag, value)
			if err != nil || len(got) != length+2 || got[0] != byte(identifier) || got[1] != byte(length) || !bytes.Equal(got[2:], value) {
				t.Fatalf("identifier=%02x length=%d: %x, %v", identifier, length, got, err)
			}
			if length != 0 {
				value[0] = 0x5a
				if got[2] != 0xa5 {
					t.Fatal("output retains caller contents")
				}
				got[2] = 0x11
				if value[0] != 0x5a {
					t.Fatal("output modification changes caller contents")
				}
			}
		}
	}
}

func TestShortTLVCapacityErrorsAndFallbacks(t *testing.T) {
	wireTag := tag.Tag{Number: tag.TagOctetString}
	for _, test := range []struct {
		limit int
		want  string
	}{
		{-1, "ber: invalid value encoding: invalid BER output limit"},
		{0, "ber: invalid value encoding: BER output exceeds host int or configured limit"},
		{2, "ber: invalid value encoding: BER output exceeds host int or configured limit"},
	} {
		got, err := encodeTLVWithLimit(wireTag, []byte{0xa5}, test.limit)
		if got != nil || !errors.Is(err, ErrInvalidValue) || err.Error() != test.want {
			t.Fatalf("limit %d: %x, %v", test.limit, got, err)
		}
	}
	if got, err := encodeTLVWithLimit(wireTag, []byte{0xa5}, 3); err != nil || !bytes.Equal(got, []byte{4, 1, 0xa5}) {
		t.Fatalf("exact capacity: %x, %v", got, err)
	}
	if got, err := EncodeImplicitTagWithClass(tag.ClassContextSpecific, 31, []byte{4, 1, 0xa5}); err != nil || !bytes.Equal(got, []byte{0x9f, 0x1f, 1, 0xa5}) {
		t.Fatalf("high implicit identifier: %x, %v", got, err)
	}
	for _, test := range []struct {
		name  string
		tag   tag.Tag
		value []byte
		want  []byte
	}{
		{"high tag", tag.Tag{Class: tag.ClassContextSpecific, Number: 31}, []byte{0xa5}, []byte{0x9f, 0x1f, 1, 0xa5}},
		{"negative tag", tag.Tag{Number: -1}, []byte{0xa5}, []byte{0xff, 1, 0xa5}},
		{"nonstandard class", tag.Tag{Class: 4, Number: 4}, []byte{0xa5}, []byte{4, 1, 0xa5}},
		{"long length", wireTag, bytes.Repeat([]byte{0xa5}, 128), append([]byte{4, 0x81, 0x80}, bytes.Repeat([]byte{0xa5}, 128)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeTLV(test.tag, test.value)
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("fallback: %x, %v; want %x", got, err, test.want)
			}
		})
	}
}

func TestShortImplicitTagUsesOneOwnedAllocation(t *testing.T) {
	// X.690 (02/2021) §8.14.4 replaces only the identifier octets.
	for _, test := range []struct {
		wire  []byte
		class tag.Class
		num   int
		want  []byte
	}{
		{[]byte{4, 1, 0xa5}, tag.ClassContextSpecific, 30, []byte{0x9e, 1, 0xa5}},
		{[]byte{0x1f, 0x81, 0, 1, 0xa5}, tag.ClassApplication, 2, []byte{0x42, 1, 0xa5}},
		{[]byte{0xbf, 0x1f, 3, 4, 1, 0xa5}, tag.ClassPrivate, 30, []byte{0xfe, 3, 4, 1, 0xa5}},
		{[]byte{0xa0, 0x81, 3, 4, 1, 0xa5}, tag.ClassUniversal, 16, []byte{0x30, 0x81, 3, 4, 1, 0xa5}},
		{[]byte{0xa0, 0x80, 4, 1, 0xa5, 0, 0}, tag.ClassUniversal, 16, []byte{0x30, 0x80, 4, 1, 0xa5, 0, 0}},
	} {
		var retained []byte
		allocations := testing.AllocsPerRun(1000, func() {
			var err error
			retained, err = EncodeImplicitTagWithClass(test.class, test.num, test.wire)
			if err != nil {
				t.Fatal(err)
			}
		})
		if allocations > 1 || !bytes.Equal(retained, test.want) {
			t.Fatalf("retagging %x allocated %.0f times, result %x; want at most one and %x", test.wire, allocations, retained, test.want)
		}
		test.wire[0] ^= 1
		if !bytes.Equal(retained, test.want) {
			t.Fatal("retagged output retains caller storage")
		}
	}
}
