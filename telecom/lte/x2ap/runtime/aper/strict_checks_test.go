// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/strict_checks_test.go; SHA-256 f1aa2adb770ce9692e38def03208c0a75ab09820fd28e444ddb1cd31ae4e4a46.
package aper

import (
	"errors"
	"testing"
)

// These negative fields are constructed directly from X.691 (02/2021),
// independently of the encoder. Each check must retain its original span.
func TestStrictMalformedFieldsHaveRulesAndLocations(t *testing.T) {
	cases := []struct {
		name, clause string
		wire         []byte
		decode       func(*BitBuffer) error
	}{
		{"internal alignment", "§11.1.4", []byte{0x7f}, func(bb *BitBuffer) error {
			if _, err := bb.ReadBit(); err != nil {
				return err
			}
			return bb.AlignToOctetRead()
		}},
		{"terminal bits", "§11.1.4", []byte{0x01}, func(bb *BitBuffer) error {
			if _, err := bb.ReadBit(); err != nil {
				return err
			}
			return ValidateFinalPadding(bb)
		}},
		{"empty open value", "§11.2.1", []byte{0}, func(bb *BitBuffer) error { _, err := DecodeOpenTypeAligned(bb); return err }},
		{"long short length", "§11.9.3.6", []byte{0x80, 0x7f}, func(bb *BitBuffer) error { _, err := DecodeUnconstrainedLengthAligned(bb); return err }},
		{"fragment multiplier", "§11.9.3.8", []byte{0xc5}, func(bb *BitBuffer) error { _, err := DecodeOpenTypeAligned(bb); return err }},
		{"integer unused code", "§11.5.7.1", []byte{0xc0}, func(bb *BitBuffer) error { _, err := DecodeConstrainedWholeNumberAligned(bb, 0, 2); return err }},
		{"enum unused code", "§11.5.7.1", []byte{0xc0}, func(bb *BitBuffer) error { _, err := DecodeEnumeratedAligned(bb, 3, false); return err }},
		{"sequence empty extension bitmap", "§19.1", []byte{0}, func(bb *BitBuffer) error {
			var additions ExtensionAdditions
			_, _, err := additions.DecodeBitmapAligned(bb)
			return err
		}},
		{"sequence truncated bitmap", "§19.7", []byte{0x7e}, func(bb *BitBuffer) error {
			var additions ExtensionAdditions
			_, _, err := additions.DecodeBitmapAligned(bb)
			return err
		}},
		{"choice missing open alternative", "§11.2.1", []byte{0}, func(bb *BitBuffer) error { _, err := DecodeChoiceExtensionAligned(bb, 0); return err }},
		{"bit string missing bits", "§16.9", nil, func(bb *BitBuffer) error { _, _, err := DecodeBitStringAligned(bb, 8, 8, true); return err }},
		{"object identifier contents", "§24", []byte{1, 0x80}, func(bb *BitBuffer) error { _, err := DecodeObjectIdentifierAligned(bb); return err }},
		{"octet string missing octets", "§17.6", nil, func(bb *BitBuffer) error { _, err := DecodeOctetStringAligned(bb, 1, 1, true); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			{
				bb := NewBitBufferFromBytes(tc.wire)
				err := tc.decode(bb)
				var located *DecodeError
				if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != tc.clause || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 {
					t.Fatalf("err=%v location=%+v", err, located)
				}
				for _, span := range located.Location.Spans {
					if span.End < span.Start || span.End > uint64(len(tc.wire))*8 {
						t.Fatalf("span outside input: %+v", span)
					}
				}
			}
		})
	}
}

func TestStrictAdditionalGuardsHaveRulesAndLocations(t *testing.T) {
	cases := []struct {
		name, clause string
		wire         []byte
		decode       func(*BitBuffer) error
	}{
		{"empty complete value", "§11.1.4", nil, func(bb *BitBuffer) error { return ValidateFinalPadding(bb) }},
		{"nonzero zero-bit complete value", "§11.1.4", []byte{0xff}, func(bb *BitBuffer) error { return ValidateFinalPadding(bb) }},
		{"empty object identifier", "§24", []byte{0}, func(bb *BitBuffer) error { _, e := DecodeObjectIdentifierAligned(bb); return e }},
		{"nonminimal object identifier", "§24", []byte{2, 0x80, 0}, func(bb *BitBuffer) error { _, e := DecodeObjectIdentifierAligned(bb); return e }},
		{"unterminated object identifier", "§24", []byte{1, 0x81}, func(bb *BitBuffer) error { _, e := DecodeObjectIdentifierAligned(bb); return e }},
		{"two-octet integer unused code", "§11.5.7.3", []byte{1, 1}, func(bb *BitBuffer) error { _, e := DecodeConstrainedWholeNumberAligned(bb, 0, 256); return e }},
		{"indefinite integer unused code", "§11.5.7.4", []byte{0x80, 1, 0x86, 0xa1}, func(bb *BitBuffer) error { _, e := DecodeConstrainedWholeNumberAligned(bb, 0, 100000); return e }},
		{"semi integer empty", "§11.7.4", []byte{0}, func(bb *BitBuffer) error { _, e := DecodeSemiConstrainedWholeNumberAligned(bb, 0); return e }},
		{"semi integer nonminimal", "§11.7.4", []byte{2, 0, 1}, func(bb *BitBuffer) error { _, e := DecodeSemiConstrainedWholeNumberAligned(bb, 0); return e }},
		{"signed integer empty", "§11.4.6", []byte{0}, func(bb *BitBuffer) error { _, e := DecodeUnconstrainedWholeNumberAligned(bb); return e }},
		{"signed positive nonminimal", "§11.4.6", []byte{2, 0, 1}, func(bb *BitBuffer) error { _, e := DecodeUnconstrainedWholeNumberAligned(bb); return e }},
		{"signed negative nonminimal", "§11.4.6", []byte{2, 0xff, 0xff}, func(bb *BitBuffer) error { _, e := DecodeUnconstrainedWholeNumberAligned(bb); return e }},
		{"long normally-small below64", "§11.6.2", []byte{0x80, 1, 1}, func(bb *BitBuffer) error { _, e := DecodeNormallySmallNonNegativeAligned(bb); return e }},
		{"long normally-small length below65", "§11.9.3.4", []byte{0x80, 1}, func(bb *BitBuffer) error { _, e := DecodeNormallySmallLengthAligned(bb); return e }},
		{"integer extension inside root", "§13.1", []byte{0x80, 1, 1}, func(bb *BitBuffer) error {
			lo, hi := int64(0), int64(2)
			_, e := DecodeIntegerAligned(bb, &lo, &hi, true)
			return e
		}},
		{"bit extension inside root", "§16.6", []byte{0x80, 1, 0}, func(bb *BitBuffer) error { _, _, e := DecodeBitStringAlignedExt(bb, 1, 2, true, true); return e }},
		{"octet extension inside root", "§17.3", []byte{0x80, 1, 0}, func(bb *BitBuffer) error { _, e := DecodeOctetStringAlignedExt(bb, 1, 2, true, true); return e }},
		{"fixed bit string beyond16 missing bits", "§16.10", []byte{0}, func(bb *BitBuffer) error { _, _, e := DecodeBitStringAligned(bb, 17, 17, true); return e }},
		{"variable bit string missing bits", "§16.11", []byte{3}, func(bb *BitBuffer) error { _, _, e := DecodeBitStringAligned(bb, 0, 0, false); return e }},
		{"fixed octets beyond2 missing data", "§17.7", []byte{0}, func(bb *BitBuffer) error { _, e := DecodeOctetStringAligned(bb, 3, 3, true); return e }},
		{"variable octets missing data", "§17.8", []byte{1}, func(bb *BitBuffer) error { _, e := DecodeOctetStringAligned(bb, 0, 0, false); return e }},
		{"fragment multiplier zero", "§11.9.3.8", []byte{0xc0}, func(bb *BitBuffer) error { _, e := DecodeOpenTypeAligned(bb); return e }},
		{"appended complete octet", "§11.1.4", []byte{0, 0}, func(bb *BitBuffer) error {
			_, e := bb.ReadBit()
			if e != nil {
				return e
			}
			return ValidateFinalPadding(bb)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			err := tc.decode(bb)
			var located *DecodeError
			if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != tc.clause || !located.Location.HasWireLocation {
				t.Fatalf("err=%v location=%+v", err, located)
			}
		})
	}
}
