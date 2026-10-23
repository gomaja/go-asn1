// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/minimal_integer_octets_test.go; SHA-256 978e2c56af10484c533b015c4009c361fede67e404ff3c8a523ce9d8adbb04dc.
package uper

import (
	"errors"
	"testing"
)

// ITU-T X.691 (02/2021) §§11.3.6, 11.5.7.4, 11.6.2, 11.7.4.
func TestMinimumUnsignedIntegerOctets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    []byte
		decode  func(*BitBuffer) (int64, error)
		wantErr bool
	}{
		{"uper-semi-leading-zero", []byte{0x02, 0x00, 0x40}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumber(bb, 0) }, true},

		{"uper-semi-zero-length", []byte{0x00}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumber(bb, 0) }, true},

		{"uper-semi-zero", []byte{0x01, 0x00}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumber(bb, 0) }, false},

		{"uper-small-index-leading-zero", []byte{0x81, 0x00, 0x20, 0x00}, DecodeNormallySmallNonNegative, true},

		{"uper-small-index-canonical", []byte{0x80, 0xa0, 0x00}, DecodeNormallySmallNonNegative, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.decode(NewBitBufferFromBytes(tc.wire))
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("decode %x: got %d, error %v; want ErrInvalidValue", tc.wire, got, err)
				}
			} else if err != nil {
				t.Fatalf("decode %x: unexpected error %v", tc.wire, err)
			}
		})
	}
}

// The extension-index decoders use the same semi-constrained integer path.
// ITU-T X.691 (02/2021) §§11.6.2, 14.2, 23.4.
func TestExtensionIndexesRejectRedundantOctets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		wire   []byte
		decode func(*BitBuffer) (int64, error)
	}{
		{"uper-enumerated", []byte{0xc0, 0x80, 0x10, 0x00}, func(bb *BitBuffer) (int64, error) { return DecodeEnumerated(bb, 1, true) }},

		{"uper-choice", []byte{0xc0, 0x80, 0x10, 0x00}, func(bb *BitBuffer) (int64, error) { value, _, err := DecodeChoiceIndex(bb, 1, true); return value, err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.decode(NewBitBufferFromBytes(tc.wire))
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("decode %x: error %v, want ErrInvalidValue", tc.wire, err)
			}
		})
	}
}

// ITU-T X.691 (02/2021) §§11.3.6, 11.4.6: any redundant sign or
// leading-zero octet is invalid for the minimum-octet integer procedures.
func FuzzMinimumIntegerOctets(f *testing.F) {
	for _, data := range [][]byte{{0}, {0x40}, {0x80}, {0xff}, {0, 0x40}, {0xff, 0x80}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 6 {
			return
		}
		unsigned := append([]byte{byte(len(data) + 1), 0}, data...)
		for _, decode := range []func(*BitBuffer) (int64, error){
			func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumber(bb, 0) },
		} {
			if _, err := decode(NewBitBufferFromBytes(unsigned)); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("redundant unsigned octet %x: error %v", unsigned, err)
			}
		}
		for _, signed := range [][]byte{append([]byte{0}, data...), append([]byte{0xff}, data...)} {
			if len(signed) < 2 || (signed[0] == 0 && signed[1]&0x80 != 0) || (signed[0] == 0xff && signed[1]&0x80 == 0) {
				continue // leading octet is needed for the sign
			}
			wire := append([]byte{byte(len(signed))}, signed...)
			for _, aligned := range []bool{false} {
				_ = aligned
				var err error

				{
					_, err = DecodeIntegerBig(NewBitBufferFromBytes(wire), nil, nil, false)
				}
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("redundant signed octet %x: error %v", wire, err)
				}
			}
		}
	})
}
