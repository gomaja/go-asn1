package ber

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
)

func TestDecodeLengthAcceptsLongFormWithLeadingZeroOctets(t *testing.T) {
	// X.690 (02/2021) §8.1.3.5 permits 1–126 subsequent octets.
	for _, count := range []int{5, 126} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			wire := append([]byte{byte(0x80 | count)}, make([]byte, count)...)
			wire[len(wire)-1] = 1
			length, indefinite, consumed, err := DecodeLength(wire)
			if err != nil || indefinite || length != 1 || consumed != len(wire) {
				t.Fatalf("DecodeLength(%x) = (%d, %t, %d, %v); want (1, false, %d, nil)", wire, length, indefinite, consumed, err, len(wire))
			}
			// The complete BER TLV is valid with one contents octet.
			tlv := append(append([]byte{0x04}, wire...), 0x61)
			_, total, value, err := DecodeTLV(tlv)
			if err != nil || total != len(tlv) || !bytes.Equal(value, []byte{0x61}) {
				t.Fatalf("DecodeTLV(%x) = (%d, %x, %v); want (%d, 61, nil)", tlv, total, value, err, len(tlv))
			}
		})
	}
}

func TestDecodeLengthRejectsReservedAndHostOverflow(t *testing.T) {
	if _, _, _, err := DecodeLength([]byte{0xff}); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("reserved long-form initial octet error = %v; want ErrInvalidLength", err)
	}
	wire := append([]byte{0x88, 0x80}, make([]byte, 7)...)
	if _, _, _, err := DecodeLength(wire); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("host-int overflow error = %v; want ErrInvalidLength", err)
	}
}

func FuzzDecodeLengthNoPanic(f *testing.F) {
	for _, seed := range [][]byte{
		{0x00}, {0x7f}, {0x80}, {0x81, 0x01},
		{0x85, 0, 0, 0, 0, 1}, {0xff},
		append([]byte{0xfe}, append(make([]byte, 125), 1)...),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		length, indefinite, consumed, err := DecodeLength(data)
		if err != nil {
			return
		}
		if consumed < 1 || consumed > len(data) || length < 0 || indefinite && (length != 0 || consumed != 1) {
			t.Fatalf("invalid successful length decode: length=%d indefinite=%t consumed=%d input=%x", length, indefinite, consumed, data)
		}
	})
}
