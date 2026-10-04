package ber

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// X.690 (02/2021) §§8.3.1–8.3.2, 8.4: redundant sign octets are
// invalid BER for INTEGER and ENUMERATED, regardless of the outer tag.
func TestRejectNonminimalIntegerContents(t *testing.T) {
	for _, contents := range [][]byte{{0, 1}, {0xff, 0xff}, {0, 0, 0x7f}, {0xff, 0xff, 0x80}} {
		for _, test := range []struct {
			name string
			fn   func([]byte) error
		}{
			{"INTEGER", func(v []byte) error { _, _, err := DecodeInteger(append([]byte{2, byte(len(v))}, v...)); return err }},
			{"ENUMERATED", func(v []byte) error {
				_, _, err := DecodeEnumerated(append([]byte{10, byte(len(v))}, v...))
				return err
			}},
			{"big INTEGER", func(v []byte) error { _, _, err := DecodeBigInt(append([]byte{2, byte(len(v))}, v...)); return err }},
			{"uint64 INTEGER", func(v []byte) error { _, _, err := DecodeUint64(append([]byte{2, byte(len(v))}, v...)); return err }},
			{"implicit INTEGER", func(v []byte) error { _, err := DecodeIntegerValue(v); return err }},
			{"implicit ENUMERATED", func(v []byte) error { _, err := DecodeEnumeratedValue(v); return err }},
			{"implicit big INTEGER", func(v []byte) error { _, err := DecodeBigIntValue(v); return err }},
			{"implicit uint64 INTEGER", func(v []byte) error { _, err := DecodeUint64Value(v); return err }},
		} {
			t.Run(fmt.Sprintf("%s/%x", test.name, contents), func(t *testing.T) {
				err := test.fn(contents)
				if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "8.3.2") {
					t.Fatalf("contents %x: error = %v", contents, err)
				}
			})
		}
	}
	for _, wire := range [][]byte{
		{2, 2, 0, 1},
		{10, 2, 0, 1},
		{0xa0, 4, 2, 2, 0, 1},
	} {
		if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("nested/universal %x: error = %v", wire, err)
		}
	}
	for _, contents := range [][]byte{{0}, {0x80}, {0, 0x80}, {0xff, 0x7f}} {
		if _, err := DecodeBigIntValue(contents); err != nil {
			t.Fatalf("valid contents %x: %v", contents, err)
		}
	}
	if _, err := DecodeBigIntValue(append([]byte{0}, bytesOf(0x80, 8)...)); err != nil {
		t.Fatalf("valid wide positive integer: %v", err)
	}
}

func TestRejectConstructedNull(t *testing.T) {
	if _, err := DecodeNull([]byte{0x25, 0x00}); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("constructed NULL: %v", err)
	}
}

func bytesOf(value byte, n int) []byte {
	out := make([]byte, n)
	out[0] = value
	return out
}
